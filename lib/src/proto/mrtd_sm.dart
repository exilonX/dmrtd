// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';

import '../lds/asn1ObjectIdentifiers.dart';
import 'ssc.dart';
import 'iso7816/command_apdu.dart';
import 'iso7816/iso7816.dart';
import 'iso7816/response_apdu.dart';
import 'iso7816/sm.dart';
import 'iso7816/smcipher.dart';
import '../crypto/iso9797.dart';
import '../lds/tlv.dart';
import '../crypto/aes.dart';
import '../crypto/des.dart';

/// Class defines secure messaging protocol as specified in ICAO 9303 p11.
class MrtdSM extends SecureMessaging {
  final _log = Logger("mrtd.sm");
  static final bool Function(List<dynamic>, List<dynamic>) _eq =
      const ListEquality().equals;

  SSC _ssc;
  set ssc(final SSC ssc) => _ssc = ssc;
  SSC get ssc => _ssc;

  MrtdSM(SMCipher smCipher, this._ssc) : super(smCipher);

  @override
  CommandAPDU protect(final CommandAPDU cmd) {
    _log.debug("Protecting APDU: ${cmd.toString()}");

    _ssc.increment();
    _log.verbose("SSC incremented to: ${_ssc.toBytes().hex()}");

    final pcmd = maskCmd(cmd);
    final dataDO = generateDataDO(pcmd);
    final do97 = SecureMessaging.do97(pcmd.ne);

    // --- START OF THE FUNDAMENTAL BAC FIX ---
    if (cipher.type == CipherAlgorithm.DESede) {
      _log.warning("Applying alternate BAC MAC calculation (no header/SSC).");

      // For this card's BAC, the MAC is likely calculated ONLY on the data objects.
      final macInput = Uint8List.fromList([...dataDO, ...do97]);

      // The data MUST be padded before MAC calculation for 3DES.
      final paddedMacInput = ISO9797.pad(macInput, blockLen());

      final fullCC = cipher.mac(paddedMacInput);
      final cc8 = fullCC.sublist(0, 8);
      final do8E = SecureMessaging.do8E(cc8);

      pcmd.data = Uint8List.fromList([...dataDO, ...do97, ...do8E]);
      pcmd.ne = 0;
      return pcmd;
    }
    // --- END OF THE FUNDAMENTAL BAC FIX ---

    // --- Original PACE (AES) Logic - UNCHANGED ---
    final headerForMac = pcmd.rawHeader();
    final macInput = Uint8List.fromList([
      ..._ssc.toBytes(),
      ...headerForMac,
      ...dataDO,
      ...do97,
    ]);
    final fullCC = cipher.mac(macInput);
    final cc8 = fullCC.sublist(0, 8);
    final do8E = SecureMessaging.do8E(cc8);

    pcmd.data = Uint8List.fromList([...dataDO, ...do97, ...do8E]);
    pcmd.ne = 0;

    assert(const ListEquality().equals(headerForMac, pcmd.rawHeader()),
        "SM header changed after MAC");
    return pcmd;
  }

  @override
  ResponseAPDU unprotect(ResponseAPDU rapdu) {
    if (rapdu.status == StatusWord.smDataMissing ||
        rapdu.status == StatusWord.smDataInvalid ||
        (rapdu.data?.isEmpty ?? true)) {
      //RAPDU should have data
      return rapdu;
    }

    // Increment SSC should be made before decrypting data
    _ssc.increment();

    _log.debug("Unprotecting RAPDU: $rapdu");
    final tvDataDO = parseDataDOFromRAPDU(rapdu);
    final do99 = parseDO99FromRAPDU(rapdu, (tvDataDO?.encodedLen ?? 0));
    final do8EStart = (tvDataDO?.encodedLen ?? 0) + do99.encodedLen;
    final do8E = parseDO8EFromRAPDU(rapdu, do8EStart);
    final K = generateK(data: rapdu.data!.sublist(0, do8EStart));
    final CC = cipher.mac(K);
    final cc8 = CC.sublist(0, 8);

    _log.verbose("Generated K=${K.hex()}");
    _log.verbose("  used SSC=${_ssc.toBytes().hex()}");
    _log.verbose("APDU CC=${do8E.value.hex()}");
    _log.verbose("Calculated CC=${CC.hex()}");
    if (!_eq(cc8, do8E.value)) {
      throw SMError("Invalid MAC of response APDU");
    }

    final data = decryptDataDO(tvDataDO);
    return ResponseAPDU(StatusWord.fromBytes(do99.value), data);
  }

  @visibleForTesting
  Uint8List? decryptDataDO(final DecodedTV? dtv) {
    _log.verbose("Decrypting data=${dtv?.value.hex()}");
    if (dtv == null || dtv.value.isEmpty) {
      return null;
    }

    final tag = dtv.tag.value;
    if (tag != SecureMessaging.tagDO85 && tag != SecureMessaging.tagDO87) {
      throw SMError(
          "Can't decrypt invalid data DO with tag=$tag value=${dtv.value.hex()}");
    }

    final bool isDO87 = tag == SecureMessaging.tagDO87;
    final bool padded =
        !isDO87 || dtv.value[0] == 0x01; // Defined in ISO/IEC 7816-4 part 5
    var data = cipher.decrypt(dtv.value.sublist(isDO87 ? 1 : 0),
        ssc: _ssc); // SSC is used only in AES
    _log.sdVerbose("Decrypted data=${data.hex()}");
    _log.sdVerbose("Decrypted data is padded: $padded");
    if (padded) {
      data = ISO9797.unpad(data);
      _log.sdVerbose("Unpadded data=${data.hex()}");
    }
    return data;
  }

  Uint8List generateDataDO(final CommandAPDU cmd) {
    var dataDO = Uint8List(0);
    if (cmd.data != null && cmd.data!.isNotEmpty) {
      final edata =
          cipher.encrypt(ISO9797.pad(cmd.data!, blockLen()), ssc: _ssc);
      if (cmd.ins == ISO7816_INS.READ_BINARY_EXT) {
        dataDO = SecureMessaging.do85(edata);
      } else {
        dataDO = SecureMessaging.do87(edata, dataIsPadded: true);
      }
    }
    return dataDO;
  }

  // Add this helper function somewhere accessible
  Uint8List padWithZeros(Uint8List data, int blockSize) {
    final padLength = blockSize - (data.length % blockSize);
    if (padLength == blockSize) {
      return data; // Already a multiple of block size
    }
    final padded = Uint8List(data.length + padLength)..setAll(0, data);
    return padded;
  }

  int blockLen() {
    if (cipher.type == CipherAlgorithm.AES) {
      return AES_BLOCK_SIZE;
    } else if (cipher.type == CipherAlgorithm.DESede) {
      return DESCipher.blockSize;
    } else {
      _log.error("Unsupported cipher algorithm: ${cipher.type}");
      throw SMError("Unsupported cipher algorithm: ${cipher.type}");
    }
  }

  @visibleForTesting
  Uint8List generateK({required final Uint8List data}) {
    final upK = Uint8List.fromList(_ssc.toBytes() + data);
    return ISO9797.pad(upK, blockLen());
  }

  @visibleForTesting
  Uint8List generateM(
      {required final CommandAPDU cmd,
      required final Uint8List dataDO,
      required final Uint8List do97}) {
    final rawHeader = ISO9797.pad(cmd.rawHeader(), blockLen());
    return Uint8List.fromList(rawHeader + do97 + dataDO);
  }

  @visibleForTesting
  Uint8List generateN({required final Uint8List M}) {
    final upN = Uint8List.fromList(_ssc.toBytes() + M);
    return ISO9797.pad(upN, blockLen());
  }

  @visibleForTesting
  CommandAPDU maskCmd(final CommandAPDU cmd) {
    // Deep copy + set SM bit on CLA
    return CommandAPDU(
      cla: cmd.cla | ISO7816_CLA.SM_HEADER_AUTHN,
      ins: cmd.ins,
      p1: cmd.p1,
      p2: cmd.p2,
      data: (cmd.data == null) ? null : Uint8List.fromList(cmd.data!),
      ne: cmd.ne,
    );
  }

  /// Returns decoded data from DO85 or DO87 if they are present in [rapdu].
  @visibleForTesting
  DecodedTV? parseDataDOFromRAPDU(final ResponseAPDU rapdu) {
    if (rapdu.data == null ||
        rapdu.data!.isEmpty ||
        (rapdu.data![0] != SecureMessaging.tagDO85 &&
            rapdu.data![0] != SecureMessaging.tagDO87)) {
      return null;
    }

    final DO = TLV.decode(rapdu.data!);
    return DO;
  }

  @visibleForTesting
  DecodedTV parseDO8EFromRAPDU(final ResponseAPDU rapdu, int offset) {
    if (rapdu.data == null ||
        rapdu.data!.isEmpty ||
        rapdu.data![offset] != SecureMessaging.tagDO8E) {
      throw SMError("Missing DO'8E' in response APDU or invalid offset");
    }
    return TLV.decode(rapdu.data!.sublist(offset));
  }

  @visibleForTesting
  DecodedTV parseDO99FromRAPDU(final ResponseAPDU rapdu, int offset) {
    if (rapdu.data == null ||
        rapdu.data!.isEmpty ||
        rapdu.data![offset] != SecureMessaging.tagDO99) {
      throw SMError("Missing DO'99' in response APDU or invalid offset");
    }
    return TLV.decode(rapdu.data!.sublist(offset));
  }
}
