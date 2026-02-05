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
import 'aes_smcipher.dart';

/// Class defines secure messaging protocol as specified in ICAO 9303 p11.
class MrtdSM extends SecureMessaging {
  final _log = Logger("mrtd.sm");
  static final bool Function(List<dynamic>, List<dynamic>) _eq =
      const ListEquality().equals;

  SSC _ssc;
  set ssc(final SSC ssc) => _ssc = ssc;
  SSC get ssc => _ssc;

  MrtdSM(SMCipher smCipher, this._ssc) : super(smCipher) {
    // print("=== MrtdSM CONSTRUCTOR ===");
    // print("SMCipher type: ${smCipher.runtimeType}");
    // print("Cipher algorithm: ${smCipher.type}");
    // print("Initial SSC: ${_ssc.toBytes().hex()}");
    // print("SSC bit size: ${_ssc.bitSize}");
    // if (smCipher is AES_SMCipher) {
    //   print("AES_SMCipher K_enc: ${smCipher.KSenc.hex()}");
    //   print("AES_SMCipher K_mac: ${smCipher.KSmac.hex()}");
    // }
    // print("=== MrtdSM INITIALIZED ===");
  }

  @override
  CommandAPDU protect(final CommandAPDU cmd) {
    // _log.debug("Protecting APDU");
    _ssc.increment();

    final pcmd = maskCmd(cmd);
    final header = pcmd.rawHeader();

    // Skip DO87 if no data (required for PACE/AES)
    final dataDO = generateDataDO(pcmd);
    // DO97 is always included (per working version)
    final do97 = SecureMessaging.do97(pcmd.ne);

    Uint8List fullCC;

    if (cipher.type == CipherAlgorithm.DESede) {
      // === BAC branch ===
      final M = generateM(cmd: pcmd, dataDO: dataDO, do97: do97);
      final N = generateN(M: M); // ISO9797 padded
      fullCC = cipher.mac(N);
      final do8E = SecureMessaging.do8E(fullCC);
      pcmd.data = Uint8List.fromList([...dataDO, ...do97, ...do8E]);
      pcmd.ne = 256;
      return pcmd;
    }

    // === PACE/AES branch (JMRTD-compatible) ===
    // 1. Padded header (16 bytes)
    // 2. DO87 if data present
    // 3. DO97 ONLY if Le>0 (omit when Le=0)
    // 4. Pre-pad MAC input to block boundary

    final paddedHeader = ISO9797.pad(header, blockLen());

    // JMRTD behavior: omit DO97 when Le=0, include when Le>0
    final Uint8List do97ForAes;
    if (pcmd.ne == 0) {
      // Le=0: omit DO97 entirely (JMRTD behavior - verified working)
      do97ForAes = Uint8List(0);
    } else {
      do97ForAes = SecureMessaging.do97(pcmd.ne);
    }

    // JMRTD approach: pre-pad MAC input to block boundary
    final macInputUnpadded = Uint8List.fromList([
      ..._ssc.toBytes(),
      ...paddedHeader,
      ...dataDO,
      ...do97ForAes,
    ]);
    final macInput = ISO9797.pad(macInputUnpadded, blockLen());

    // print("=== SM PROTECT (AES) ===");
    // print("SSC: ${_ssc.toBytes().hex()}");
    // print("Header (raw 4 bytes): ${header.hex()}");
    // print("Header (padded to 16): ${paddedHeader.hex()}");
    // print("DO87 (${dataDO.length} bytes): ${dataDO.hex()}");
    // print("DO97 (${do97ForAes.length} bytes): ${do97ForAes.hex()}");
    // print(
    //     "MAC input (unpadded, ${macInputUnpadded.length} bytes): ${macInputUnpadded.hex()}");
    // print("MAC input (padded, ${macInput.length} bytes): ${macInput.hex()}");
    // _log.verbose("MAC input=${macInput.hex()}");

    fullCC = cipher.mac(macInput);

    final cc8 = fullCC.sublist(0, 8);

    // print("Full CMAC (16 bytes): ${fullCC.hex()}");
    // print("Truncated CC (8 bytes): ${cc8.hex()}");

    final do8E = SecureMessaging.do8E(cc8);
    pcmd.data = Uint8List.fromList([...dataDO, ...do97ForAes, ...do8E]);
    pcmd.ne = 256;

    // print("DO8E: ${do8E.hex()}");
    // print("Final protected APDU data: ${pcmd.data?.hex()}");
    // print(
    //     "Final protected APDU: CLA=${pcmd.cla.toRadixString(16)} INS=${pcmd.ins.toRadixString(16)} P1=${pcmd.p1.toRadixString(16)} P2=${pcmd.p2.toRadixString(16)}");
    // print("=== SM PROTECT END ===");

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

    // _log.debug("Unprotecting RAPDU: $rapdu");
    final tvDataDO = parseDataDOFromRAPDU(rapdu);
    final do99 = parseDO99FromRAPDU(rapdu, (tvDataDO?.encodedLen ?? 0));
    final do8EStart = (tvDataDO?.encodedLen ?? 0) + do99.encodedLen;
    final do8E = parseDO8EFromRAPDU(rapdu, do8EStart);

    // MAC verification: pad(SSC || responseBody) - same approach as protect()
    final K = generateK(data: rapdu.data!.sublist(0, do8EStart));
    final fullCC = cipher.mac(K);
    // Truncate CMAC to 8 bytes for comparison (same as protect())
    final CC = fullCC.sublist(0, 8);

    // _log.verbose("Generated K=${K.hex()}");
    // _log.verbose("  used SSC=${_ssc.toBytes().hex()}");
    // _log.verbose("APDU CC=${do8E.value.hex()}");
    // _log.verbose("Calculated full CC=${fullCC.hex()}");
    // _log.verbose("Calculated truncated CC=${CC.hex()}");
    if (!_eq(CC, do8E.value)) {
      throw SMError("Invalid MAC of response APDU");
    }
    final data = decryptDataDO(tvDataDO);
    return ResponseAPDU(StatusWord.fromBytes(do99.value), data);
  }

  @visibleForTesting
  Uint8List? decryptDataDO(final DecodedTV? dtv) {
    // _log.verbose("Decrypting data=${dtv?.value.hex()}");
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
    // _log.sdVerbose("Decrypted data=${data.hex()}");
    // _log.sdVerbose("Decrypted data is padded: $padded");
    if (padded) {
      data = ISO9797.unpad(data);
      // _log.sdVerbose("Unpadded data=${data.hex()}");
    }
    return data;
  }

  @visibleForTesting
  Uint8List generateDataDO(final CommandAPDU cmd) {
    var dataDO = Uint8List(0);
    if (cmd.data != null && cmd.data!.isNotEmpty) {
      final edata = cipher.encrypt(ISO9797.pad(cmd.data!, blockLen()),
          ssc: _ssc); // SSC is used only in AES
      dataDO = SecureMessaging.do87(edata, dataIsPadded: true);
    }
    return dataDO;
  }

  int blockLen() {
    if (cipher.type == CipherAlgorithm.AES) {
      return AES_BLOCK_SIZE;
    } else if (cipher.type == CipherAlgorithm.DESede) {
      return DESCipher.blockSize;
    } else {
      throw SMError("Unsupported cipher algorithm: ${cipher.type}");
    }
  }

  @visibleForTesting
  Uint8List generateK({required final Uint8List data}) {
    // Pre-pad to block boundary for consistency with protect() - JMRTD behavior
    final unpadded = Uint8List.fromList(_ssc.toBytes() + data);
    return ISO9797.pad(unpadded, blockLen());
  }

  @visibleForTesting
  Uint8List generateM(
      {required final CommandAPDU cmd,
      required final Uint8List dataDO,
      required final Uint8List do97}) {
    final rawHeader = ISO9797.pad(cmd.rawHeader(), blockLen());
    return Uint8List.fromList(rawHeader + dataDO + do97);
  }

  @visibleForTesting
  Uint8List generateN({required final Uint8List M}) {
    final upN = Uint8List.fromList(_ssc.toBytes() + M);
    return ISO9797.pad(upN, blockLen());
  }

  @visibleForTesting
  CommandAPDU maskCmd(final CommandAPDU cmd) {
    CommandAPDU mcmd = cmd;
    mcmd.cla |= ISO7816_CLA.SM_HEADER_AUTHN;
    return mcmd;
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
