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
    _log.debug("Protecting APDU");
    _log.verbose("  header=${cmd.rawHeader().hex()}");
    _log.sdVerbose("  data=${cmd.data?.hex()}");
    _log.verbose("  Le=${cmd.ne}");

    // 1) Increment SSC first (PACE/AES: SSC starts at 0…0 and increments per C-APDU)
    _ssc.increment();
    final sscBytes = _ssc.toBytes();
    _log.verbose("  SSC incremented to: ${sscBytes.hex()}");

    // 2) Mask the header (set SM bit in CLA), do not touch INS/P1/P2
    final pcmd = maskCmd(cmd);
    final headerForMac = pcmd.rawHeader(); // snapshot for MAC + sanity check
    _log.verbose("masked APDU header=${headerForMac.hex()}");

    // 3) Decide command flavor
    final bool isSelectByDfName = (pcmd.ins == ISO7816_INS.SELECT_FILE &&
        pcmd.p1 == ISO97816_SelectFileP1.byDFName); // A4/04

    // 4) Build DO for command data
    //    PACE + AES: for SELECT by DF name, many eID PICCs require ENCRYPTED data (DO87).
    //    Use AES-CBC with IV=0x00..00 and ISO/IEC 9797-1 M2 padding. Prefix 0x01 before ciphertext in DO87 value.
    Uint8List doData; // DO85 or DO87 (we'll build 87 here for SELECT)
    if (isSelectByDfName) {
      final Uint8List body = pcmd.data ?? Uint8List(0);
      // pad plaintext to block size (ISO9797-1 Method 2)
      final Uint8List padded = ISO9797.pad(body, blockLen());
      // encrypt with zero IV (CBC)
      final Uint8List zeroIV = Uint8List(blockLen());
      final Uint8List ct = cipher.encrypt(padded, iv: zeroIV);

      // DO87 = 87 | L | ( 0x01 || CIPHERTEXT )
      final Uint8List do87Val = Uint8List.fromList([0x01, ...ct]);
      doData = SecureMessaging.tlv(0x87, do87Val);
      _log.verbose("Generated DO87 (enc)=${doData.hex()}");
    } else {
      // For other commands:
      //  - if there is outgoing data, encrypt it as DO87 the same way
      //  - if there is no data, no DO85/DO87 is present
      if ((pcmd.data?.isNotEmpty ?? false)) {
        final Uint8List body = pcmd.data!;
        final Uint8List padded = ISO9797.pad(body, blockLen());
        final Uint8List zeroIV = Uint8List(blockLen());
        final Uint8List ct = cipher.encrypt(padded, iv: zeroIV);
        final Uint8List do87Val = Uint8List.fromList([0x01, ...ct]);
        doData = SecureMessaging.tlv(0x87, do87Val);
        _log.verbose("Generated DO87 (enc)=${doData.hex()}");
      } else {
        doData = Uint8List(0);
        _log.verbose("No data DO present");
      }
    }

    // 5) Build DO97 (expected response length)
    //    For SELECT by DF name we *do* expect FCI → include DO97(00) (variable length).
    //    For other commands: if Le==0 and you still expect data, you can also include 970100.
    Uint8List do97;
    if (isSelectByDfName) {
      do97 = SecureMessaging.do97(256); // 970100
    } else {
      // Use caller's Le if >0, else omit; many stacks are picky
      if (pcmd.ne > 0) {
        // NB: SecureMessaging.do97() should encode 1-byte Le correctly (0x00 for 256)
        do97 = SecureMessaging.do97(pcmd.ne);
      } else {
        do97 = Uint8List(0);
      }
    }
    _log.verbose("Generated DO97=${do97.hex()}, size=${do97.length}");

    // 6) CMAC input: SSC' || CLA' INS P1 P2 || [DO87/DO85] || [DO97]
    //    DO NOT pad here; CMAC implementation handles padding internally.
    final Uint8List macInput = Uint8List.fromList([
      ...sscBytes,
      ...headerForMac,
      ...doData,
      ...do97,
    ]);

    // One-shot sanity logs (keep them, they help a ton)
    _log.verbose("SSC'         = ${sscBytes.hex()}");
    _log.verbose("Hdr (masked) = ${headerForMac.hex()}");
    _log.verbose("DO85/DO87    = ${doData.hex()}");
    _log.verbose("DO97         = ${do97.hex()}");
    _log.verbose("CMAC input   = ${macInput.hex()} (len=${macInput.length})");

    // 7) Compute CC = AES-CMAC(macInput); use first 8 bytes in DO8E
    final Uint8List fullCC = cipher.mac(macInput); // 16 bytes
    final Uint8List cc8 = fullCC.sublist(0, 8); // truncate
    final Uint8List do8E = SecureMessaging.do8E(cc8);

    _log.verbose("Calculated CC (full)     =${fullCC.hex()}");
    _log.verbose("Calculated CC (8 bytes)  =${cc8.hex()}");
    _log.verbose("Generated DO8E=${do8E.hex()}");

    // 8) Serialize protected APDU:
    //    data' = [DO87 or DO85] || [DO97] || DO8E
    //    outer Le (Ne) MUST be zero/omitted under SM
    pcmd.data = Uint8List.fromList(doData + do97 + do8E);
    pcmd.ne = 0; // no outer Le — avoids case-4 ambiguity

    // 9) Paranoia: header must not change after MAC
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

  @visibleForTesting
  Uint8List generateDataDO(final CommandAPDU cmd) {
    var dataDO = Uint8List(0);
    if (cmd.data != null && cmd.data!.isNotEmpty) {
      final bool isSelectByDfName = (cmd.ins == ISO7816_INS.SELECT_FILE &&
          cmd.p1 == ISO97816_SelectFileP1.byDFName); // P1 == 0x04

      if (isSelectByDfName) {
        // Authenticated-but-not-encrypted SELECT AID
        dataDO = SecureMessaging.do85(cmd.data!);
      } else {
        // Current behavior
        final edata =
            cipher.encrypt(ISO9797.pad(cmd.data!, blockLen()), ssc: _ssc);
        if (cmd.ins == ISO7816_INS.READ_BINARY_EXT) {
          dataDO = SecureMessaging.do85(edata);
        } else {
          dataDO = SecureMessaging.do87(edata, dataIsPadded: true);
        }
      }
    }
    return dataDO;
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
