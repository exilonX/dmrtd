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
    print("=== MrtdSM CONSTRUCTOR ===");
    print("SMCipher type: ${smCipher.runtimeType}");
    print("Cipher algorithm: ${smCipher.type}");
    print("Initial SSC: ${_ssc.toBytes().hex()}");
    print("SSC bit size: ${_ssc.bitSize}");
    if (smCipher is AES_SMCipher) {
      print("AES_SMCipher K_enc: ${smCipher.KSenc.hex()}");
      print("AES_SMCipher K_mac: ${smCipher.KSmac.hex()}");
    }
    print("=== MrtdSM INITIALIZED ===");
  }
  @override
  CommandAPDU protect(final CommandAPDU cmd) {
    _log.debug("Protecting APDU");
    _ssc.increment();

    final pcmd = maskCmd(cmd);
    final header = pcmd.rawHeader();
    final int originalNe = cmd.ne;

    // Skip DO87 if no data (required for PACE/AES)
    final dataDO = generateDataDO(pcmd);

    // Only include DO'97' in MAC if the original command expects a response (ne != 0)
    final bool includeDo97 = (originalNe != 0);

    // For PACE/AES: DO'97' encoding (when included)
    // - ne=256 or ne=65536 → 97 01 00 or 97 02 00 00
    // - other values → 97 <len> <value>
    final do97 = includeDo97
        ? (originalNe == 256
            ? Uint8List.fromList([0x97, 0x01, 0x00])
            : SecureMessaging.do97(originalNe, cipherType: cipher.type))
        : Uint8List(0);

    if (cipher.type == CipherAlgorithm.DESede) {
      // === BAC branch ===
      final M = generateM(cmd: pcmd, dataDO: dataDO, do97: do97);
      final N = generateN(M: M); // ISO9797 padded
      final fullCC = cipher.mac(N);
      final do8E = SecureMessaging.do8E(fullCC);
      pcmd.data = Uint8List.fromList([...dataDO, ...do97, ...do8E]);
      pcmd.ne = originalNe;
      return pcmd;
    }

    // === PACE/AES branch ===
    // Per ICAO 9303-11: MAC input = SSC || pad16(masked_header) || DO87 || DO97, then M2 pad
    // The masked header MUST be padded to 16 bytes BEFORE concatenation with DOs
    final paddedHeader = ISO9797.pad(header, blockLen()); // => 16 bytes

    // Build body with padded header + present DOs
    final macBody = Uint8List.fromList([
      ...paddedHeader, // padded masked header (16 bytes)
      ...dataDO, // DO87 if data present
      ...do97, // DO97 if Le present
    ]);

    _log.verbose("paddedHeader=${paddedHeader.hex()}");
    _log.verbose("dataDO=${dataDO.hex()}");
    _log.verbose("do97=${do97.hex()}");

    // MAC input is SSC || pad16(macBody)
    final macInput = Uint8List.fromList([
      ..._ssc.toBytes(), // 16 bytes
      ...ISO9797.pad(macBody, blockLen()), // padded body
    ]);

    _log.verbose("MAC input=${macInput.hex()}");
    _log.verbose("  used SSC=${_ssc.toBytes().hex()}");

    print("=== MrtdSM.protect() calling cipher.mac() ===");
    print("MAC input length: ${macInput.length}");
    print("MAC input: ${macInput.hex()}");

    final fullCC = cipher.mac(macInput);

    print("Back from cipher.mac()");
    print("fullCC length: ${fullCC.length}");
    print("fullCC: ${fullCC.hex()}");

    if (fullCC.length != 16) {
      print("*** WARNING: Expected 16 bytes, got ${fullCC.length} bytes! ***");
    }

    _log.verbose("Full 16-byte CMAC=${fullCC.hex()}");
    final macFragment = Uint8List.fromList(fullCC.sublist(0, 8));
    _log.verbose("MACFragment CC=${macFragment.hex()}");
    print("Truncated to 8 bytes: ${macFragment.hex()}");

    final do8E = SecureMessaging.do8E(macFragment);
    pcmd.data = Uint8List.fromList([...dataDO, ...do97, ...do8E]);
    // JMRTD appends Le=00 for all protected APDUs (even when DO'97' is omitted)
    // This provides case-4 framing that many cards expect
    pcmd.ne = 256; // Encodes as trailing 0x00 byte on wire
    _log.verbose("Protected APDU: ${pcmd.toString()}");
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

    Uint8List macMaterial;
    Uint8List CC;
    if (cipher.type == CipherAlgorithm.DESede) {
      macMaterial = generateK(data: rapdu.data!.sublist(0, do8EStart));
      CC = cipher.mac(macMaterial);
    } else {
      // For AES/PACE: pad the response body before computing MAC
      final responseBody = rapdu.data!.sublist(0, do8EStart);
      final paddedBody = ISO9797.pad(responseBody, blockLen());
      macMaterial = Uint8List.fromList([
        ..._ssc.toBytes(),
        ...paddedBody,
      ]);
      CC = cipher.mac(macMaterial);
    }

    _log.verbose("MAC input=${macMaterial.hex()}");
    _log.verbose("  used SSC=${_ssc.toBytes().hex()}");
    _log.verbose("APDU CC=${do8E.value.hex()}");
    _log.verbose("Calculated CC=${CC.hex()}");

    final expectedMacFragment = CC.sublist(0, do8E.value.length);
    if (!_eq(expectedMacFragment, do8E.value)) {
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
    final upK = Uint8List.fromList(_ssc.toBytes() + data);
    return ISO9797.pad(upK, blockLen());
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
