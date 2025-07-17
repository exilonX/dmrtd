// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import '../../lds/tlv.dart';
import '../../utils.dart';

import 'command_apdu.dart';
import 'response_apdu.dart';
import 'smcipher.dart';

class SMError implements Exception {
  final String message;
  SMError(this.message);
  @override
  String toString() => "SMError: $message";
}

// Class defines ISO/IEC 7816-4 Secure Messaging (SM) interface.
// ref: section 5.6 of ISO/IEC 7816-4 doc
abstract class SecureMessaging {
  static const tagDO85 = 0x85;
  static const tagDO87 = 0x87;
  static const tagDO8E = 0x8E;
  static const tagDO97 = 0x97;
  static const tagDO99 = 0x99;

  final SMCipher cipher;
  SecureMessaging(this.cipher);

  CommandAPDU protect(final CommandAPDU cmd);
  ResponseAPDU unprotect(final ResponseAPDU rapdu);

  static Uint8List do85(final Uint8List data) {
    return _buildDO(tagDO85, data);
  }

  static Uint8List do87(final Uint8List data, {bool dataIsPadded = true}) {
    if (data.isEmpty) {
      return Uint8List(0);
    }
    final data1 = Uint8List.fromList([dataIsPadded ? 0x01 : 0x02] +
        data); // Padding info byte defined in ISO/IEC 7816-4 part 5
    return _buildDO(tagDO87, data1);
  }

  static Uint8List do8E(final Uint8List data) {
    return _buildDO(tagDO8E, data);
  }

  static Uint8List do97(final int? ne) {
    // Make ne nullable to handle cmd.ne being null
    final int expectedLength = ne ?? 0;

    // ======================= THE FINAL FIX =======================
    // As per the guide, if Le (ne) is 0, we must still encode DO97 as "97 01 00".
    if (expectedLength == 0) {
      return TLV.encode(tagDO97, Uint8List.fromList([0x00]));
    }
    // ===============================================================

    if (expectedLength == 256) {
      // For Le=256, value is 0x00. Length is 1 byte.
      return TLV.encode(tagDO97, Uint8List.fromList([0x00]));
    }
    if (expectedLength == 65536) {
      // For Le=65536, value is 0x0000. Length is 2 bytes.
      return TLV.encode(tagDO97, Uint8List.fromList([0x00, 0x00]));
    }

    // For all other cases, use the existing logic.
    return _buildDO(tagDO97, Utils.intToBin(expectedLength, minLen: 0));
  }

  static Uint8List do99(final int ne) {
    return _buildDO(tagDO99, Utils.intToBin(ne, minLen: 0));
  }

  static Uint8List _buildDO(final int tag, final Uint8List data) {
    assert(tag < 256);
    if (data.isEmpty) {
      return Uint8List(0);
    }
    return TLV.encode(tag, data);
  }
}
