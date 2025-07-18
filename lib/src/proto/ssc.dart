// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';

import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/crypto/des.dart';
import 'package:crypto/crypto.dart';

/// Class represents Send Sequence Counter as specified in
/// section 9.8.2 of ICAO 9303 p11 doc.
///
/// SSC by definition is unsigned integer whose bit size
/// is equal to the block size of block cipher.
class SSC {
  final int bitSize;
  late BigInt _ssc;

  /// Constructs new [SSC] with [ssc] bytes.
  /// [bitSize] should be equal to the block size of block cipher.
  SSC(Uint8List ssc, this.bitSize) {
    if ((bitSize % 8) != 0) {
      throw ArgumentError.value(
          bitSize, null, "(bitSize) must be multiple of 8");
    }

    _ssc = BigInt.parse(ssc.hex(), radix: 16);
    if (_ssc.bitLength > bitSize) {
      throw ArgumentError.value(ssc, null,
          "Bit size of provided argument (ssc) is greater than argument (bitSize)");
    }
  }

  static SSC fromBAC({
    required Uint8List iccEphemeral,
    required Uint8List ifdEphemeral,
    required int bitSize,
  }) {
    final byteSize = bitSize ~/ 8;
    final halfLength = byteSize ~/ 2;

    if (iccEphemeral.length < halfLength || ifdEphemeral.length < halfLength) {
      throw ArgumentError('Public key too short for computing SSC: '
          'need at least $halfLength bytes');
    }

    final iccTail = iccEphemeral.sublist(iccEphemeral.length - halfLength);
    final ifdTail = ifdEphemeral.sublist(ifdEphemeral.length - halfLength);
    final sscBytes = Uint8List.fromList([...iccTail, ...ifdTail]);

    return SSC(sscBytes, bitSize);
  }

  static SSC fromPACE({
    required Uint8List iccEphemeral,
    required Uint8List ifdEphemeral,
  }) {
    final concatenated = Uint8List.fromList([...iccEphemeral, ...ifdEphemeral]);
    final hash = sha1.convert(concatenated).bytes;
    final sscBytes = Uint8List.fromList(
        hash.sublist(hash.length - 16)); // Last 16 bytes of SHA-1 hash
    return SSC(sscBytes, 128); // AES SSC bit size is always 128 bits (16 bytes)
  }

  void increment() {
    _ssc += BigInt.from(1);
    if (_ssc.bitLength > bitSize) {
      _ssc = BigInt.from(0);
    }
  }

  Uint8List toBytes() {
    final padLen = (bitSize / 8).round() * 2;
    final hexSSC = _ssc.toRadixString(16).padLeft(padLen, '0');
    return hexSSC.parseHex();
  }
}

class DESedeSSC extends SSC {
  DESedeSSC(Uint8List ssc) : super(ssc, DESedeCipher.blockSize * 8);
}

class DESede_PACE_SSC extends SSC {
  DESede_PACE_SSC() : super(Uint8List(8), DESedeCipher.blockSize * 8);
}

class AES_SSC extends SSC {
  // icao 9303 p11 doc section 9.8.7.3 specifies that AES SSC is 16 bytes long and is initialized to 0.
  AES_SSC() : super(Uint8List(16), AESCipher128().size * 8);
}
