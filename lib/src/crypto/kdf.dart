// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'package:crypto/crypto.dart';
import 'package:fixnum/fixnum.dart';
import 'dart:typed_data';

/// Implements key derivation function as specified in ICAO 9303 p11 Section 9.7.1
/// Key is derived by [hash] object using [keySeed] bytes and [counter] number.
// ignore: non_constant_identifier_names
Uint8List KDF(final Hash hash, final Uint8List keySeed, final Int32 counter) {
  Uint8List preimage = Uint8List(keySeed.length + 4);
  preimage.setRange(0, keySeed.length, keySeed);

  ByteData piview = ByteData.view(preimage.buffer);
  piview.setInt32(keySeed.length, counter.toInt(), Endian.big);
  return hash.convert(preimage).bytes as Uint8List;
}

enum DeriveKeyType {
  // Encryption key types
  DESede,
  AES128,
  AES192,
  AES256,

  // MAC key types
  ISO9797MacAlg3,
  CMAC128,
  CMAC192,
  CMAC256
}

/// Implements key derivation function as specified in
/// ICAO 9303 p11 Sections: 9.7.1.1, 9.7.1.2, 9.7.1.3, 9.7.1.4
class DeriveKey {
  static Uint8List iso9797MacAlg3(final Uint8List keySeed) =>
      derive(DeriveKeyType.ISO9797MacAlg3, keySeed);
  static Uint8List cmac128(final Uint8List keySeed) =>
      derive(DeriveKeyType.CMAC128, keySeed);
  static Uint8List cmac192(final Uint8List keySeed) =>
      derive(DeriveKeyType.CMAC192, keySeed);
  static Uint8List cmac256(final Uint8List keySeed) =>
      derive(DeriveKeyType.CMAC256, keySeed);
  static Uint8List desEDE(final Uint8List keySeed) =>
      derive(DeriveKeyType.DESede, keySeed);
  static Uint8List aes128(final Uint8List keySeed) =>
      derive(DeriveKeyType.AES128, keySeed);
  static Uint8List aes192(final Uint8List keySeed) =>
      derive(DeriveKeyType.AES192, keySeed);
  static Uint8List aes256(final Uint8List keySeed) =>
      derive(DeriveKeyType.AES256, keySeed);

  /// Returns key from [keySeed] bytes for specific [keyType] and
  /// counter mode specific for key type (1 - ENC mode, 2 - MAC mode).
  /// If [paceMode] is true counter 3 for encryption key types.
  static Uint8List derive(
      final DeriveKeyType keyType, final Uint8List keySeed) {
    Int32 mode;
    switch (keyType) {
      case DeriveKeyType.DESede:
      case DeriveKeyType.AES128:
      case DeriveKeyType.AES192:
      case DeriveKeyType.AES256:
        mode = Int32(1); // ENC mode
        break;
      case DeriveKeyType.ISO9797MacAlg3:
      case DeriveKeyType.CMAC128:
      case DeriveKeyType.CMAC192:
      case DeriveKeyType.CMAC256:
        mode = Int32(2); // MAC mode
        break;
    }

    switch (keyType) {
      case DeriveKeyType.DESede:
      case DeriveKeyType.ISO9797MacAlg3:
        final key = KDF(sha1, keySeed, mode).sublist(0, 16);
        // Adjust parity bits
        for (int i = 0; i < key.length; i++) {
          var count = 0;
          for (int j = 0; j < 8; j++) {
            count += (key[i] >> j) & 0x01;
          }
          if (count % 2 == 0) {
            key[i] ^= 0x01;
          }
        }
        return key;

      case DeriveKeyType.AES128:
      case DeriveKeyType.CMAC128:
        // ICAO 9303, Part 11, 9.7.2 requires SHA-1 for 128-bit keys
        return KDF(sha1, keySeed, mode).sublist(0, 16);

      case DeriveKeyType.AES192:
      case DeriveKeyType.CMAC192:
        // ICAO 9303, Part 11, 9.7.2 requires SHA-256 for 192-bit keys
        return KDF(sha256, keySeed, mode).sublist(0, 24);

      case DeriveKeyType.AES256:
      case DeriveKeyType.CMAC256:
        // ICAO 9303, Part 11, 9.7.2 requires SHA-256 for 256-bit keys
        return KDF(sha256, keySeed, mode);
    }
  }
}
