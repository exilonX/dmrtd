// Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/export.dart';
import 'ssc.dart';
import 'iso7816/smcipher.dart';
import '../crypto/aes.dart';

class AES_SMCipher implements SMCipher {
  static final _log = Logger("AES_SMCipher");
  @override
  CipherAlgorithm type = CipherAlgorithm.AES;

  Uint8List KSenc;
  Uint8List KSmac;
  AESCipher cipher;

  AES_SMCipher(this.KSenc, this.KSmac, {required KEY_LENGTH size})
      : cipher = AESCipher(size: size) {
    // print("=== AES_SMCipher CONSTRUCTOR ===");
    // print("K_enc length: ${KSenc.length} bytes");
    // print("K_enc: ${KSenc.hex()}");
    // print("K_mac length: ${KSmac.length} bytes");
    // print("K_mac: ${KSmac.hex()}");
    // print("Key size enum: $size");
    // print("Key size in bytes: ${_keySizeToBytes(size)}");
    // print("AES cipher created: ${cipher.runtimeType}");
    // print("=== AES_SMCipher INITIALIZED ===");
  }

  int _keySizeToBytes(KEY_LENGTH size) {
    switch (size) {
      case KEY_LENGTH.s128:
        return 16;
      case KEY_LENGTH.s192:
        return 24;
      case KEY_LENGTH.s256:
        return 32;
    }
  }

  @override
  CipherAlgorithm get cipherAlgorithm => type;

  @override
  Uint8List encrypt(Uint8List data, {SSC? ssc}) {
    // _log.debug(
    //     "encrypt: data size: ${data.length}, ssc: ${ssc?.toBytes().hex()}");
    // _log.sdVerbose("encrypt: data: ${data.hex()}, KSenc: ${KSenc.hex()}");
    if (ssc == null)
      throw Exception("PACE_SMCipher_AES.encrypt: SSC should not be null");

    // print("=== AES_SMCipher.encrypt() ENTRY ===");
    // print("Data to encrypt length: ${data.length}");
    // print("Data to encrypt: ${data.hex()}");
    // print("SSC: ${ssc.toBytes().hex()}");
    // print("K_enc: ${KSenc.hex()}");

    //IV = E(KSenc, SCC)
    // _log.sdDebug(
    //     "Encrypting IV with KSenc: ${KSenc.hex()}, ssc: ${ssc.toBytes().hex()}");
    // 2. Create a temporary AES/ECB cipher with the session key (KSenc).
    final ecbCipher = ECBBlockCipher(AESEngine())
      ..init(true, KeyParameter(KSenc));
    // 3. Encrypt the SSC block to produce the IV.
    final iv = Uint8List(16);
    ecbCipher.processBlock(ssc.toBytes(), 0, iv, 0);
    // _log.fine("Derived IV for encryption: ${iv.hex()}");
    // print("Derived IV = E(K_enc, SSC): ${iv.hex()}");

    // 4. Now, encrypt the actual data using AES/CBC with the IV we just made.
    final cbcCipher = CBCBlockCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(KSenc), iv));

    final encrypted = Uint8List(data.length);
    var offset = 0;
    while (offset < data.length) {
      offset += cbcCipher.processBlock(data, offset, encrypted, offset);
    }

    // print("Encrypted data: ${encrypted.hex()}");
    // print("=== AES_SMCipher.encrypt() EXIT ===");

    return encrypted;
  }

  @override
  Uint8List decrypt(Uint8List data, {SSC? ssc}) {
    if (ssc == null)
      throw Exception("AES_SMCipher.decrypt: SSC should not be null");

    // print("=== AES_SMCipher.decrypt() ENTRY ===");
    // print("Data to decrypt length: ${data.length}");
    // print("Data to decrypt: ${data.hex()}");
    // print("SSC: ${ssc.toBytes().hex()}");
    // print("K_enc: ${KSenc.hex()}");

    // --- REPLICATE THE SAME LOGIC FOR DECRYPTION ---

    // 1. Get the current 16-byte SSC value.
    final sscBytes = ssc.toBytes();
    // _log.fine("Decrypting with SSC: ${sscBytes.hex()}");

    // 2. Create the temporary AES/ECB cipher.
    final ecbCipher = ECBBlockCipher(AESEngine())
      ..init(true, KeyParameter(KSenc));

    // 3. Encrypt the SSC block to re-create the IV that was used by the sender.
    final iv = Uint8List(16);
    ecbCipher.processBlock(sscBytes, 0, iv, 0);
    _log.fine("Derived IV for decryption: ${iv.hex()}");
    // print("Derived IV = E(K_enc, SSC): ${iv.hex()}");

    // 4. Decrypt the data using AES/CBC with the re-created IV.
    final cbcCipher = CBCBlockCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(KSenc), iv));

    final decrypted = Uint8List(data.length);
    var offset = 0;
    while (offset < data.length) {
      offset += cbcCipher.processBlock(data, offset, decrypted, offset);
    }

    // print("Decrypted data: ${decrypted.hex()}");
    // print("=== AES_SMCipher.decrypt() EXIT ===");

    return decrypted;
  }

  @override
  Uint8List mac(Uint8List data) {
    // _log.fine("mac: data size: ${data.length}");
    // _log.fine("mac: K_mac=${KSmac.hex()}");
    // _log.sdVerbose("mac: data: ${data.hex()}, KSmac: ${KSmac.hex()}");

    // print("=== AES_SMCipher.mac() ENTRY ===");
    // print("Data length: ${data.length}");
    // print("Data: ${data.hex()}");
    // print("K_mac length: ${KSmac.length}");
    // print("K_mac: ${KSmac.hex()}");
    // print("About to call cipher.calculateCMAC()...");

    Uint8List cmac = cipher.calculateCMAC(data: data, key: KSmac);

    // print("Back from cipher.calculateCMAC()");
    // print("Returned CMAC length: ${cmac.length}");
    // print("Returned CMAC: ${cmac.hex()}");
    // print("=== AES_SMCipher.mac() EXIT ===");

    // _log.fine("CMAC result: ${cmac.hex()}");
    // _log.sdVerbose("CMAC: ${cmac.hex()}");
    return cmac;
  }
}
