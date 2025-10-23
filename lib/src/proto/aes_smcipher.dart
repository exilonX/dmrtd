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
      : cipher = AESCipher(size: size);

  @override
  CipherAlgorithm get cipherAlgorithm => type;

  @override
  Uint8List encrypt(Uint8List data, {SSC? ssc}) {
    _log.debug(
        "encrypt: data size: ${data.length}, ssc: ${ssc?.toBytes().hex()}");
    _log.sdVerbose("encrypt: data: ${data.hex()}, KSenc: ${KSenc.hex()}");
    if (ssc == null)
      throw Exception("PACE_SMCipher_AES.encrypt: SSC should not be null");

    //IV = E(KSenc, SCC)
    _log.sdDebug(
        "Encrypting IV with KSenc: ${KSenc.hex()}, ssc: ${ssc.toBytes().hex()}");
    // 2. Create a temporary AES/ECB cipher with the session key (KSenc).
    final ecbCipher = ECBBlockCipher(AESEngine())
      ..init(true, KeyParameter(KSenc));
    // 3. Encrypt the SSC block to produce the IV.
    final iv = Uint8List(16);
    ecbCipher.processBlock(ssc.toBytes(), 0, iv, 0);
    _log.fine("Derived IV for encryption: ${iv.hex()}");

    // 4. Now, encrypt the actual data using AES/CBC with the IV we just made.
    final cbcCipher = CBCBlockCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(KSenc), iv));

    final encrypted = Uint8List(data.length);
    var offset = 0;
    while (offset < data.length) {
      offset += cbcCipher.processBlock(data, offset, encrypted, offset);
    }

    return encrypted;
  }

  @override
  Uint8List decrypt(Uint8List data, {SSC? ssc}) {
    if (ssc == null)
      throw Exception("AES_SMCipher.decrypt: SSC should not be null");

    // --- REPLICATE THE SAME LOGIC FOR DECRYPTION ---

    // 1. Get the current 16-byte SSC value.
    final sscBytes = ssc.toBytes();
    _log.fine("Decrypting with SSC: ${sscBytes.hex()}");

    // 2. Create the temporary AES/ECB cipher.
    final ecbCipher = ECBBlockCipher(AESEngine())
      ..init(true, KeyParameter(KSenc));

    // 3. Encrypt the SSC block to re-create the IV that was used by the sender.
    final iv = Uint8List(16);
    ecbCipher.processBlock(sscBytes, 0, iv, 0);
    _log.fine("Derived IV for decryption: ${iv.hex()}");

    // 4. Decrypt the data using AES/CBC with the re-created IV.
    final cbcCipher = CBCBlockCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(KSenc), iv));

    final decrypted = Uint8List(data.length);
    var offset = 0;
    while (offset < data.length) {
      offset += cbcCipher.processBlock(data, offset, decrypted, offset);
    }
    return decrypted;
  }

  @override
  Uint8List mac(Uint8List data) {
    _log.fine("mac: data size: ${data.length}");
    _log.fine("mac: K_mac=${KSmac.hex()}");
    _log.sdVerbose("mac: data: ${data.hex()}, KSmac: ${KSmac.hex()}");
    Uint8List cmac = cipher.calculateCMAC(data: data, key: KSmac);
    _log.fine("CMAC result: ${cmac.hex()}");
    _log.sdVerbose("CMAC: ${cmac.hex()}");
    return cmac;
  }
}
