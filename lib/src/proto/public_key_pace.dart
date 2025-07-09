//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.

import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:pointycastle/ecc/api.dart';

import '../lds/asn1ObjectIdentifiers.dart';
import '../utils.dart';

abstract class PublicKeyPACE {
  TOKEN_AGREEMENT_ALGO algo;

  TOKEN_AGREEMENT_ALGO get agreementAlgorithm => algo;

  PublicKeyPACE({required this.algo});

  Uint8List toBytes();

  Uint8List toRelavantBytes();

  String toString();
}

class PublicKeyPACEeCDH extends PublicKeyPACE {
  final BigInt _x;
  final BigInt _y;
  final int fieldSizeInBits; // We need this to know how much to pad

  PublicKeyPACEeCDH(
      {required BigInt x, required BigInt y, required this.fieldSizeInBits})
      : _x = x,
        _y = y,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  PublicKeyPACEeCDH.fromECPoint(
      {required ECPoint public, required this.fieldSizeInBits})
      : _x = public.x!.toBigInteger()!,
        _y = public.y!.toBigInteger()!,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  BigInt get x => _x;
  BigInt get y => _y;

  Uint8List get xBytes => Utils.bigIntToUint8List(bigInt: _x);
  Uint8List get yBytes => Utils.bigIntToUint8List(bigInt: _y);

  @override
  Uint8List toBytes() {
    // This is the fixed part. It now formats the public key correctly for PACE.
    // SEC1 format: 0x04 || Padded-X || Padded-Y
    final int fieldSizeInBytes = (fieldSizeInBits / 8).ceil();

    final xBytes = Utils.bigIntToUint8List(bigInt: x);
    final yBytes = Utils.bigIntToUint8List(bigInt: y);

    final paddedX = Uint8List(fieldSizeInBytes);
    final paddedY = Uint8List(fieldSizeInBytes);

    // Copy the bytes to the end of the padded list (this creates left-padding with zeros)
    paddedX.setRange(
        fieldSizeInBytes - xBytes.length, fieldSizeInBytes, xBytes);
    paddedY.setRange(
        fieldSizeInBytes - yBytes.length, fieldSizeInBytes, yBytes);

    return Uint8List.fromList([0x04, ...paddedX, ...paddedY]);
  }

  @override
  Uint8List toRelavantBytes() => toBytes();

  PublicKeyPACEeCDH.fromHex(
      {required Uint8List hexKey, required int fieldSizeInBits})
      : _x = Utils.uint8ListToBigInt(hexKey.sublist(0, hexKey.length ~/ 2)),
        _y = Utils.uint8ListToBigInt(hexKey.sublist(hexKey.length ~/ 2)),
        fieldSizeInBits = fieldSizeInBits,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  @override
  String toString() {
    return "X: ${xBytes.hex()}\nY: ${yBytes.hex()}";
  }
}

class PublicKeyPACEdH extends PublicKeyPACE {
  final Uint8List _pub;
  PublicKeyPACEdH({required Uint8List pub})
      : _pub = pub,
        super(algo: TOKEN_AGREEMENT_ALGO.DH);

  Uint8List get pub => _pub;

  @override
  Uint8List toBytes() {
    return _pub;
  }

  @override
  Uint8List toRelavantBytes() {
    return _pub;
  }

  @override
  String toString() {
    return _pub.hex();
  }
}
