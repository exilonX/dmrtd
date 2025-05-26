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
  PublicKeyPACEeCDH({required BigInt x, required BigInt y})
      : _x = x,
        _y = y,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  PublicKeyPACEeCDH.fromECPoint({required ECPoint public})
      : _x = public.x!.toBigInteger()!,
        _y = public.y!.toBigInteger()!,
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  BigInt get x => _x;
  BigInt get y => _y;

  Uint8List get xBytes => Utils.bigIntToUint8List(bigInt: _x);
  Uint8List get yBytes => Utils.bigIntToUint8List(bigInt: _y);

  // Helper: pad BigInt to correct size (32 bytes for P-256, BrainpoolP256r1)
  Uint8List _bigIntTo32Bytes(BigInt n) {
    // Always pad to 32 bytes (change if curve is not 256 bit!)
    final raw = n.toUnsigned(256).toRadixString(16).padLeft(64, '0');
    return Uint8List.fromList(List<int>.generate(
        32, (i) => int.parse(raw.substring(i * 2, i * 2 + 2), radix: 16)));
  }

  @override
  Uint8List toBytes() {
    // SEC1 uncompressed: 0x04 + 32-byte X + 32-byte Y
    return Uint8List.fromList([
      0x04,
      ..._bigIntTo32Bytes(_x),
      ..._bigIntTo32Bytes(_y),
    ]);
  }

  PublicKeyPACEeCDH.fromHex({required Uint8List hexKey})
      : _x = Utils.uint8ListToBigInt(hexKey.sublist(0, hexKey.length ~/ 2)),
        _y = Utils.uint8ListToBigInt(hexKey.sublist(hexKey.length ~/ 2)),
        super(algo: TOKEN_AGREEMENT_ALGO.ECDH);

  @override
  Uint8List toRelavantBytes() {
    // For key agreement you usually need both X and Y, so return toBytes
    return toBytes();
  }

  @override
  String toString() {
    return "X: ${_bigIntTo32Bytes(_x).hex()}\nY: ${_bigIntTo32Bytes(_y).hex()}";
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
