import 'dart:typed_data';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:logging/logging.dart';

import 'access_key.dart';
import '../crypto/kdf.dart';

class PinKey extends AccessKey {
  static final _log = Logger("AccessKey.CanKeys");

  @override
  int PACE_REF_KEY_TAG = 0x03; // ICAO: 0x03 = PIN

  final Uint8List _pinBytes;

  /// Constructs [PinKey] using a 4- to 6-digit PIN.
  PinKey(String pin) : _pinBytes = _encodePin(pin) {
    if (!_isValidPin(pin)) {
      throw ArgumentError("PIN must be 4–6 numeric digits");
    }
  }

  static bool _isValidPin(String pin) {
    final RegExp regex = RegExp(r'^\d{4,6}$');
    return regex.hasMatch(pin);
  }

  static Uint8List _encodePin(String pin) {
    return Uint8List.fromList(pin.codeUnits);
  }

  @override
  Uint8List Kpi(CipherAlgorithm cipherAlgorithm, KEY_LENGTH keyLength) {
    switch ((cipherAlgorithm, keyLength)) {
      case (CipherAlgorithm.AES, KEY_LENGTH.s128):
        return DeriveKey.aes128(_pinBytes, paceMode: true);
      case (CipherAlgorithm.AES, KEY_LENGTH.s192):
        return DeriveKey.aes192(_pinBytes, paceMode: true);
      case (CipherAlgorithm.AES, KEY_LENGTH.s256):
        return DeriveKey.aes256(_pinBytes, paceMode: true);
      case (CipherAlgorithm.DESede, _):
        return DeriveKey.desEDE(_pinBytes, paceMode: true);
      default:
        throw ArgumentError("Unsupported cipher/keyLength combo");
    }
  }

  @override
  String toString() {
    return "PinKey(PIN: ${_pinBytes.map((b) => "*").join()})";
  }
}
