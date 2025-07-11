// import 'dart:convert';
// import 'dart:typed_data';
// import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
// import 'package:dmrtd/src/proto/iso7816/response_apdu.dart';
// import 'package:dmrtd/src/proto/iso7816/iso7816.dart';
// import 'package:dmrtd/src/proto/mrtd_api.dart';

/// Thrown when a PIN verification fails but retries are still available.
class PinVerificationFailedException implements Exception {
  final int retriesLeft;
  PinVerificationFailedException(this.retriesLeft);
  @override
  String toString() => 'PIN verification failed. Retries left: \$retriesLeft';
}

/// Thrown when a PIN has been entered incorrectly too many times and is now blocked.
class PinPermanentlyBlockedException implements Exception {
  @override
  String toString() => 'PIN is permanently blocked.';
}

// extension PinVerification on MrtdApi {
//   /// Sends VERIFY PIN APDU and handles response.
//   Future<void> verifyPin(String pin) async {
//     if (pin.isEmpty) throw ArgumentError('PIN cannot be empty');
//     final pinBytes = utf8.encode(pin);
//     if (pinBytes.length > 12) throw ArgumentError('PIN is too long');

//     // Pad to 12 bytes with 0xFF
//     final padded = Uint8List(12)..fillRange(0, 12, 0xFF);
//     padded.setRange(0, pinBytes.length, pinBytes);

//     // Build APDU: CLA=ISO7816_CLA.NO_SM, INS=VERIFY, P1=0x00, P2=0x03
//     final apdu = CommandAPDU(
//       cla: ISO7816_CLA.NO_SM,
//       ins: ISO7816_INS.VERIFY,
//       p1: 0x00,
//       p2: 0x03, // PIN reference ID from log
//       data: padded,
//     );

//     // Use the ICC instance within MrtdApi for transceive
//     final rapdu = await icc.transceive(apdu);

//     // Success: status word 0x9000
//     if (rapdu.status == StatusWord.success) return;

//     // Authentication failed: SW1=0x63, lower nibble of SW2 = retries
//     if (rapdu.status.sw1 == StatusWord.authenticationFailed.sw1) {
//       final retries = rapdu.status.sw2 & 0x0F;
//       if (retries == 0) throw PinPermanentlyBlockedException();
//       throw PinVerificationFailedException(retries);
//     }

//     // Other blocking codes (e.g., classNotSupported for 0x6983)
//     if (rapdu.status == StatusWord.classNotSupported) {
//       throw PinPermanentlyBlockedException();
//     }

//     throw Exception(
//         'Unexpected status word: 0x\${rapdu.status.sw1.toRadixString(16)}'
//         '\${rapdu.status.sw2.toRadixString(16)}');
//   }
// }
