// Test to verify CMAC calculation matches JMRTD exactly
// This isolates whether the issue is in SM layer or PACE key derivation

import 'package:test/test.dart';
import 'package:dmrtd/extensions.dart';
import 'dart:typed_data';
import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';

void main() {
  group('CMAC Sanity Test - Match JMRTD', () {
    test('JMRTD CMAC calculation for protected SELECT', () {
      // From JMRTD log:
      // Data for MAC calculation (N):
      // 000000000000000000000000000000010CA4040C80000000000000000000000087110116C16C676FB768762FE51F8E82865BD880000000000000000000000000

      final macInput = Uint8List.fromList([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SSC part 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SSC part 2
        0x0C, 0xA4, 0x04, 0x0C, 0x80, 0x00, 0x00, 0x00, // Padded header part 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padded header part 2
        0x87, 0x11, 0x01, 0x16, 0xC1, 0x6C, 0x67, 0x6F, // DO'87 part 1
        0xB7, 0x68, 0x76, 0x2F, 0xE5, 0x1F, 0x8E, 0x82, // DO'87 part 2
        0x86, 0x5B, 0xD8, // DO'87 part 3
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding part 1
        0x00, 0x00, 0x00, 0x00, 0x00 // Padding part 2
      ]);

      print("=== CMAC SANITY TEST ===");
      print("MAC input from JMRTD:");
      print(macInput.hex());
      print("MAC input length: ${macInput.length}");

      // JMRTD expected output:
      // Full 16-byte MAC calculated: AD40DFEAF0E2ECDC3EFE8C44D6B2C591
      // Truncated 8-byte MAC: AD40DFEAF0E2ECDC

      final expectedFullMAC = Uint8List.fromList([
        0xAD,
        0x40,
        0xDF,
        0xEA,
        0xF0,
        0xE2,
        0xEC,
        0xDC,
        0x3E,
        0xFE,
        0x8C,
        0x44,
        0xD6,
        0xB2,
        0xC5,
        0x91
      ]);

      final expectedTruncatedMAC =
          Uint8List.fromList([0xAD, 0x40, 0xDF, 0xEA, 0xF0, 0xE2, 0xEC, 0xDC]);

      // TODO: We need the Kmac from JMRTD to complete this test
      // For now, just verify the input is correct
      expect(macInput.length, equals(64));

      print("\nExpected JMRTD results:");
      print("Full 16-byte MAC: ${expectedFullMAC.hex()}");
      print("Truncated 8-byte MAC: ${expectedTruncatedMAC.hex()}");

      print("\n⚠️  To complete this test, we need Kmac from JMRTD");
      print("Please add logging in JMRTD to show Kmac value");
      print("=========================\n");
    });

    test('Calculate CMAC with known test vector', () {
      // K_mac from JMRTD log: 396D064C343B225F4BF511CC71943EA15922568D6EE2DD8354DABEB291A41BD6
      final kmac = Uint8List.fromList([
        0x39,
        0x6D,
        0x06,
        0x4C,
        0x34,
        0x3B,
        0x22,
        0x5F,
        0x4B,
        0xF5,
        0x11,
        0xCC,
        0x71,
        0x94,
        0x3E,
        0xA1,
        0x59,
        0x22,
        0x56,
        0x8D,
        0x6E,
        0xE2,
        0xDD,
        0x83,
        0x54,
        0xDA,
        0xBE,
        0xB2,
        0x91,
        0xA4,
        0x1B,
        0xD6,
      ]);

      // MAC input from JMRTD (same as above test)
      final macInput = Uint8List.fromList([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SSC part 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SSC part 2
        0x0C, 0xA4, 0x04, 0x0C, 0x80, 0x00, 0x00, 0x00, // Padded header part 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padded header part 2
        0x87, 0x11, 0x01, 0x16, 0xC1, 0x6C, 0x67, 0x6F, // DO'87 part 1
        0xB7, 0x68, 0x76, 0x2F, 0xE5, 0x1F, 0x8E, 0x82, // DO'87 part 2
        0x86, 0x5B, 0xD8, // DO'87 part 3
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding part 1
        0x00, 0x00, 0x00, 0x00, 0x00 // Padding part 2
      ]);

      // JMRTD expected output
      final expectedFullMAC = Uint8List.fromList([
        0xAD,
        0x40,
        0xDF,
        0xEA,
        0xF0,
        0xE2,
        0xEC,
        0xDC,
        0x3E,
        0xFE,
        0x8C,
        0x44,
        0xD6,
        0xB2,
        0xC5,
        0x91
      ]);

      print("\n=== CALCULATING CMAC WITH JMRTD Kmac ===");
      print("Kmac: ${kmac.hex()}");
      print("MAC input: ${macInput.hex()}");

      // Calculate CMAC using our implementation
      final cipher = AESCipher(size: KEY_LENGTH.s256);
      final result = cipher.calculateCMAC(data: macInput, key: kmac);

      print("Our CMAC result:      ${result.hex()}");
      print("JMRTD expected CMAC:  ${expectedFullMAC.hex()}");

      // Verify it matches
      expect(result.hex().toUpperCase(),
          equals(expectedFullMAC.hex().toUpperCase()));

      // Also check truncated version
      final truncated = result.sublist(0, 8);
      print("Our truncated (8 bytes): ${truncated.hex()}");
      print("JMRTD truncated:         AD40DFEAF0E2ECDC");

      print("✅ CMAC calculation matches JMRTD!");
      print("=====================================\n");
    });
  });
}
