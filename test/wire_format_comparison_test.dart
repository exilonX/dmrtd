// Test to compare wire-level APDU format between JMRTD and Flutter implementation
// This verifies that CommandAPDU.toBytes() produces the same byte sequence as JMRTD sends

import 'package:test/test.dart';
import 'package:dmrtd/extensions.dart';
import 'dart:typed_data';
import 'package:dmrtd/src/proto/aes_smcipher.dart';
import 'package:dmrtd/src/proto/mrtd_sm.dart';
import 'package:dmrtd/src/proto/ssc.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';

void main() {
  group('Wire Format Comparison - JMRTD vs Flutter', () {
    test('Verify wire format matches JMRTD exactly (SSC=3)', () {
      print("\n=== WIRE FORMAT COMPARISON TEST ===");
      print("Comparing actual bytes sent to card\n");

      // From JMRTD log - second SELECT command (SSC=3):
      // TX PROT: 0CA4040C1D871101074B34C82347CFB2D6F2C382DC149FCD8E089AB538BA84F6072A00
      final jmrtdWireFormat =
          '0CA4040C1D871101074B34C82347CFB2D6F2C382DC149FCD8E089AB538BA84F6072A00';
      final jmrtdBytes = Uint8List.fromList(jmrtdWireFormat
          .split('')
          .toList()
          .asMap()
          .entries
          .where((e) => e.key % 2 == 0)
          .map((e) =>
              int.parse(jmrtdWireFormat.substring(e.key, e.key + 2), radix: 16))
          .toList());

      print("JMRTD wire bytes: $jmrtdWireFormat");
      print("Length: ${jmrtdBytes.length} bytes\n");

      // Parse JMRTD format
      print("=== JMRTD APDU STRUCTURE ===");
      print("CLA:  0x${jmrtdBytes[0].toRadixString(16).padLeft(2, '0')}");
      print("INS:  0x${jmrtdBytes[1].toRadixString(16).padLeft(2, '0')}");
      print("P1:   0x${jmrtdBytes[2].toRadixString(16).padLeft(2, '0')}");
      print("P2:   0x${jmrtdBytes[3].toRadixString(16).padLeft(2, '0')}");
      print(
          "Lc:   0x${jmrtdBytes[4].toRadixString(16).padLeft(2, '0')} (${jmrtdBytes[4]} bytes)");

      final lcLen = jmrtdBytes[4];
      final dataBytes = jmrtdBytes.sublist(5, 5 + lcLen);
      print("Data: ${dataBytes.hex()} ($lcLen bytes)");
      print(
          "Le:   0x${jmrtdBytes[5 + lcLen].toRadixString(16).padLeft(2, '0')} (256 = 0x00)\n");

      // Now generate the same command with Flutter
      print("=== FLUTTER IMPLEMENTATION ===");

      final kenc = Uint8List.fromList([
        0x82,
        0x11,
        0xA5,
        0x8C,
        0xA9,
        0x42,
        0x40,
        0x57,
        0x90,
        0x4E,
        0x23,
        0x69,
        0xB0,
        0x77,
        0x16,
        0x08,
        0x91,
        0xBD,
        0xD3,
        0x36,
        0xD3,
        0x1D,
        0x19,
        0x04,
        0xF0,
        0x59,
        0xB6,
        0x81,
        0xF6,
        0x95,
        0xC2,
        0x17,
      ]);

      final kmac = Uint8List.fromList([
        0x49,
        0x54,
        0x2A,
        0xED,
        0xBD,
        0x0F,
        0xB3,
        0x2B,
        0x73,
        0x08,
        0x19,
        0xC0,
        0x03,
        0x0B,
        0xCB,
        0x31,
        0x27,
        0x18,
        0xBB,
        0xE8,
        0x61,
        0xCB,
        0xB5,
        0x4A,
        0xEF,
        0x24,
        0x9A,
        0xF9,
        0x8A,
        0x8F,
        0x4A,
        0xA9,
      ]);

      // SSC at 2, will increment to 3
      final ssc = AES_SSC();
      ssc.increment(); // 0 -> 1
      ssc.increment(); // 1 -> 2

      final smCipher = AES_SMCipher(kenc, kmac, size: KEY_LENGTH.s256);
      final sm = MrtdSM(smCipher, ssc);

      // Original command: SELECT A0000002471001
      final plainData =
          Uint8List.fromList([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]);

      final cmd = CommandAPDU(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x0C,
        data: plainData,
        ne: 0,
      );

      final protectedCmd = sm.protect(cmd);
      final flutterBytes = protectedCmd.toBytes();
      final flutterWireFormat = flutterBytes.hex().toUpperCase();

      print("Flutter wire bytes: $flutterWireFormat");
      print("Length: ${flutterBytes.length} bytes\n");

      // Parse Flutter format
      print("=== FLUTTER APDU STRUCTURE ===");
      print("CLA:  0x${flutterBytes[0].toRadixString(16).padLeft(2, '0')}");
      print("INS:  0x${flutterBytes[1].toRadixString(16).padLeft(2, '0')}");
      print("P1:   0x${flutterBytes[2].toRadixString(16).padLeft(2, '0')}");
      print("P2:   0x${flutterBytes[3].toRadixString(16).padLeft(2, '0')}");
      print(
          "Lc:   0x${flutterBytes[4].toRadixString(16).padLeft(2, '0')} (${flutterBytes[4]} bytes)");

      final flutterLcLen = flutterBytes[4];
      final flutterDataBytes = flutterBytes.sublist(5, 5 + flutterLcLen);
      print("Data: ${flutterDataBytes.hex()} ($flutterLcLen bytes)");

      if (flutterBytes.length > 5 + flutterLcLen) {
        print(
            "Le:   0x${flutterBytes[5 + flutterLcLen].toRadixString(16).padLeft(2, '0')} (256 = 0x00)\n");
      } else {
        print("Le:   <none>\n");
      }

      // Compare byte-by-byte
      print("=== BYTE-BY-BYTE COMPARISON ===");
      print("Expected (JMRTD): $jmrtdWireFormat");
      print("Actual (Flutter): $flutterWireFormat");
      print("");

      if (jmrtdBytes.length != flutterBytes.length) {
        print("❌ LENGTH MISMATCH!");
        print("   JMRTD:   ${jmrtdBytes.length} bytes");
        print("   Flutter: ${flutterBytes.length} bytes");
        print("");

        // Show which bytes differ
        final minLen = jmrtdBytes.length < flutterBytes.length
            ? jmrtdBytes.length
            : flutterBytes.length;
        for (int i = 0; i < minLen; i++) {
          if (jmrtdBytes[i] != flutterBytes[i]) {
            print(
                "   Byte $i: JMRTD=0x${jmrtdBytes[i].toRadixString(16).padLeft(2, '0')} "
                "Flutter=0x${flutterBytes[i].toRadixString(16).padLeft(2, '0')} ❌");
          }
        }

        if (jmrtdBytes.length > flutterBytes.length) {
          print(
              "   Flutter MISSING ${jmrtdBytes.length - flutterBytes.length} bytes at end:");
          for (int i = minLen; i < jmrtdBytes.length; i++) {
            print(
                "   Byte $i: JMRTD=0x${jmrtdBytes[i].toRadixString(16).padLeft(2, '0')} Flutter=<missing>");
          }
        } else if (flutterBytes.length > jmrtdBytes.length) {
          print(
              "   Flutter has ${flutterBytes.length - jmrtdBytes.length} EXTRA bytes:");
          for (int i = minLen; i < flutterBytes.length; i++) {
            print(
                "   Byte $i: Flutter=0x${flutterBytes[i].toRadixString(16).padLeft(2, '0')} (extra)");
          }
        }
      } else {
        // Same length, check each byte
        bool allMatch = true;
        for (int i = 0; i < jmrtdBytes.length; i++) {
          if (jmrtdBytes[i] != flutterBytes[i]) {
            allMatch = false;
            print(
                "   Byte $i: JMRTD=0x${jmrtdBytes[i].toRadixString(16).padLeft(2, '0')} "
                "Flutter=0x${flutterBytes[i].toRadixString(16).padLeft(2, '0')} ❌");
          }
        }

        if (allMatch) {
          print("✅ PERFECT MATCH! All ${jmrtdBytes.length} bytes identical!");
        }
      }

      // Final assertion
      expect(flutterBytes.hex().toUpperCase(), equals(jmrtdWireFormat),
          reason: "Wire format must match JMRTD exactly");

      print("\n🎉 Wire format test PASSED!");
      print("Flutter sends the EXACT same bytes as JMRTD!\n");
    });

    test('First command wire format (SSC=1)', () {
      print("\n=== FIRST COMMAND WIRE FORMAT (SSC=1) ===\n");

      // From JMRTD log - first command after PACE
      // Expected based on integration test:
      // Protected data: 87110168DCB0BBCF666F019EBA74B3C093FB998E0850A12D9362F63DC1
      // Full APDU: 0CA4040C1D + data + 00
      final expectedWire =
          '0CA4040C1D87110168DCB0BBCF666F019EBA74B3C093FB998E0850A12D9362F63DC100';

      print("Expected wire: $expectedWire");
      print("Length: ${expectedWire.length ~/ 2} bytes\n");

      final kenc = Uint8List.fromList([
        0x82,
        0x11,
        0xA5,
        0x8C,
        0xA9,
        0x42,
        0x40,
        0x57,
        0x90,
        0x4E,
        0x23,
        0x69,
        0xB0,
        0x77,
        0x16,
        0x08,
        0x91,
        0xBD,
        0xD3,
        0x36,
        0xD3,
        0x1D,
        0x19,
        0x04,
        0xF0,
        0x59,
        0xB6,
        0x81,
        0xF6,
        0x95,
        0xC2,
        0x17,
      ]);

      final kmac = Uint8List.fromList([
        0x49,
        0x54,
        0x2A,
        0xED,
        0xBD,
        0x0F,
        0xB3,
        0x2B,
        0x73,
        0x08,
        0x19,
        0xC0,
        0x03,
        0x0B,
        0xCB,
        0x31,
        0x27,
        0x18,
        0xBB,
        0xE8,
        0x61,
        0xCB,
        0xB5,
        0x4A,
        0xEF,
        0x24,
        0x9A,
        0xF9,
        0x8A,
        0x8F,
        0x4A,
        0xA9,
      ]);

      final ssc = AES_SSC();
      final smCipher = AES_SMCipher(kenc, kmac, size: KEY_LENGTH.s256);
      final sm = MrtdSM(smCipher, ssc);

      final plainData =
          Uint8List.fromList([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]);

      final cmd = CommandAPDU(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x0C,
        data: plainData,
        ne: 0,
      );

      final protectedCmd = sm.protect(cmd);
      final actualWire = protectedCmd.toBytes().hex().toUpperCase();

      print("Flutter wire: $actualWire");
      print("Length: ${protectedCmd.toBytes().length} bytes\n");

      expect(actualWire, equals(expectedWire),
          reason: "First command wire format must match");

      print("✅ First command wire format matches!\n");
    });

    test('READ BINARY wire format (SSC=7)', () {
      print("\n=== READ BINARY WIRE FORMAT (SSC=7) ===\n");

      // From JMRTD log:
      // TX PROT: 0CB000000D9701108E08FB04958219AD003000
      final expectedWire = '0CB000000D9701108E08FB04958219AD003000';

      print("Expected wire: $expectedWire");
      print("Length: ${expectedWire.length ~/ 2} bytes\n");

      final kenc = Uint8List.fromList([
        0x82,
        0x11,
        0xA5,
        0x8C,
        0xA9,
        0x42,
        0x40,
        0x57,
        0x90,
        0x4E,
        0x23,
        0x69,
        0xB0,
        0x77,
        0x16,
        0x08,
        0x91,
        0xBD,
        0xD3,
        0x36,
        0xD3,
        0x1D,
        0x19,
        0x04,
        0xF0,
        0x59,
        0xB6,
        0x81,
        0xF6,
        0x95,
        0xC2,
        0x17,
      ]);

      final kmac = Uint8List.fromList([
        0x49,
        0x54,
        0x2A,
        0xED,
        0xBD,
        0x0F,
        0xB3,
        0x2B,
        0x73,
        0x08,
        0x19,
        0xC0,
        0x03,
        0x0B,
        0xCB,
        0x31,
        0x27,
        0x18,
        0xBB,
        0xE8,
        0x61,
        0xCB,
        0xB5,
        0x4A,
        0xEF,
        0x24,
        0x9A,
        0xF9,
        0x8A,
        0x8F,
        0x4A,
        0xA9,
      ]);

      // SSC at 6, will increment to 7
      final ssc = AES_SSC();
      for (int i = 0; i < 6; i++) {
        ssc.increment();
      }

      final smCipher = AES_SMCipher(kenc, kmac, size: KEY_LENGTH.s256);
      final sm = MrtdSM(smCipher, ssc);

      // READ BINARY P1=00 P2=00 Le=16
      final cmd = CommandAPDU(
        cla: 0x00,
        ins: 0xB0,
        p1: 0x00,
        p2: 0x00,
        ne: 16,
      );

      final protectedCmd = sm.protect(cmd);
      final actualWire = protectedCmd.toBytes().hex().toUpperCase();

      print("Flutter wire: $actualWire");
      print("Length: ${protectedCmd.toBytes().length} bytes\n");

      expect(actualWire, equals(expectedWire),
          reason: "READ BINARY wire format must match");

      print("✅ READ BINARY wire format matches!\n");
    });
  });
}
