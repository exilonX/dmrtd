// Integration test to verify the ENTIRE MrtdSM.protect() flow matches JMRTD
// This validates the complete SM wrapper, not just CMAC calculation

import 'package:test/test.dart';
import 'package:dmrtd/extensions.dart';
import 'dart:typed_data';
import 'package:dmrtd/src/proto/aes_smcipher.dart';
import 'package:dmrtd/src/proto/mrtd_sm.dart';
import 'package:dmrtd/src/proto/ssc.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';

void main() {
  group('SM protect() Integration Test - Match JMRTD Exactly', () {
    test('First SM-protected SELECT command (SSC=1)', () {
      print("\n=== SM PROTECT() INTEGRATION TEST ===");
      print("Validating ENTIRE protect() flow against JMRTD\n");

      // From JMRTD log (after PACE completed):
      // K_enc: 8211A58CA9424057904E2369B077160891BDD336D31D1904F059B681F695C217
      // K_mac: 49542AEDBD0FB32B730819C0030BCB312718BBE861CBB54AEF249AF98A8F4AA9
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

      print("K_enc: ${kenc.hex()}");
      print("K_mac: ${kmac.hex()}");

      // SSC starts at 0, will be incremented to 1 by protect()
      final ssc = AES_SSC();
      print("Initial SSC: ${ssc.toBytes().hex()}");

      // Create SM cipher and wrapper
      final smCipher = AES_SMCipher(kenc, kmac, size: KEY_LENGTH.s256);
      final sm = MrtdSM(smCipher, ssc);

      print("\n--- Building Original APDU ---");
      // Original command from JMRTD:
      // Plain Header: 00A4040C
      // Plain Data: A0000002471001
      // Plain Le: 0
      final plainData =
          Uint8List.fromList([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]);

      print("Plain Header: 00A4040C");
      print("Plain Data: ${plainData.hex()}");
      print("Plain Le: 0");

      final cmd = CommandAPDU(
        cla: 0x00,
        ins: 0xA4, // SELECT
        p1: 0x04,
        p2: 0x0C,
        data: plainData,
        ne: 0, // Le=0 means "return all available"
      );

      print("\n--- Calling protect() ---");
      final protectedCmd = sm.protect(cmd);

      print("\n=== RESULTS ===");
      print("SSC after protect: ${sm.ssc.toBytes().hex()}");
      print("Protected APDU bytes: ${protectedCmd.toBytes().hex()}");

      // Parse the protected command
      print("\nProtected APDU breakdown:");
      print("  CLA: ${protectedCmd.cla.toRadixString(16).padLeft(2, '0')}");
      print("  INS: ${protectedCmd.ins.toRadixString(16).padLeft(2, '0')}");
      print("  P1:  ${protectedCmd.p1.toRadixString(16).padLeft(2, '0')}");
      print("  P2:  ${protectedCmd.p2.toRadixString(16).padLeft(2, '0')}");
      print("  Lc:  ${protectedCmd.data?.length ?? 0}");
      print("  Data: ${protectedCmd.data?.hex() ?? 'null'}");
      print("  Le:  ${protectedCmd.ne}");

      // JMRTD expected values:
      // SSC: 00000000000000000000000000000001
      final expectedSSC = Uint8List.fromList([
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
      ]);

      // DO'87' (Encrypted Data): 87110168DCB0BBCF666F019EBA74B3C093FB99
      final expectedDO87 = Uint8List.fromList([
        0x87,
        0x11,
        0x01,
        0x68,
        0xDC,
        0xB0,
        0xBB,
        0xCF,
        0x66,
        0x6F,
        0x01,
        0x9E,
        0xBA,
        0x74,
        0xB3,
        0xC0,
        0x93,
        0xFB,
        0x99,
      ]);

      // DO'8E' (MAC): 8E0850A12D9362F63DC1
      final expectedDO8E = Uint8List.fromList([
        0x8E,
        0x08,
        0x50,
        0xA1,
        0x2D,
        0x93,
        0x62,
        0xF6,
        0x3D,
        0xC1,
      ]);

      // Final Protected APDU Data (Lc payload):
      // 87110168DCB0BBCF666F019EBA74B3C093FB998E0850A12D9362F63DC1
      final expectedProtectedData = Uint8List.fromList([
        0x87,
        0x11,
        0x01,
        0x68,
        0xDC,
        0xB0,
        0xBB,
        0xCF,
        0x66,
        0x6F,
        0x01,
        0x9E,
        0xBA,
        0x74,
        0xB3,
        0xC0,
        0x93,
        0xFB,
        0x99,
        0x8E,
        0x08,
        0x50,
        0xA1,
        0x2D,
        0x93,
        0x62,
        0xF6,
        0x3D,
        0xC1,
      ]);

      print("\n=== VALIDATION ===");

      // 1. Check SSC incremented correctly
      expect(sm.ssc.toBytes().hex().toUpperCase(),
          equals(expectedSSC.hex().toUpperCase()),
          reason: "SSC should be incremented to 1");
      print("✅ SSC correct");

      // 2. Check masked header (CLA should be OR'd with 0x0C)
      expect(protectedCmd.cla, equals(0x0C),
          reason: "CLA should be masked with SM bit");
      expect(protectedCmd.ins, equals(0xA4));
      expect(protectedCmd.p1, equals(0x04));
      expect(protectedCmd.p2, equals(0x0C));
      print("✅ Masked header correct");

      // 3. Check the protected data matches JMRTD exactly
      expect(protectedCmd.data?.hex().toUpperCase(),
          equals(expectedProtectedData.hex().toUpperCase()),
          reason: "Protected data (DO'87' + DO'8E') should match JMRTD");
      print("✅ Protected data matches JMRTD EXACTLY");

      // 4. Verify DO'87' is present and correct
      final actualDO87 = protectedCmd.data!.sublist(0, expectedDO87.length);
      expect(actualDO87.hex().toUpperCase(),
          equals(expectedDO87.hex().toUpperCase()),
          reason: "DO'87' encrypted data should match JMRTD");
      print("✅ DO'87' (encrypted data) matches JMRTD");

      // 5. Verify DO'8E' (MAC) is correct
      final actualDO8E = protectedCmd.data!.sublist(expectedDO87.length);
      expect(actualDO8E.hex().toUpperCase(),
          equals(expectedDO8E.hex().toUpperCase()),
          reason: "DO'8E' (MAC) should match JMRTD");
      print("✅ DO'8E' (MAC) matches JMRTD");

      // 6. Check Le encoding (should be 256 which encodes as trailing 0x00)
      expect(protectedCmd.ne, equals(256),
          reason: "Le should be 256 (encodes as 0x00 on wire)");
      print("✅ Le encoding correct");

      print("\n🎉 COMPLETE INTEGRATION TEST PASSED!");
      print("The entire protect() flow matches JMRTD byte-for-byte!");
      print("=====================================\n");
    });

    test('Second SM-protected SELECT command (SSC=3)', () {
      // Second command from JMRTD log (same session, SSC=3)
      print("\n=== SECOND SM COMMAND (SSC=3) ===");

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

      // SSC needs to be at 2, will increment to 3
      // (In reality this follows first command + unwrap, so SSC would be at 2)
      final ssc = AES_SSC();
      ssc.increment(); // 0 -> 1
      ssc.increment(); // 1 -> 2

      print("Initial SSC: ${ssc.toBytes().hex()}");

      final smCipher = AES_SMCipher(kenc, kmac, size: KEY_LENGTH.s256);
      final sm = MrtdSM(smCipher, ssc);

      // JMRTD second command:
      // Plain Header: 00A4040C
      // Plain Data: A0000002471001
      // Plain Le: 0
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

      print("SSC after protect: ${sm.ssc.toBytes().hex()}");

      // JMRTD expected for SSC=3:
      // DO'87': 871101074B34C82347CFB2D6F2C382DC149FCD
      // DO'8E': 8E089AB538BA84F6072A
      // Full: 871101074B34C82347CFB2D6F2C382DC149FCD8E089AB538BA84F6072A
      final expectedProtectedData = Uint8List.fromList([
        0x87,
        0x11,
        0x01,
        0x07,
        0x4B,
        0x34,
        0xC8,
        0x23,
        0x47,
        0xCF,
        0xB2,
        0xD6,
        0xF2,
        0xC3,
        0x82,
        0xDC,
        0x14,
        0x9F,
        0xCD,
        0x8E,
        0x08,
        0x9A,
        0xB5,
        0x38,
        0xBA,
        0x84,
        0xF6,
        0x07,
        0x2A,
      ]);

      final expectedSSC = Uint8List.fromList([
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
      ]);

      expect(sm.ssc.toBytes().hex().toUpperCase(),
          equals(expectedSSC.hex().toUpperCase()));
      print("✅ SSC=3 correct");

      expect(protectedCmd.data?.hex().toUpperCase(),
          equals(expectedProtectedData.hex().toUpperCase()),
          reason: "Second command protected data should match JMRTD");
      print("✅ Second command matches JMRTD");

      print("🎉 Second command test PASSED!\n");
    });

    test('READ BINARY command with DO97 (SSC=7)', () {
      // Third type of command - READ BINARY with Le
      print("\n=== READ BINARY COMMAND (SSC=7) ===");

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

      // JMRTD command:
      // Plain Header: 00B00000
      // Plain Le: 16
      // (no data)
      final cmd = CommandAPDU(
        cla: 0x00,
        ins: 0xB0,
        p1: 0x00,
        p2: 0x00,
        ne: 16,
      );

      final protectedCmd = sm.protect(cmd);

      // JMRTD expected:
      // DO'97': 970110
      // DO'8E': 8E08FB04958219AD0030
      // Full: 9701108E08FB04958219AD0030
      final expectedProtectedData = Uint8List.fromList([
        0x97,
        0x01,
        0x10,
        0x8E,
        0x08,
        0xFB,
        0x04,
        0x95,
        0x82,
        0x19,
        0xAD,
        0x00,
        0x30,
      ]);

      expect(protectedCmd.data?.hex().toUpperCase(),
          equals(expectedProtectedData.hex().toUpperCase()),
          reason: "READ BINARY with DO'97' should match JMRTD");
      print("✅ READ BINARY command matches JMRTD");

      print("🎉 READ BINARY test PASSED!\n");
    });
  });
}
