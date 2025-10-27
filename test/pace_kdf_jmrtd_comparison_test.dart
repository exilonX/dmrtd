import 'package:test/test.dart';
import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/extensions.dart';

void main() {
  test('PACE KDF - compare Flutter vs JMRTD with SAME shared secret', () {
    // From JMRTD log (latest session):
    // Shared Secret (K): 74EE01765578EE12C41AAAC3024108A3BD175C842ABFA22BC31E2F557C752EC3
    // K_enc: 8211A58CA9424057904E2369B077160891BDD336D31D1904F059B681F695C217
    // K_mac: 49542AEDBD0FB32B730819C0030BCB312718BBE861CBB54AEF249AF98A8F4AA9

    final seed =
        '74EE01765578EE12C41AAAC3024108A3BD175C842ABFA22BC31E2F557C752EC3'
            .parseHex();

    print('=== JMRTD KDF COMPARISON ===');
    print('Shared Secret (K): ${seed.hex()}');
    print('Seed length: ${seed.length} bytes');

    // Derive encryption key
    final kEnc = DeriveKey.aes256(seed, paceMode: true);
    print('\nK_enc (counter=3):');
    print('  Flutter:   ${kEnc.hex()}');
    print(
        '  JMRTD:     8211a58ca9424057904e2369b077160891bdd336d31d1904f059b681f695c217');

    // Derive MAC key
    final kMac = DeriveKey.cmac256(seed, paceMode: true);
    print('\nK_mac (counter=2):');
    print('  Flutter:   ${kMac.hex()}');
    print(
        '  JMRTD:     49542aedbd0fb32b730819c0030bcb312718bbe861cbb54aef249af98a8f4aa9');

    // Verify they match JMRTD exactly
    expect(
        kEnc.hex(),
        equals(
            '8211a58ca9424057904e2369b077160891bdd336d31d1904f059b681f695c217'),
        reason: 'K_enc must match JMRTD');
    expect(
        kMac.hex(),
        equals(
            '49542aedbd0fb32b730819c0030bcb312718bbe861cbb54aef249af98a8f4aa9'),
        reason: 'K_mac must match JMRTD');

    print('\n✅ SUCCESS! Flutter KDF matches JMRTD exactly!');
  });

  test('Verify counter values used', () {
    final seed =
        '74EE01765578EE12C41AAAC3024108A3BD175C842ABFA22BC31E2F557C752EC3'
            .parseHex();

    print('\n=== COUNTER VERIFICATION ===');

    // Test with different counter values
    final kEncCounter3 = DeriveKey.aes256(seed, paceMode: true);
    final kEncCounter1 = DeriveKey.aes256(seed, paceMode: false);

    final kMacCounter2 =
        DeriveKey.cmac256(seed, paceMode: true); // Should use c=2
    final kMacCounter4 =
        DeriveKey.cmac256(seed, paceMode: false); // Should use c=2

    print('K_enc with paceMode=true:  ${kEncCounter3.hex()}');
    print('K_enc with paceMode=false: ${kEncCounter1.hex()}');
    print('');
    print('K_mac with paceMode=true:  ${kMacCounter2.hex()}');
    print('K_mac with paceMode=false: ${kMacCounter4.hex()}');

    // For CMAC, both should be the same (always counter=2)
    expect(kMacCounter2.hex(), equals(kMacCounter4.hex()),
        reason: 'CMAC should always use counter=2 regardless of paceMode');

    // For AES, they should differ (counter=3 vs counter=1)
    expect(kEncCounter3.hex(), isNot(equals(kEncCounter1.hex())),
        reason: 'AES encryption key should differ based on paceMode');

    print('\n✅ Counter behavior verified');
  });
}
