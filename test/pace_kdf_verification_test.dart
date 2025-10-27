import 'package:test/test.dart';
import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/extensions.dart';
import 'dart:typed_data';

void main() {
  test('PACE KDF verification - compare with your Flutter log', () {
    // From your log:
    // Shared Secret (K): 23991579360d8943bd1fef13098d8255560b0213f1ff5c127749183435d10d3d
    final seed =
        '23991579360d8943bd1fef13098d8255560b0213f1ff5c127749183435d10d3d'
            .parseHex();

    print('=== PACE KDF VERIFICATION ===');
    print('Seed (shared secret): ${seed.hex()}');
    print('Seed length: ${seed.length} bytes');

    // Derive encryption key (counter = 3 for PACE)
    final kEnc = DeriveKey.aes256(seed, paceMode: true);
    print('\nK_enc (counter=3, PACE mode):');
    print('  Generated: ${kEnc.hex()}');
    print(
        '  From log:  f023654d8d32fbf63940e7c48232f7e5cc61432795c194ef550816a47f4165b1');

    // Derive MAC key (counter = 4 for PACE)
    final kMac = DeriveKey.cmac256(seed, paceMode: true);
    print('\nK_mac (counter=4, PACE mode):');
    print('  Generated: ${kMac.hex()}');
    print(
        '  From log:  6d49a22df3b47f97406c9d01fb5933ebad387724d54b7db5f340576a58b1bbd2');

    // Verify they match
    expect(
        kEnc.hex(),
        equals(
            'f023654d8d32fbf63940e7c48232f7e5cc61432795c194ef550816a47f4165b1'),
        reason: 'K_enc must match Flutter log');
    expect(
        kMac.hex(),
        equals(
            '6d49a22df3b47f97406c9d01fb5933ebad387724d54b7db5f340576a58b1bbd2'),
        reason: 'K_mac must match Flutter log');

    print('\n✅ KDF is working correctly - keys match log!');
  });

  test('Verify KDF counter logic', () {
    final seed =
        '23991579360d8943bd1fef13098d8255560b0213f1ff5c127749183435d10d3d'
            .parseHex();

    print('\n=== COUNTER VERIFICATION ===');

    // Test different counter values manually
    print('Testing if paceMode flag correctly sets counters...');

    // PACE mode (should use counter 3 for ENC, 4 for MAC)
    final kEncPACE = DeriveKey.aes256(seed, paceMode: true);
    final kMacPACE = DeriveKey.cmac256(seed, paceMode: true);

    // BAC mode (should use counter 1 for ENC, 2 for MAC)
    final kEncBAC = DeriveKey.aes256(seed, paceMode: false);
    final kMacBAC = DeriveKey.cmac256(seed, paceMode: false);

    print('PACE K_enc (c=3): ${kEncPACE.hex()}');
    print('BAC  K_enc (c=1): ${kEncBAC.hex()}');
    print('');
    print('PACE K_mac (c=4): ${kMacPACE.hex()}');
    print('BAC  K_mac (c=2): ${kMacBAC.hex()}');

    // They should be different
    expect(kEncPACE.hex(), isNot(equals(kEncBAC.hex())),
        reason:
            'PACE and BAC encryption keys should differ (different counters)');
    expect(kMacPACE.hex(), isNot(equals(kMacBAC.hex())),
        reason: 'PACE and BAC MAC keys should differ (different counters)');

    print('\n✅ Counter logic is correct - PACE ≠ BAC keys');
  });
}
