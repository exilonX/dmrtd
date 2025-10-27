import 'package:test/test.dart';
import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/extensions.dart';

void main() {
  test('Verify KDF matches JMRTD latest session', () {
    // From JMRTD latest successful session:
    // Shared Secret (K): 52E927B2F09961B5C13D703D2DF012063DFD5B4E8AB6F5F552A192CEE2E41CC5
    final seed =
        '52E927B2F09961B5C13D703D2DF012063DFD5B4E8AB6F5F552A192CEE2E41CC5'
            .parseHex();

    print('=== JMRTD LATEST SESSION KDF CHECK ===');
    print('Shared Secret (K): ${seed.hex()}');

    // Derive keys
    final kEnc = DeriveKey.aes256(seed, paceMode: true);
    final kMac = DeriveKey.cmac256(seed, paceMode: true);

    print('\nDerived Keys:');
    print('K_enc: ${kEnc.hex()}');
    print('K_mac: ${kMac.hex()}');

    print('\nFrom JMRTD log:');
    print(
        'K_enc: 664d3530b5b216daaf81a1c02eef86f90694a7c3d8fe59cf20fe6795e9fd725d');
    print(
        'K_mac: 8747b8a8ee798973cdd9fb1f6754df31282080303bfcdb9e32178f5d485910e3');

    // Verify keys match
    expect(
        kEnc.hex(),
        equals(
            '664d3530b5b216daaf81a1c02eef86f90694a7c3d8fe59cf20fe6795e9fd725d'),
        reason: 'K_enc should match JMRTD');
    expect(
        kMac.hex(),
        equals(
            '8747b8a8ee798973cdd9fb1f6754df31282080303bfcdb9e32178f5d485910e3'),
        reason: 'K_mac should match JMRTD');

    print('\n✅ KDF matches JMRTD perfectly!');
  });
}
