import 'package:test/test.dart';
import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:dmrtd/extensions.dart';

void main() {
  test('Verify CMAC Auth Token calculation matches JMRTD', () {
    print('\n=== AUTH TOKEN VERIFICATION TEST ===');

    // From JMRTD log - Step 4 PCD authentication
    final kMac =
        '8747B8A8EE798973CDD9FB1F6754DF31282080303BFCDB9E32178F5D485910E3'
            .parseHex();
    final tBlock =
        '7F494F060A04007F00070202040204864104A72F9DB4D6E316E959FB315F8D1E4A5DF6A58752AE1A7FDBEEB1D652195B4B4033236E4A44E2296A2254A7204282ED8EB305A7DC192689031A7B07BF04C31E7F'
            .parseHex();
    final expectedAuthToken = '6B4B884FFF7151DC'.parseHex();

    print('K_mac: ${kMac.hex()}');
    print('T-Block (${tBlock.length} bytes): ${tBlock.hex()}');
    print('Expected Auth Token: ${expectedAuthToken.hex()}');

    // Calculate CMAC using AES-256
    final aesCipher = AESCipher(size: KEY_LENGTH.s256);
    final fullCMAC = aesCipher.calculateCMAC(key: kMac, data: tBlock);

    print('\nFull CMAC (${fullCMAC.length} bytes): ${fullCMAC.hex()}');

    // Truncate to first 8 bytes
    final calculatedAuthToken = fullCMAC.sublist(0, 8);

    print(
        'Calculated Auth Token (first 8 bytes): ${calculatedAuthToken.hex()}');

    // Compare
    print('\nComparison:');
    print('Expected:   ${expectedAuthToken.hex()}');
    print('Calculated: ${calculatedAuthToken.hex()}');
    print('Match: ${expectedAuthToken.hex() == calculatedAuthToken.hex()}');

    expect(
      calculatedAuthToken.hex(),
      equals(expectedAuthToken.hex()),
      reason: 'Auth token should match JMRTD exactly',
    );

    print('\n✅ Auth token calculation is correct!');
  });
}
