// Test to verify PaceTestConfig is properly exported
import 'package:test/test.dart';
import 'package:dmrtd/dmrtd.dart'; // Should import PaceTestConfig

void main() {
  test('PaceTestConfig is exported and accessible', () {
    // Verify we can access PaceTestConfig
    expect(PaceTestConfig.useDeterministicKeys, isFalse);

    // Test setup
    PaceTestConfig.setupFromJmrtdLog(
      step2PrivateKeyHex:
          '74593FB3F0C45D93C01DEA78B71B79625A90E1B961C11481662D14B3DCA6BFE1',
      step3PrivateKeyHex:
          '0CDCA550ED18AB9C52EEDFCAE06B7DB34A6A44D7013CB5F4683468BE1AC62165',
    );

    expect(PaceTestConfig.useDeterministicKeys, isTrue);
    expect(PaceTestConfig.step2PrivateKey, isNotNull);
    expect(PaceTestConfig.step3PrivateKey, isNotNull);
    expect(PaceTestConfig.step2PrivateKey!.length,
        equals(32)); // 32 bytes for P-256
    expect(PaceTestConfig.step3PrivateKey!.length, equals(32));

    // Test reset
    PaceTestConfig.reset();
    expect(PaceTestConfig.useDeterministicKeys, isFalse);
    expect(PaceTestConfig.step2PrivateKey, isNull);
    expect(PaceTestConfig.step3PrivateKey, isNull);

    print('✅ PaceTestConfig is properly exported and functional!');
  });
}
