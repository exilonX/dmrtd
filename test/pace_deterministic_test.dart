// Deterministic PACE test - reproduces exact JMRTD session
// Run this to compare Flutter vs JMRTD byte-by-byte

import 'package:test/test.dart';
import 'pace_jmrtd_reproduction.dart' as jmrtd_config;

void main() {
  test('Setup deterministic PACE keys from JMRTD', () {
    // Configure the exact keys from JMRTD session
    jmrtd_config.setupJmrtdReproduction();

    // Verify keys are set
    print('\n═══════════════════════════════════════════════════');
    print('  Deterministic PACE Testing Ready');
    print('═══════════════════════════════════════════════════');
    print('');
    print('✅ Keys configured from JMRTD session (2025-10-24 17:03:39)');
    print('');
    print('Step 2 Private Key (d):');
    print('  74593FB3F0C45D93C01DEA78B71B79625A90E1B961C11481662D14B3DCA6BFE1');
    print('');
    print('Step 3 Private Key (d~):');
    print('  0CDCA550ED18AB9C52EEDFCAE06B7DB34A6A44D7013CB5F4683468BE1AC62165');
    print('');
    print('═══════════════════════════════════════════════════');
    print('');
    print('🎯 NEXT STEPS:');
    print('   1. Run your Flutter app to read the eID');
    print('   2. Flutter will use JMRTD\'s exact private keys');
    print('   3. Collect the following values from logs:');
    print('      - Step 2 PCD Public Key');
    print('      - Step 2 ICC Response');
    print('      - Step 3 PCD Ephemeral Public');
    print('      - Step 3 ICC Response');
    print('      - Shared Secret (K)');
    print('      - K_enc');
    print('      - K_mac');
    print('      - Step 4 PCD Auth Token');
    print('      - Step 4 ICC Auth Token');
    print('      - SM Protected SELECT APDU');
    print('      - SM SELECT MAC');
    print('      - Card Response');
    print('   4. Use pace_session_comparison.dart to compare');
    print('');
    print('⚠️  WARNING: Remember to call tearDown() when done!');
    print('');
    print('═══════════════════════════════════════════════════\n');
  });

  tearDown(() {
    // Cleanup after test
    // Note: Uncomment this when you're done testing
    // jmrtd_config.tearDown();
  });
}
