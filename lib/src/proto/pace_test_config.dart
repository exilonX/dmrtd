// Test configuration for deterministic PACE sessions
// This allows reproducing exact JMRTD sessions for debugging
// DO NOT USE IN PRODUCTION!

import 'dart:typed_data';

class PaceTestConfig {
  // When true, uses fixed ephemeral keys from JMRTD session
  static bool useDeterministicKeys = false;

  // Fixed ephemeral private key for Step 2 (mapping)
  // From JMRTD: [STEP 2] PCD Mapping Private Key
  static Uint8List? step2PrivateKey;

  // Fixed ephemeral private key for Step 3 (key agreement)
  // From JMRTD: [STEP 3] PCD Ephemeral Private Key (d~)
  static Uint8List? step3PrivateKey;

  /// Set up keys from JMRTD log for exact reproduction
  /// Example from JMRTD log:
  /// [STEP 2] PCD Mapping Private Key: <hex>
  /// [STEP 3] PCD Ephemeral Private Key (d~): <hex>
  static void setupFromJmrtdLog({
    required String step2PrivateKeyHex,
    required String step3PrivateKeyHex,
  }) {
    useDeterministicKeys = true;
    step2PrivateKey = _hexToBytes(step2PrivateKeyHex);
    step3PrivateKey = _hexToBytes(step3PrivateKeyHex);
  }

  /// Clear test configuration and return to random key generation
  static void reset() {
    useDeterministicKeys = false;
    step2PrivateKey = null;
    step3PrivateKey = null;
  }

  static Uint8List _hexToBytes(String hex) {
    // Remove any spaces or colons
    hex = hex.replaceAll(RegExp(r'[\s:]'), '');

    final List<int> bytes = [];
    for (int i = 0; i < hex.length; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(bytes);
  }
}
