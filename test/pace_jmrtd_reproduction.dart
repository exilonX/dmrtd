// Example of how to use deterministic PACE keys for debugging
// This allows exact reproduction of JMRTD sessions

// Import from the main library (not from src/)
import 'package:dmrtd/dmrtd.dart';

void setupJmrtdReproduction() {
  // Keys extracted from JMRTD log (2025-10-24 17:03:39)
  // [STEP 2] PCD Mapping Private Key (d): 74593FB3F0C45D93C01DEA78B71B79625A90E1B961C11481662D14B3DCA6BFE1
  // [STEP 3] PCD Ephemeral Private Key (d~): 370EF82C76D9A88B4298D2975A93D9122D64BA2CC4247483FB2AB42711815341

  PaceTestConfig.setupFromJmrtdLog(
    step2PrivateKeyHex:
        '74593FB3F0C45D93C01DEA78B71B79625A90E1B961C11481662D14B3DCA6BFE1',
    step3PrivateKeyHex:
        '370EF82C76D9A88B4298D2975A93D9122D64BA2CC4247483FB2AB42711815341',
  );

  print("✅ Deterministic PACE keys configured!");
  print("⚠️  WARNING: This should ONLY be used for debugging/testing!");
  print("Next PACE session will use JMRTD's exact keys.");
}

void tearDown() {
  // Always reset after testing!
  PaceTestConfig.reset();
  print("✅ Deterministic keys cleared. Back to random generation.");
}

// HOW TO USE:
// 1. Get a fresh JMRTD log with verbose logging enabled
// 2. Find the private keys in the log (they should be printed)
// 3. Paste them into setupFromJmrtdLog() above
// 4. Call setupJmrtdReproduction() BEFORE reading the passport
// 5. Run your Flutter app - it will use JMRTD's exact keys
// 6. Compare the resulting session byte-by-byte with JMRTD
// 7. Call tearDown() when done testing
