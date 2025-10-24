// Comparison helper for JMRTD vs Flutter PACE sessions
// Run this after both sessions complete

// ignore_for_file: avoid_print

class PaceSessionComparison {
  final String label;
  final String jmrtdValue;
  final String flutterValue;

  PaceSessionComparison({
    required this.label,
    required this.jmrtdValue,
    required this.flutterValue,
  });

  bool get matches => jmrtdValue.toLowerCase() == flutterValue.toLowerCase();

  void printComparison() {
    final status = matches ? '✅ MATCH' : '❌ DIFFER';
    print('\n$status - $label:');
    print('  JMRTD:   $jmrtdValue');
    print('  Flutter: $flutterValue');
    if (!matches) {
      print('  ⚠️  DIVERGENCE POINT IDENTIFIED!');
    }
  }
}

void compareSessions({
  // Step 2
  required String jmrtdStep2PubKey,
  required String flutterStep2PubKey,
  required String jmrtdStep2IccResponse,
  required String flutterStep2IccResponse,

  // Step 3
  required String jmrtdStep3EphemeralPubKey,
  required String flutterStep3EphemeralPubKey,
  required String jmrtdStep3IccResponse,
  required String flutterStep3IccResponse,

  // Key Derivation
  required String jmrtdSharedSecret,
  required String flutterSharedSecret,
  required String jmrtdKenc,
  required String flutterKenc,
  required String jmrtdKmac,
  required String flutterKmac,

  // Step 4
  required String jmrtdPcdAuthToken,
  required String flutterPcdAuthToken,
  required String jmrtdIccAuthToken,
  required String flutterIccAuthToken,

  // SM Protected SELECT
  required String jmrtdSelectApdu,
  required String flutterSelectApdu,
  required String jmrtdSelectMac,
  required String flutterSelectMac,
  required String jmrtdSelectResponse,
  required String flutterSelectResponse,
}) {
  print('═══════════════════════════════════════════════════');
  print('       JMRTD vs Flutter PACE Session Comparison');
  print('═══════════════════════════════════════════════════');

  final comparisons = [
    // Step 2
    PaceSessionComparison(
      label: 'Step 2: PCD Mapping Public Key',
      jmrtdValue: jmrtdStep2PubKey,
      flutterValue: flutterStep2PubKey,
    ),
    PaceSessionComparison(
      label: 'Step 2: ICC Response',
      jmrtdValue: jmrtdStep2IccResponse,
      flutterValue: flutterStep2IccResponse,
    ),

    // Step 3
    PaceSessionComparison(
      label: 'Step 3: PCD Ephemeral Public Key',
      jmrtdValue: jmrtdStep3EphemeralPubKey,
      flutterValue: flutterStep3EphemeralPubKey,
    ),
    PaceSessionComparison(
      label: 'Step 3: ICC Response',
      jmrtdValue: jmrtdStep3IccResponse,
      flutterValue: flutterStep3IccResponse,
    ),

    // Key Derivation
    PaceSessionComparison(
      label: 'Shared Secret (K)',
      jmrtdValue: jmrtdSharedSecret,
      flutterValue: flutterSharedSecret,
    ),
    PaceSessionComparison(
      label: 'Encryption Key (K_enc)',
      jmrtdValue: jmrtdKenc,
      flutterValue: flutterKenc,
    ),
    PaceSessionComparison(
      label: 'MAC Key (K_mac)',
      jmrtdValue: jmrtdKmac,
      flutterValue: flutterKmac,
    ),

    // Step 4
    PaceSessionComparison(
      label: 'Step 4: PCD Auth Token',
      jmrtdValue: jmrtdPcdAuthToken,
      flutterValue: flutterPcdAuthToken,
    ),
    PaceSessionComparison(
      label: 'Step 4: ICC Auth Token',
      jmrtdValue: jmrtdIccAuthToken,
      flutterValue: flutterIccAuthToken,
    ),

    // SM
    PaceSessionComparison(
      label: 'SM Protected SELECT APDU',
      jmrtdValue: jmrtdSelectApdu,
      flutterValue: flutterSelectApdu,
    ),
    PaceSessionComparison(
      label: 'SM SELECT MAC',
      jmrtdValue: jmrtdSelectMac,
      flutterValue: flutterSelectMac,
    ),
    PaceSessionComparison(
      label: 'Card Response to SELECT',
      jmrtdValue: jmrtdSelectResponse,
      flutterValue: flutterSelectResponse,
    ),
  ];

  // Print all comparisons
  for (final comp in comparisons) {
    comp.printComparison();
  }

  // Summary
  final matchCount = comparisons.where((c) => c.matches).length;
  final totalCount = comparisons.length;

  print('\n═══════════════════════════════════════════════════');
  print('Summary: $matchCount/$totalCount items match');

  if (matchCount == totalCount) {
    print('✅ SESSIONS ARE IDENTICAL!');
    print('   The issue must be in how the card interprets the data.');
  } else {
    print('❌ DIVERGENCE DETECTED!');
    final firstDiverge = comparisons.firstWhere((c) => !c.matches);
    print('   First divergence at: ${firstDiverge.label}');
    print('   This is where to focus debugging efforts!');
  }
  print('═══════════════════════════════════════════════════\n');
}

// Example usage:
void main() {
  // Fill in values from both logs
  compareSessions(
    // TODO: Fill these from JMRTD and Flutter logs
    jmrtdStep2PubKey: 'TODO',
    flutterStep2PubKey: 'TODO',
    jmrtdStep2IccResponse: 'TODO',
    flutterStep2IccResponse: 'TODO',
    jmrtdStep3EphemeralPubKey: 'TODO',
    flutterStep3EphemeralPubKey: 'TODO',
    jmrtdStep3IccResponse: 'TODO',
    flutterStep3IccResponse: 'TODO',
    jmrtdSharedSecret: 'TODO',
    flutterSharedSecret: 'TODO',
    jmrtdKenc: 'TODO',
    flutterKenc: 'TODO',
    jmrtdKmac: 'TODO',
    flutterKmac: 'TODO',
    jmrtdPcdAuthToken: 'TODO',
    flutterPcdAuthToken: 'TODO',
    jmrtdIccAuthToken: 'TODO',
    flutterIccAuthToken: 'TODO',
    jmrtdSelectApdu: 'TODO',
    flutterSelectApdu: 'TODO',
    jmrtdSelectMac: 'TODO',
    flutterSelectMac: 'TODO',
    jmrtdSelectResponse: 'TODO',
    flutterSelectResponse: 'TODO',
  );
}
