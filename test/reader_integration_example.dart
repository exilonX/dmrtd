// Modified version of RomanianIdWithCaReader with deterministic PACE support
// Add this to your reader file or use as reference

// 1. Import - PaceTestConfig is now exported from main library:
import 'package:dmrtd/dmrtd.dart';

// 2. Modify the read() method:

@override
Future<MrtdData> read({
  required Function(String) onProgress,
  Map<String, dynamic>? params,
}) async {
  if (params == null) throw ArgumentError('params required');
  final can = (params['can'] as String?)?.trim();
  final serverNonce = params['serverNonce'] as Uint8List?;

  if (can == null || can.isEmpty) {
    throw ArgumentError("params['can'] is required");
  }
  if (serverNonce == null || serverNonce.length < 8) {
    throw ArgumentError("params['serverNonce'] (>=8 bytes) is required");
  }

  // NEW: Enable deterministic PACE keys for JMRTD comparison
  final useDeterministicKeys = params['useDeterministicKeys'] as bool? ?? false;
  if (useDeterministicKeys) {
    PaceTestConfig.setupFromJmrtdLog(
      step2PrivateKeyHex: '74593FB3F0C45D93C01DEA78B71B79625A90E1B961C11481662D14B3DCA6BFE1',
      step3PrivateKeyHex: '0CDCA550ED18AB9C52EEDFCAE06B7DB34A6A44D7013CB5F4683468BE1AC62165',
    );
    _log.warning('═══════════════════════════════════════════');
    _log.warning('⚠️  DETERMINISTIC PACE KEYS ENABLED');
    _log.warning('⚠️  TEST MODE ONLY - DO NOT USE IN PRODUCTION');
    _log.warning('═══════════════════════════════════════════');
  }

  Passport? passport;
  final mrtdData = MrtdData();

  try {
    onProgress('Connect…');
    await connectWithRetries(onProgress: onProgress);

    // Always start fresh, unprotected
    passport = Passport(nfc);

    // 3) Read EF.CardAccess (unprotected) under ICAO
    onProgress('Read EF.CardAccess…');
    mrtdData.cardAccess = await passport.readEfCardAccess();
    _log.info('EF.CardAccess read OK (ICAO)');

    // 4) PACE inside ICAO (this creates SM context for ICAO)
    onProgress('PACE (ICAO)…');
    await passport.startSessionPACE(CanKey(can), mrtdData.cardAccess!);
    _log.info('PACE(ICAO) OK');

    // WORKAROUND: dmrtd sets SSC=0 after PACE instead of deriving from ephemeral keys
    // This causes 0x6988 on Romanian eIDs. Read files UNPROTECTED instead.
    onProgress('Read DG14 & SOD (unprotected)…');

    // Select + Read DG14 (010E)
    await passport.transceiveRawUnprotected(
      CommandAPDU.fromHex('00A4020C02010E'),
    );
    final dg14Resp = await passport.transceiveRawUnprotected(
      CommandAPDU.fromHex('00B0000000'),
    );
    if (dg14Resp.data == null) {
      throw PassportError('DG14 read failed');
    }
    final dg14 = EfDG14.fromBytes(dg14Resp.data!);

    // Select + Read SOD (011D)
    await passport.transceiveRawUnprotected(
      CommandAPDU.fromHex('00A4020C02011D'),
    );
    final sodResp = await passport.transceiveRawUnprotected(
      CommandAPDU.fromHex('00B0000000'),
    );
    if (sodResp.data == null) {
      throw PassportError('SOD read failed');
    }
    final sod = EfSOD.fromBytes(sodResp.data!);

    // 6) Chip Authentication: GA with terminal ephemeral; then CMAC(nonce)
    onProgress('Chip Authentication…');
    final proof = await _chipAuthAndMacNonce(
      passport: passport,
      dg14: dg14.toBytes(),
      sod: sod.toBytes(),
      serverNonce: serverNonce,
    );
    lastProof = proof;

    onProgress('✅ Proof generated');
    return MrtdData();
  } finally {
    // NEW: Clean up deterministic keys if used
    if (useDeterministicKeys) {
      PaceTestConfig.reset();
      _log.info('✅ Deterministic keys cleared');
    }
    await disconnect();
  }
}

// 3. Usage example:

// Normal mode (random keys):
final mrtdData = await reader.read(
  onProgress: (msg) => print(msg),
  params: {
    'can': 'YOUR_CAN',
    'serverNonce': serverNonce,
  },
);

// Test mode (deterministic keys matching JMRTD):
final mrtdData = await reader.read(
  onProgress: (msg) => print(msg),
  params: {
    'can': 'YOUR_CAN',
    'serverNonce': serverNonce,
    'useDeterministicKeys': true,  // ← Enable JMRTD comparison mode
  },
);
