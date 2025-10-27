import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dmrtd/src/proto/ecdh_pace.dart';
import 'package:dmrtd/src/proto/domain_parameter.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/utils.dart';
import 'package:pointycastle/ecc/api.dart';

void main() {
  test('Verify shared secret calculation matches JMRTD approach', () {
    print('\n=== SHARED SECRET CALCULATION TEST ===');

    // From your Flutter log - the ephemeral key agreement inputs
    final privateScalar =
        '32a1fa5b8223898056011d91a663df71d7abf8cf29a0f1ffbf9f2e99280a20b9'
            .parseHex();
    final publicX =
        '28cf4a28c3a8441b6d71f742984a399ce45b3e24f0674e6384e9f810960d55ee'
            .parseHex();
    final publicY =
        '99292cd97df8c87b8d2590d3c85d154a4c36f1368c526f3a04f97636431e2d47'
            .parseHex();

    // Your Flutter calculated this shared secret
    final expectedSharedSecret =
        '3d7c9a84890deadc3570e647ff345bc1e70a64e374166166eeb6151e84aa9a9b'
            .parseHex();

    print('Private key (d): ${privateScalar.hex()}');
    print('Public key X: ${publicX.hex()}');
    print('Public key Y: ${publicY.hex()}');
    print('Expected shared secret: ${expectedSharedSecret.hex()}');

    // Get BrainpoolP256r1 parameters
    final domainParam = DomainParameterSelectorECDH.getDomainParameter(id: 13);
    final curve = domainParam.domainParameters.curve;

    // Convert to BigInt
    final d = Utils.uint8ListToBigInt(privateScalar);
    final Qx = Utils.uint8ListToBigInt(publicX);
    final Qy = Utils.uint8ListToBigInt(publicY);

    // Create the public key point
    final Q = curve.createPoint(Qx, Qy);

    print('\nPoint created successfully');

    // Calculate P = d * Q
    final P = (Q * d)!;

    print('\nCalculated shared point:');
    print('P.x: ${P.x!.toBigInteger()!.toRadixString(16)}');
    print('P.y: ${P.y!.toBigInteger()!.toRadixString(16)}');

    // Get x-coordinate as shared secret
    final sharedSecretX = P.x!.toBigInteger()!;
    final sharedSecretBytes = Utils.bigIntToUint8List(bigInt: sharedSecretX);

    // Pad to 32 bytes if needed
    final paddedSharedSecret = Uint8List(32);
    paddedSharedSecret.setRange(
      32 - sharedSecretBytes.length,
      32,
      sharedSecretBytes,
    );

    print('\nCalculated shared secret: ${paddedSharedSecret.hex()}');
    print('Expected shared secret:   ${expectedSharedSecret.hex()}');
    print('Match: ${paddedSharedSecret.hex() == expectedSharedSecret.hex()}');

    expect(
      paddedSharedSecret.hex(),
      equals(expectedSharedSecret.hex()),
      reason: 'Shared secret should match',
    );

    print('\n✅ Shared secret calculation is correct!');
  });
}
