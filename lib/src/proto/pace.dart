//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/crypto/cmac.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';
import 'package:dmrtd/src/proto/iso7816/iso7816.dart';
import 'package:dmrtd/src/proto/public_key_pace.dart';
import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/crypto/iso9797.dart';
import 'package:dmrtd/src/proto/ssc.dart';
import "package:dmrtd/src/proto/des_smcipher.dart";
import 'package:dmrtd/src/proto/mrtd_sm.dart';
import 'package:dmrtd/src/crypto/des.dart';
import 'package:pointycastle/asn1/primitives/asn1_object_identifier.dart';

import 'package:logging/logging.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/ecc/api.dart';

import "package:dmrtd/src/extension/logging_apis.dart";
import "package:dmrtd/src/lds/tlv.dart";
import "package:dmrtd/src/proto/iso7816/icc.dart";
import 'package:dmrtd/src/lds/efcard_access.dart';
import 'package:pointycastle/export.dart';

import '../lds/tlvSet.dart';
import '../utils.dart';
import 'access_key.dart';
import 'ecdh_pace.dart';
import 'dh_pace.dart';
import 'aes_smcipher.dart';

// Specified in section 9.2.1 of ICAO 9303 p11 doc only this algorithms are
// supported
/*
id-PACE-DH-GM-3DES-CBC-CBC |
id-PACE-DH-GM-AES-CBC-CMAC-128 |
id-PACE-DH-GM-AES-CBC-CMAC-192 |
id-PACE-DH-GM-AES-CBC-CMAC-256 |
id-PACE-ECDH-GM-3DES-CBC-CBC |
id-PACE-ECDH-GM-AES-CBC-CMAC-128 |
id-PACE-ECDH-GM-AES-CBC-CMAC-192 |
id-PACE-ECDH-GM-AES-CBC-CMAC-256 |
id-PACE-DH-IM-3DES-CBC-CBC |
id-PACE-DH-IM-AES-CBC-CMAC-128 |
id-PACE-DH-IM-AES-CBC-CMAC-192 |
id-PACE-DH-IM-AES-CBC-CMAC-256 |
id-PACE-ECDH-IM-3DES-CBC-CBC |
id-PACE-ECDH-IM-AES-CBC-CMAC-128 |
id-PACE-ECDH-IM-AES-CBC-CMAC-192 |
id-PACE-ECDH-IM-AES-CBC-CMAC-256 |
id-PACE-ECDH-CAM-AES-CBC-CMAC-128 |
id-PACE-ECDH-CAM-AES-CBC-CMAC-192 |
id-PACE-ECDH-CAM-AES-CBC-CMAC-256)
*/

class PACEResponseCheckError implements Exception {
  final String message;
  PACEResponseCheckError(this.message);
  @override
  String toString() => message;
}

//Specified in section 4.4.5 of ICAO 9303 p11, table 4:Exchanged data for PACE
class ExchangedDataPACE {
  //step 1 - encrypted nonce
  static const encryptedNonceResponse = 0x80;

  //step 2 - map nonce
  static const mappingDataCommand = 0x81;
  static const mappingDataResponse = 0x82;

  //step 3 - perform key agreement
  static const ephemeralPublicKeyCommand = 0x83;
  static const ephemeralPublicKeyResponse = 0x84;

  //step 4 - mutual authentication
  static const authenticationTokenCommand = 0x85;
  static const authenticationTokenResponse = 0x86;
  static const certificationAuthorityReference = 0x87;
  static const certificationAuthorityReference2 = 0x88;
  static const encryptedChipAuthenticationData = 0x8A;
}

class ResponseDataTagList {
  static const dynamicAuthenticationData = 0x7c;
}

//
// response parsers
//

class ResponseAPDUStep1PaceError implements Exception {
  final String message;
  ResponseAPDUStep1PaceError(this.message);
  @override
  String toString() => message;
}

class ResponseAPDUStep2or3PaceError implements Exception {
  final String message;
  ResponseAPDUStep2or3PaceError(this.message);
  @override
  String toString() => message;
}

class ResponseAPDUStep4PaceError implements Exception {
  final String message;
  ResponseAPDUStep4PaceError(this.message);
  @override
  String toString() => message;
}

class ResponseAPDUStep1Pace {
  late Uint8List data;

  late Uint8List _nonce;

  Uint8List get nonce => _nonce;

  static final _log = Logger("ResponseAPDUStep1Pace");

  ResponseAPDUStep1Pace(this.data);

  void parse() {
    //checking if response has data
    if (this.data == null) {
      _log.error("Pace.step1; Response data is null");
      throw ResponseAPDUStep1PaceError("Pace.step1; Response data is null");
    }
    _log.sdVerbose("ResponseAPDUStep1Pace data: ${data.hex()}");

    TLV dynamicAuthenticationData = TLV.fromBytes(data!);

    //checking if response contains dynamic authentication data
    if (dynamicAuthenticationData.tag !=
        ResponseDataTagList.dynamicAuthenticationData) {
      _log.error(
          "Pace.step1; Response data does not contain dynamic authentication data");
      throw ResponseAPDUStep1PaceError(
          "Pace.step1; Response data does not contain dynamic authentication data");
    }
    _log.verbose(
        "Pace.step1; Response data contains dynamic authentication data");

    //checking if dynamic authentication data contains encrypted nonce
    TLV encryptedNonce = TLV.fromBytes(dynamicAuthenticationData.value);
    if (encryptedNonce.tag != ExchangedDataPACE.encryptedNonceResponse) {
      _log.error(
          "Pace.step1; Dynamic authentication data does not contain encrypted nonce");
      throw ResponseAPDUStep1PaceError(
          "Pace.step1; Dynamic authentication data does not contain encrypted nonce");
    }
    this._nonce = encryptedNonce.value;
    _log.sdVerbose("Nonce: ${_nonce.hex()}");
  }
}

class ResponseAPDUStep2or3Pace {
  late Uint8List data;

  late PublicKeyPACE _public;

  PublicKeyPACE get public => _public;

  static final _log = Logger("ResponseAPDUStep2or3Pace");

  ResponseAPDUStep2or3Pace(this.data);

  void parse(
      {required TOKEN_AGREEMENT_ALGO tokenAgreementAlgorithm,
      required int fieldSize}) {
    //checking if response has data
    if (this.data == null) {
      _log.error("Pace.step2; Response data is null");
      throw ResponseAPDUStep2or3PaceError("Pace.step2; Response data is null");
    }
    _log.sdVerbose("ResponseAPDUStep2and3Pace data: ${data.hex()}");

    TLV dynamicAuthenticationData = TLV.fromBytes(data!);

    //checking if response contains dynamic authentication data
    if (dynamicAuthenticationData.tag !=
        ResponseDataTagList.dynamicAuthenticationData) {
      _log.error(
          "Pace.step2; Response data does not contain dynamic authentication data");
      throw ResponseAPDUStep2or3PaceError(
          "Pace.step2 or 3; Response data does not contain dynamic authentication data");
    }
    _log.verbose(
        "Pace.step2 or 3; Response data contains dynamic authentication data");

    //checking if dynamic authentication data contains public element
    TLV mappingData = TLV.fromBytes(dynamicAuthenticationData.value);

    int mappingDataResponseTag = mappingData.tag;
    if (mappingDataResponseTag == ExchangedDataPACE.mappingDataResponse) {
      _log.verbose("... step 2");
    } else if (mappingDataResponseTag ==
        ExchangedDataPACE.ephemeralPublicKeyResponse) {
      _log.verbose("... step 3");
    } else {
      _log.error(
          "Pace.step2 or 3; Dynamic authentication data does not contain mapping data");
      throw ResponseAPDUStep2or3PaceError(
          "Pace.step2 or 3; Dynamic authentication data does not contain mapping data");
    }

    if (mappingData.value.length == 0) {
      _log.error("Pace.step2 or 3; Mapping data is empty");
      throw ResponseAPDUStep2or3PaceError(
          "Pace.step2 or 3; Mapping data is empty");
    }

    if (tokenAgreementAlgorithm == TOKEN_AGREEMENT_ALGO.ECDH) {
      // ECDH
      if (mappingData.value.first != 0x04) {
        _log.verbose(
            "Pace.step2 or 3; Token agreement is ECDH, but first element is not 0x04");
        throw ResponseAPDUStep2or3PaceError(
            "Pace.step2 or 3; Token agreement is ECDH, but first element is not 0x04");
      }
      _log.verbose("Pace.step2 or 3; Mapping data contains EC public key");
      Uint8List hexPublic = Uint8List.fromList(mappingData.value.sublist(1));
      //if length is odd number then we need to print error and throw exception
      if (hexPublic.length % 2 != 0) {
        _log.error(
            "Pace.step2 or 3; Mapping data contains EC public key, but length is odd number. No X and Y component.");
        throw ResponseAPDUStep2or3PaceError(
            "Pace.step2 or 3; Mapping data contains EC public key, but length is odd number. No X and Y component.");
      }
      _public = PublicKeyPACEeCDH.fromHex(
          hexKey: hexPublic, fieldSizeInBits: fieldSize);
    } else {
      // DH
      _log.verbose("Pace.step2 or 3; Mapping data contains DH public key");
      _public = PublicKeyPACEdH(pub: mappingData.value);
    }
    _log.sdVerbose("ICC public key: ${_public.toString()}");
  }
}

class ResponseAPDUStep4Pace {
  late Uint8List data;

  late Uint8List _authToken;

  Uint8List get authToken => _authToken;

  static final _log = Logger("ResponseAPDUStep4Pace");

  ResponseAPDUStep4Pace(this.data);

  void parse() {
    //checking if response has data
    if (this.data == null) {
      _log.error("Pace.step4; Response data is null");
      throw ResponseAPDUStep2or3PaceError("Pace.step4; Response data is null");
    }

    _log.sdVerbose("ResponseAPDUStep4Pace data: ${data.hex()}");

    TLV dynamicAuthenticationData = TLV.fromBytes(data!);

    //checking if response contains dynamic authentication data
    if (dynamicAuthenticationData.tag !=
        ResponseDataTagList.dynamicAuthenticationData) {
      _log.error(
          "Pace.step4; Response data does not contain dynamic authentication data");
      throw ResponseAPDUStep4PaceError(
          "Pace.step4; Response data does not contain dynamic authentication data");
    }
    _log.verbose(
        "Pace.step4; Response data contains dynamic authentication data");

    //checking if dynamic authentication data contains public element
    TLV mappingData = TLV.fromBytes(dynamicAuthenticationData.value);

    int mappingDataResponseTag = mappingData.tag;
    if (mappingDataResponseTag !=
        ExchangedDataPACE.authenticationTokenResponse) {
      _log.error(
          "Pace.step4; Dynamic authentication data does not contain authentication token");
      throw ResponseAPDUStep4PaceError(
          "Pace.step4; Dynamic authentication data does not contain authentication token");
    }

    if (mappingData.value.length == 0) {
      _log.error("Pace.step4; Mapping data is empty");
      throw ResponseAPDUStep4PaceError("Pace.step4; Mapping data is empty");
    }
    _authToken = mappingData.value;
    _log.debug("Parsing step 4 response data was successful");
    _log.sdVerbose("Authentication token: ${_authToken.hex()}");
  }
}

class PACEError implements Exception {
  final String message;
  PACEError(this.message);
  @override
  String toString() => message;
}

/// Class defines Password Authenticated Connection Establishment (PACE)
/// as defined in ICAO 9303 p11 doc.
/// Ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
class PACE {
  static final _log = Logger("pace");

  // Specified in section 4.4.4 of ICAO 9303 p11 doc
  static const cryptographicMechanismReferenceLen = 8;
  static const referenceOfPublicKeyLen = 1;

  // /// Generates data for ENCODING INPUT command
  // /// At least one of [ephemeralPublicPoint] or [publicKeyDH] must be provided.
  // /// If both are provided [ephemeralPublicPoint] exception is thrown.
  // static Uint8List generateEncodingInputData({
  //   required OIEPaceProtocol crytpographicMechanism,
  //   required PublicKeyPACE ephemeralPublic,
  //   required PublicKeyPACE iccEphemeralPublic,
  // }) {
  //   try {
  //     _log.debug("Generating ENCODING INPUT data ...");
  //     const INPUT_DATA_T_TAG = 0x7f49;
  //     const OBJECT_IDENTIFIER_TAG = 0x06;
  //     const DH_POINT = 0x84;
  //     const ELLIPTIC_CURVE_POINT = 0x84;
  //     const UNCOMPRESSED_POINT = 0x04;
  //     const EPHEMERAL_PUBLIC_KEY_TAG = 0x86;

  //     // object identifier, both modes have the same identifier layout
  //     TLV objectIdentifierData = TLV(
  //         OBJECT_IDENTIFIER_TAG,
  //         Uint8List.sublistView(
  //             Uint8List.fromList(crytpographicMechanism.identifier), 1));

  //     _log.sdVerbose(
  //         "Object identifier: ${objectIdentifierData.toBytes().hex()}");
  //     TLV? publicKeyData = null;

  //     _log.sdVerbose("Ephemeral public point: ${ephemeralPublic.toString()}");

  //     if (ephemeralPublic.agreementAlgorithm == TOKEN_AGREEMENT_ALGO.ECDH) {
  //       // ECDH
  //       // Uint8List uncompressedPoint = Uint8List.fromList([UNCOMPRESSED_POINT]);
  //       publicKeyData = TLV(ELLIPTIC_CURVE_POINT, ephemeralPublic.toBytes());
  //       _log.sdVerbose("Public key EC: ${publicKeyData.toBytes().hex()}");
  //     } else {
  //       // DH
  //       publicKeyData = TLV(DH_POINT, ephemeralPublic.toBytes());
  //       _log.sdVerbose("Public key DH: ${publicKeyData.toBytes().hex()}");
  //     }

  //     // ICC's ephemeral public key (tag 0x84)
  //     TLV iccPublicKeyData =
  //         TLV(EPHEMERAL_PUBLIC_KEY_TAG, iccEphemeralPublic.toBytes());
  //     _log.sdVerbose(
  //         "ICC ephemeral public key: ${iccPublicKeyData.toBytes().hex()}");

  //     if (publicKeyData == null) {
  //       _log.error("PACE.generateEncodingInputData; Public key DH is null");
  //       throw PACEError(
  //           "PACE.generateEncodingInputData; Public key DH is null");
  //     }

  //     TLV inputData = TLV(
  //         INPUT_DATA_T_TAG,
  //         Uint8List.fromList(objectIdentifierData.toBytes() +
  //             publicKeyData.toBytes() +
  //             iccPublicKeyData.toBytes()));

  //     _log.sdDebug("ENCODING INPUT data: ${inputData.toBytes().hex()}");
  //     return inputData.toBytes();
  //   } on Exception catch (e) {
  //     _log.error(
  //         "PACE.generateEncodingInputData; Encoding input data failed: $e");
  //     throw PACEError(
  //         "PACE.generateEncodingInputData; Encoding input data failed: $e");
  //   }
  // }
  static Uint8List generateEncodingInputData({
    required OIEPaceProtocol cryptographicMechanism,
    required PublicKeyPACE publicKeyToSign,
  }) {
    _log.debug("Generating standardized ENCODING INPUT data (T-Block)...");
    const INPUT_DATA_T_TAG = 0x7F49;
    const OBJECT_IDENTIFIER_TAG = 0x06;
    const EPHEMERAL_PUBLIC_KEY_TAG = 0x86;

    try {
      // --- CORRECT OID ENCODING USING THE PROVIDED CLASS STRUCTURE ---

      // 1. Get the OID string from the correct property: 'identifierString'.
      final String oidString = cryptographicMechanism.identifierString;

      // 2. Use pointycastle to create an ASN1ObjectIdentifier object from the string.
      final asn1Oid = ASN1ObjectIdentifier.fromIdentifierString(oidString);

      // 3. Encode the entire OID object to get the full TLV bytes.
      //    This gives us [TAG, LENGTH, VALUE].
      final Uint8List fullOidTlv = asn1Oid.encode();

      // 4. Extract ONLY the value bytes, which is what the jmrtd log shows.
      //    We strip the first two bytes (the Tag 0x06 and the Length 0x0A).
      final Uint8List oidValueBytes = fullOidTlv.sublist(2);

      _log.debug("Correctly Encoded OID Value: ${oidValueBytes.hex()}");

      // --- BUILD THE FINAL TLV STRUCTURE ---

      // Build the OID TLV object (Tag + Length + Value)
      final oidTLV = TLV(OBJECT_IDENTIFIER_TAG, oidValueBytes);

      // Build the Public Key TLV object
      final publicKeyBytes = publicKeyToSign.toBytes();
      final publicKeyTLV = TLV(EPHEMERAL_PUBLIC_KEY_TAG, publicKeyBytes);

      // Concatenate the bytes of the two inner TLV objects
      final innerValue = BytesBuilder();
      innerValue.add(oidTLV.toBytes());
      innerValue.add(publicKeyTLV.toBytes());

      // Wrap everything in the final 7F49 tag
      final tBlock = TLV(INPUT_DATA_T_TAG, innerValue.toBytes());

      final goldenTBlock = "7f494f060a04007f000702020402048641" +
          publicKeyToSign.toBytes().hex();
      _log.sdDebug("Final Corrected T-Block:   ${tBlock.toBytes().hex()}");
      _log.sdDebug("Goal (from jmrtd log):     ${goldenTBlock}");

      return tBlock.toBytes();
    } catch (e) {
      _log.error("Failed to generate correct T-Block: $e");
      rethrow;
    }
  }

  static Uint8List generateSimpleAuthData({
    required PublicKeyPACE ephemeralPublic,
    required PublicKeyPACE iccEphemeralPublic,
  }) {
    _log.debug("Generating SIMPLE authentication data (raw concatenation)...");
    final ourKey = ephemeralPublic.toBytes();
    final iccKey = iccEphemeralPublic.toBytes();

    final builder = BytesBuilder();
    builder.add(iccKey);
    builder.add(ourKey);

    final result = builder.toBytes();
    _log.sdVerbose("Simple Auth Data: ${result.hex()}");
    return result;
  }

  /// Generates data for AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION
  static Uint8List generateAuthenticationTemplateForMutualAuthenticationData(
      {required final Uint8List cryptographicMechanism,
      required int paceRefType}) {
    _log.debug(
        "Generating AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION data ...");
    const CYRYPTOGRAPHIC_MECHANISM_REF_TAG = 0x80;
    const PASSWORD_REF_PUB_KEY_TAG = 0x83;

    TLV cm = TLV(CYRYPTOGRAPHIC_MECHANISM_REF_TAG,
        Uint8List.sublistView(cryptographicMechanism, 1));
    TLV drp = TLV.fromIntValue(PASSWORD_REF_PUB_KEY_TAG, paceRefType);
    TLVSet set = TLVSet();
    set.add(cm); //first element
    set.add(drp); //second element
    //set.add(additionalACrytpgraphicAlgorithm); //third element
    _log.sdDebug(
        "AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION data: ${set.toString()}");
    return set.toBytes();
  }

  /// Generates data for GENERAL AUTHENTICATE command
  static Uint8List generateGeneralAuthenticateDataStep1() {
    //the same message for ECDH and DH
    _log.debug("Generating GENERAL AUTHENTICATE (step 1) data ...");
    const ABSENT_TAG = 0x7C;
    _log.sdDebug(
        "GENERAL AUTHENTICATE data: ${TLVEmpty(ABSENT_TAG).toBytes()}");
    return TLVEmpty(ABSENT_TAG).toBytes();
  }

  // static Uint8List generateGeneralAuthenticateDataStep2and3(
  //     {required PublicKeyPACE public, bool isEphemeral = false}) {
  //   //the same message for ECDH and DH
  //   _log.debug(
  //       "Generating GENERAL AUTHENTICATE (step 2 (or 3)) data: Is ephemeral: $isEphemeral ...");
  //   const DYNAMIC_AUTHENTICATION_DATA_TAG = 0x7C;
  //   const MAPPING_DATA_TAG = 0x81;
  //   const MAPPING_DATA_EPHEMERAL_TAG = 0x83;
  //   const UNCOMPRESSED_POINT = 0x04;
  //   var PUBLIC_KEY_TAG =
  //       isEphemeral ? MAPPING_DATA_EPHEMERAL_TAG : MAPPING_DATA_TAG;

  //   TLV mappingData;
  //   if (public.agreementAlgorithm == TOKEN_AGREEMENT_ALGO.ECDH) {
  //     // ECDH
  //     Uint8List uncompressedPoint = Uint8List.fromList([UNCOMPRESSED_POINT]);
  //     mappingData = TLV(PUBLIC_KEY_TAG,
  //         Uint8List.fromList(uncompressedPoint + public.toBytes()));
  //     _log.sdVerbose("ECDH data: ${mappingData.toBytes().hex()}");
  //   } else {
  //     // DH
  //     mappingData = TLV(PUBLIC_KEY_TAG, public.toBytes());
  //     _log.sdVerbose("DH data: ${mappingData.toBytes().hex()}");
  //   }

  //   TLV dynamicAuthenticationData =
  //       TLV(DYNAMIC_AUTHENTICATION_DATA_TAG, mappingData.toBytes());

  //   _log.sdVerbose(
  //       "PACE step 2 (or 3) data: ${dynamicAuthenticationData.toBytes().hex()}");
  //   return dynamicAuthenticationData.toBytes();
  // }

  /// Build the TLV for GENERAL AUTHENTICATE step 2 or 3,
  /// handling both PACE‐ECDH and legacy DH keys.
  static Uint8List generateGeneralAuthenticateDataStep2and3({
    required Uint8List publicKeyBytes,
    required bool isEcdh, // true for PACE/ECDH, false for legacy DH
    bool isEphemeral = false, // step 2 (static) vs. step 3 (ephemeral)
  }) {
    const outerTag = 0x7C;

    // The isEcdh flag is CRITICAL here to select the correct command tag.
    final int innerTag =
        isEphemeral ? (isEcdh ? 0x83 : 0x84) : (isEcdh ? 0x81 : 0x82);

    // The value is now always the raw publicKeyBytes, because the formatting
    // (adding the 0x04 prefix for ECDH) is now correctly handled upstream
    // in the PublicKeyPACEeCDH.toBytes() method.
    final Uint8List value = publicKeyBytes;

    // Build inner TLV (e.g., 0x81 or 0x83)
    final inner = TLV(innerTag, value);

    // Wrap that in outer 0x7C
    final outer = TLV(outerTag, inner.toBytes());
    return outer.toBytes();
  }

  static Uint8List generateGeneralAuthenticateDataStep4({
    required Uint8List authToken,
    Uint8List? caRef1,
    Uint8List? caRef2,
  }) {
    //the same message for ECDH and DH
    _log.debug("Generating GENERAL AUTHENTICATE (step 4)");
    const DYNAMIC_AUTHENTICATION_DATA_TAG = 0x7C;
    const AUTHENTICATION_TOKEN_TAG = 0x85;
    const CA_REF1_TAG = 0x87;
    const CA_REF2_TAG = 0x88;

    final set = TLVSet();
    set.add(TLV(AUTHENTICATION_TOKEN_TAG, authToken));
    if (caRef1 != null) set.add(TLV(CA_REF1_TAG, caRef1));
    if (caRef2 != null) set.add(TLV(CA_REF2_TAG, caRef2));

    final dynamicAuthenticationData =
        TLV(DYNAMIC_AUTHENTICATION_DATA_TAG, set.toBytes());
    _log.sdVerbose(
        "PACE step 4 data: ${dynamicAuthenticationData.toBytes().hex()}");
    return dynamicAuthenticationData.toBytes();
  }

  static Uint8List cacluateEncKey(
      {required OIEPaceProtocol paceProtocol, required Uint8List seed}) {
    KEY_LENGTH keyLength = paceProtocol.keyLength;
    CipherAlgorithm cipherAlgorithm = paceProtocol.cipherAlgoritm;

    _log.debug("f");
    _log.sdDebug("Seed: ${seed.hex()}, "
        "Key length: $keyLength, "
        "Cipher algorithm: $cipherAlgorithm");

    if (cipherAlgorithm == CipherAlgorithm.AES) {
      if (keyLength == KEY_LENGTH.s128) {
        _log.debug("Cipher algorithm: AES, Key length: 128 bits");
        return DeriveKey.aes128(seed, paceMode: true);
      } else if (keyLength == KEY_LENGTH.s192) {
        _log.debug("Cipher algorithm: AES, Key length: 192 bits");
        return DeriveKey.aes192(seed, paceMode: true);
      } else if (keyLength == KEY_LENGTH.s256) {
        _log.debug("Cipher algorithm: AES, Key length: 256 bits");
        return DeriveKey.aes256(seed, paceMode: true);
      } else {
        _log.error("Key length is not supported");
        throw PACEError("Key length is not supported");
      }
    } else if (cipherAlgorithm == CipherAlgorithm.DESede) {
      _log.debug("Cipher algorithm: DESede.");
      return DeriveKey.desEDE(seed, paceMode: true);
    } else {
      _log.error("Cipher algorithm is not supported");
      throw PACEError("Cipher algorithm is not supported");
    }
  }

  static Uint8List cacluateMacKey(
      {required OIEPaceProtocol paceProtocol, required Uint8List seed}) {
    KEY_LENGTH keyLength = paceProtocol.keyLength;
    CipherAlgorithm cipherAlgorithm = paceProtocol.cipherAlgoritm;

    _log.debug("Calculating MAC key ...");
    _log.sdDebug("Seed: ${seed.hex()}, "
        "Key length: $keyLength, "
        "Cipher algorithm: $cipherAlgorithm");

    if (cipherAlgorithm == CipherAlgorithm.AES) {
      if (keyLength == KEY_LENGTH.s128) {
        _log.debug("Cipher algorithm: AES, Key length: 128 bits");
        return DeriveKey.cmac128(seed, paceMode: true);
      } else if (keyLength == KEY_LENGTH.s192) {
        _log.debug("Cipher algorithm: AES, Key length: 192 bits");
        return DeriveKey.cmac192(seed, paceMode: true);
      } else if (keyLength == KEY_LENGTH.s256) {
        _log.debug("Cipher algorithm: AES, Key length: 256 bits");
        return DeriveKey.cmac256(seed, paceMode: true);
      } else {
        _log.error("Key length is not supported");
        throw PACEError("Key length is not supported");
      }
    } else if (cipherAlgorithm == CipherAlgorithm.DESede) {
      _log.debug("Cipher algorithm: DESede.");
      return DeriveKey.desEDE(seed, paceMode: true);
    } else {
      _log.error("Cipher algorithm is not supported");
      throw PACEError("Cipher algorithm is not supported");
    }
  }

  static Uint8List cacluate_K_PI_Key121(
      {required OIEPaceProtocol paceProtocol, required Uint8List seed}) {
    //we need K_pi to decrypt nonce
    KEY_LENGTH keyLength = paceProtocol.keyLength;
    CipherAlgorithm cipherAlgorithm = paceProtocol.cipherAlgoritm;

    _log.debug("Calculating K-pi key ...");
    _log.sdDebug("Seed: ${seed.hex()}, "
        "Key length: $keyLength, "
        "Cipher algorithm: $cipherAlgorithm");

    if (cipherAlgorithm == CipherAlgorithm.AES) {
      if (keyLength == KEY_LENGTH.s128) {
        _log.debug("Cipher algorithm: AES, Key length: 128 bits");
        return DeriveKey.cmac128(seed);
      } else if (keyLength == KEY_LENGTH.s192) {
        _log.debug("Cipher algorithm: AES, Key length: 192 bits");
        return DeriveKey.cmac192(seed);
      } else if (keyLength == KEY_LENGTH.s256) {
        _log.debug("Cipher algorithm: AES, Key length: 256 bits");
        return DeriveKey.cmac256(seed);
      } else {
        _log.error("Key length is not supported");
        throw PACEError("Key length is not supported");
      }
    } else if (cipherAlgorithm == CipherAlgorithm.DESede) {
      _log.debug("Cipher algorithm: DESede.");
      return DeriveKey.desEDE(seed, paceMode: false);
    } else {
      _log.error("Cipher algorithm is not supported");
      throw PACEError("Cipher algorithm is not supported");
    }
  }

  // static Uint8List cacluateAuthToken(
  //     {required OIEPaceProtocol paceProtocol,
  //     required Uint8List inputData,
  //     required Uint8List macKey}) {
  //   KEY_LENGTH keyLength = paceProtocol.keyLength;
  //   CipherAlgorithm cipherAlgorithm = paceProtocol.cipherAlgoritm;

  //   _log.debug("Calculating Auth token ...");
  //   _log.sdDebug("Seed: ${inputData.hex()}, "
  //       "Key length: $keyLength, "
  //       "Cipher algorithm: $cipherAlgorithm, "
  //       "Mac key length: ${macKey.length}"
  //       "Mac key: ${macKey.hex()}");
  //   Uint8List computedAuthToken;
  //   if (cipherAlgorithm == CipherAlgorithm.AES) {
  //     _log.debug("Cipher algorithm: AES.");
  //     if (keyLength == KEY_LENGTH.s128) {
  //       AESCipher aesCipher = AESChiperSelector.getChiper(
  //           size: KEY_LENGTH.s128); //size is not important
  //       computedAuthToken =
  //           aesCipher.calculateCMAC(data: inputData, key: macKey);
  //       _log.sdVerbose("Computed auth token: ${computedAuthToken.hex()}");
  //     } else if (keyLength == KEY_LENGTH.s256) {
  //       AESCipher aesCipher = AESChiperSelector.getChiper(
  //           size: KEY_LENGTH.s256); //size is not important
  //       computedAuthToken =
  //           aesCipher.calculateCMAC(data: inputData, key: macKey);
  //       _log.sdVerbose("Computed auth token 256: ${computedAuthToken.hex()}");
  //     } else {
  //       _log.error("Key length is not supported");
  //       throw PACEError("Key length is not supported");
  //     }
  //   } else if (cipherAlgorithm == CipherAlgorithm.DESede) {
  //     _log.debug("Cipher algorithm: DESede.");
  //     computedAuthToken =
  //         ISO9797.macAlg3(macKey, inputData); //padding included:)
  //     _log.sdVerbose("Computed auth token: ${computedAuthToken.hex()}");
  //   } else {
  //     _log.error("Cipher algorithm is not supported");
  //     throw PACEError("Cipher algorithm is not supported");
  //   }

  //   // ======================= THE FINAL FIX =======================
  //   // The ICAO standard requires the token to be truncated to 8 bytes.
  //   if (computedAuthToken.length > 8) {
  //     _log.warning(
  //         "TRUNCATING auth token to 8 bytes as per ICAO 9303 standard.");
  //     // Create a view of the first 8 bytes without copying memory.
  //     final truncatedToken = Uint8List.view(computedAuthToken.buffer, 0, 8);
  //     return truncatedToken;
  //   }

  //   return computedAuthToken;
  // }

  static Uint8List cacluateAuthToken(
      {required OIEPaceProtocol paceProtocol,
      required Uint8List inputData,
      required Uint8List macKey}) {
    _log.debug("Calculating Auth token using the application's AESCipher...");
    _log.sdDebug("InputData (T-Block): ${inputData.hex()}");
    _log.sdDebug("MAC key: ${macKey.hex()}");

    if (paceProtocol.cipherAlgoritm == CipherAlgorithm.AES) {
      // ======================= THE FINAL CORRECT CODE =======================
      // 1. USE YOUR EXISTING AESCIPHER. IT WORKS.
      // This correctly uses your FixedCMac which avoids the IV crash.
      final aesCipher =
          AESChiperSelector.getChiper(size: paceProtocol.keyLength);
      final Uint8List fullComputedToken =
          aesCipher.calculateCMAC(data: inputData, key: macKey);

      _log.sdVerbose(
          "Full computed auth token from FixedCMac (${fullComputedToken.length} bytes): ${fullComputedToken.hex()}");

      // 2. TRUNCATE THE RESULT TO 8 BYTES.
      // This is the ICAO standard and the only remaining bug.
      if (fullComputedToken.length < 8) {
        throw PACEError("Computed auth token is less than 8 bytes long!");
      }

      // Use a view to avoid extra memory allocation.
      final truncatedToken = Uint8List.view(fullComputedToken.buffer, 0, 8);

      _log.sdDebug(
          "Truncated 8-byte Auth Token to be sent: ${truncatedToken.hex()}");
      return truncatedToken;
      // ======================================================================
    } else if (paceProtocol.cipherAlgoritm == CipherAlgorithm.DESede) {
      _log.debug("Cipher algorithm: DESede.");
      var computedAuthToken = ISO9797.macAlg3(macKey, inputData);
      if (computedAuthToken.length > 8) {
        return Uint8List.view(computedAuthToken.buffer, 0, 8);
      }
      return computedAuthToken;
    } else {
      _log.error("Cipher algorithm is not supported");
      throw PACEError("Cipher algorithm is not supported");
    }
  }

  static Uint8List decryptNonce(
      {required OIEPaceProtocol paceProtocol,
      required Uint8List nonce,
      required AccessKey accessKey,
      required int paceDomainParameterId}) {
    try {
      _log.debug("PACE.decryptNonce; Decrypting nonce ...");
      _log.sdVerbose("PACE.decryptNonce; Nonce: ${nonce.hex()}, "
          "Pace protocol: ${paceProtocol.toString()}");
      _log.sdVerbose("PACE.decryptNonce; Access key: ${accessKey.toString()}");

      CipherAlgorithm cipherAlgo = paceProtocol.cipherAlgoritm;
      KEY_LENGTH keyLength = paceProtocol.keyLength;

      Uint8List k_pi = accessKey.Kpi(cipherAlgo, keyLength);
      //Uint8List k_pi = cacluate_K_PI_Key(paceProtocol: paceProtocol, seed: key);
      _log.sdVerbose("PACE.decryptNonce; K-pi: ${k_pi.hex()}");

      Uint8List decryptedNonce;

      if (cipherAlgo == CipherAlgorithm.AES) {
        if (keyLength == KEY_LENGTH.s128) {
          _log.debug("PACE.decryptNonce; Cipher algorithm: AES");
          AESCipher aesCipher128 =
              AESChiperSelector.getChiper(size: KEY_LENGTH.s128);
          decryptedNonce = aesCipher128.decrypt(data: nonce, key: k_pi);
          _log.sdVerbose(
              "PACE.decryptNonce; Decrypted nonce: ${decryptedNonce.hex()}");
        } else if (keyLength == KEY_LENGTH.s256) {
          _log.debug("PACE.decryptNonce; Cipher algorithm: AES 256");
          AESCipher aesCipher256 =
              AESChiperSelector.getChiper(size: KEY_LENGTH.s256);
          decryptedNonce = aesCipher256.decrypt(data: nonce, key: k_pi);
          _log.sdVerbose(
              "PACE.decryptNonce; Decrypted nonce: ${decryptedNonce.hex()}");
        } else {
          _log.error("PACE.decryptNonce; Key length is not supported");
          throw PACEError("PACE.decryptNonce; Key length is not supported");
        }
      } else if (cipherAlgo == CipherAlgorithm.DESede) {
        _log.debug("PACE.decryptNonce; Cipher algorithm: DESede");
        /*key iv data*/
        decryptedNonce =
            DESedeDecrypt(edata: nonce, key: k_pi, iv: Uint8List(8));
        _log.sdVerbose(
            "PACE.decryptNonce; Decrypted nonce: ${decryptedNonce.hex()}");
      } else {
        _log.error("PACE.decryptNonce; Cipher algorithm is not supported");
        throw PACEError("PACE.decryptNonce; Cipher algorithm is not supported");
      }

      // try {
      //   _log.debug("Validating decrypted nonce is a point on the curve...");
      //   final domainParameter = DomainParameterSelectorECDH.getDomainParameter(
      //       id: paceDomainParameterId);
      //   final curveParams = domainParameter.domainParameters;
      //   final fieldSizeInBytes = (curveParams.curve.fieldSize / 8).ceil();

      //   if (decryptedNonce.length != 2 * fieldSizeInBytes) {
      //     throw PACEError(
      //         "Decrypted nonce has incorrect length (${decryptedNonce.length} bytes) "
      //         "for the selected curve (expected ${2 * fieldSizeInBytes} bytes). Incorrect CAN?");
      //   }

      //   // Use the correct Utils function
      //   final x = Utils.uint8ListToBigInt(
      //       decryptedNonce.sublist(0, fieldSizeInBytes));
      //   final y =
      //       Utils.uint8ListToBigInt(decryptedNonce.sublist(fieldSizeInBytes));

      //   // Use the correct pointycastle validation method: try to create the point.
      //   // The createPoint method will throw an exception if (x,y) is not on the curve.
      //   curveParams.curve.createPoint(x, y);

      //   _log.debug("Nonce validation successful.");
      // } catch (e) {
      //   _log.error(
      //       "Decrypted nonce is NOT a valid point on the curve. The CAN is almost certainly incorrect. Validation failed with error: $e");
      //   throw PACEError(
      //       "PACE.decryptNonce; Nonce validation failed. Incorrect CAN.");
      // }

      // _log.severe("== NONCE ANALYSIS ==");
      // _log.severe("Decrypted Nonce (raw): ${decryptedNonce.hex()}");
      // _log.severe("Decrypted Nonce Length: ${decryptedNonce.length} bytes");

      // try {
      //   final domainParameter = DomainParameterSelectorECDH.getDomainParameter(
      //       id: paceDomainParameterId);
      //   final curveParams = domainParameter.domainParameters;
      //   final fieldSizeInBytes = (curveParams.curve.fieldSize / 8).ceil();

      //   if (decryptedNonce.length == 2 * fieldSizeInBytes) {
      //     _log.info("Nonce has the correct length for a 64-byte public key.");
      //     final x = Utils.uint8ListToBigInt(
      //         decryptedNonce.sublist(0, fieldSizeInBytes));
      //     final y =
      //         Utils.uint8ListToBigInt(decryptedNonce.sublist(fieldSizeInBytes));
      //     curveParams.curve.createPoint(x, y);
      //   } else {
      //     _log.warning(
      //         "Nonce is NOT a 64-byte public key. It's something else.");
      //   }
      // } catch (e) {
      //   _log.error("Error during nonce validation check: $e");
      // }
      // _log.severe("====================");

      return decryptedNonce;
    } on Exception catch (e) {
      _log.error("PACE.decryptNonce; Failed: $e");
      throw PACEError("PACE.decryptNonce; Failed: $e");
    }
  }

  static Future<void> ecdh(
      {required ICC icc,
      required Uint8List nonce,
      required int paceDomainParameterId,
      required OIEPaceProtocol paceProtocol}) async {
    try {
      _log.debug("PACE >ECDH< key establishment (from step 2 to step 4) ...");
      _log.sdVerbose("PACE >ECDH< key establishment (from step 2 to step 4); "
          "Decrypted nonce: ${nonce.hex()}, "
          "Pace domain parameter id(int): $paceDomainParameterId, "
          "Pace protocol: ${paceProtocol.toString()}");

      ECDHPace? domainParameter;
      PublicKeyPACEeCDH? publicICCenvelope;
      PublicKeyPACEeCDH? ephemeralPublicICCenvelope;
      try {
        _log.debug("Starting PACE step 2 ...");
        domainParameter = DomainParameterSelectorECDH.getDomainParameter(
            id: paceDomainParameterId);
        //generating key pair
        domainParameter.generateKeyPair();
        //get public key
        PublicKeyPACEeCDH publicKeyPaceTerminal = domainParameter.getPubKey();
        final pubKeyBytes = publicKeyPaceTerminal.toBytes();

        print(
            "Public key (X): ${publicKeyPaceTerminal.x.toRadixString(16).padLeft(64, '0')}");
        print(
            "Public key (Y): ${publicKeyPaceTerminal.y.toRadixString(16).padLeft(64, '0')}");
        print("Public key SEC1 (hex): ${pubKeyBytes.hex()}");

        _log.sdVerbose("Private key: ${domainParameter.toStringWithCaution()}");
        _log.sdVerbose("Public key: ${publicKeyPaceTerminal.toBytes().hex()}");

        print("Private key: ${domainParameter.toStringWithCaution()}");
        print("Public key: ${publicKeyPaceTerminal.toBytes().hex()}");
        print(publicKeyPaceTerminal.x.toString());
        print(publicKeyPaceTerminal.y.toString());

        final staticXy = domainParameter.getPubKey().toBytes(); // X||Y
        final step2data = generateGeneralAuthenticateDataStep2and3(
          publicKeyBytes: staticXy,
          isEcdh: true,
          isEphemeral: false,
        );

        print("Step 2 data: ${step2data.hex()}");
        final step2Response =
            await icc.generalAuthenticatePACEstep2and3(data: step2data);
        //here the response is always 9000, otherwise exception is thrown

        ResponseAPDUStep2or3Pace apduStep2Pace =
            ResponseAPDUStep2or3Pace(step2Response);
        apduStep2Pace.parse(
            tokenAgreementAlgorithm: paceProtocol.tokenAgreementAlgorithm,
            fieldSize: domainParameter.selectedDomainParameter.size);

        //get public key from ICC
        publicICCenvelope = apduStep2Pace.public as PublicKeyPACEeCDH;
        _log.debug("PACE step 2 response from ICC is valid");
      } on Exception catch (e) {
        _log.error("PACE(2); Failed: $e");
        throw PACEError("PACE(2); Failed: $e");
      }

      try {
        _log.debug("Starting PACE step 3 ...");
        ECPublicKey publicICCkey =
            domainParameter.transformPublic(pubKey: publicICCenvelope);

        ECPoint generatorPoint = domainParameter.getMappedGenerator(
            otherPubKey: publicICCkey,
            nonce: nonce,
            mappingType: paceProtocol.mappingType);

        _log.warning(
            "[PACE Step3] Mapped generator X: ${generatorPoint.x.toString()}");
        _log.warning(
            "[PACE Step3] Mapped generator Y: ${generatorPoint.y.toString()}");
        _log.warning(
            "[PACE Step3] Mapped generator encoded: ${generatorPoint.getEncoded(false).hex()}");

        _log.sdVerbose(
            "Generator point: ${ECDHPace.ecPointToList(point: generatorPoint, fieldSize: domainParameter.selectedDomainParameter.size).toString()}");
        domainParameter.generateKeyPairWithCustomGenerator(
            mappedGenerator: generatorPoint);

        //get public key
        PublicKeyPACEeCDH publicKeyEphemeralPaceTerminal =
            domainParameter.getPubKeyEphemeral();

        final pubKeyBytes = publicKeyEphemeralPaceTerminal.toBytes();
        _log.warning("[PACE Step3] Ephemeral public key: ${pubKeyBytes.hex()}");
        _log.warning(
            "[PACE Step3] Ephemeral public key length: ${pubKeyBytes.length}");
        if (pubKeyBytes.length != 65 || pubKeyBytes[0] != 0x04) {
          _log.warning(
              "[PACE Step3] PUBLIC KEY FORMAT MISMATCH! Should be uncompressed SEC1 format (0x04 + 32 + 32 bytes)");
        }

        _log.sdVerbose(
            "Private key (ephemeral included): ${domainParameter.toStringWithCaution()}");
        _log.sdVerbose(
            "Public key (ephemeral): ${publicKeyEphemeralPaceTerminal.toBytes().hex()}");

        final ephXy = domainParameter.getPubKeyEphemeral().toBytes();
        final step3data = generateGeneralAuthenticateDataStep2and3(
          publicKeyBytes: ephXy,
          isEcdh: true,
          isEphemeral: true,
        );
        // await icc.generalAuthenticatePACEstep2and3(data: step3);

        _log.info(
            "PACE step 3 ephemeral public key (raw): ${publicKeyEphemeralPaceTerminal.toBytes().hex()}");
        _log.info(
            "Mapped generator (EC point): ${ECDHPace.ecPointToList(point: generatorPoint, fieldSize: domainParameter.selectedDomainParameter.size).toString()}");
        _log.info("GENERAL AUTHENTICATE APDU data (hex): ${step3data.hex()}");

        final tlv = TLV.fromBytes(step3data);
        _log.warning(
            "[PACE Step3] Outer TLV tag: ${tlv.tag.hex()}, len: ${tlv.value.length}");
        if (tlv.value.length > 0) {
          try {
            final inner = TLV.fromBytes(tlv.value);
            _log.warning(
                "[PACE Step3] Inner TLV tag: ${inner.tag.hex()}, len: ${inner.value.length}");
            _log.warning("[PACE Step3] Inner value: ${inner.value.hex()}");
          } catch (e) {
            _log.warning("[PACE Step3] Failed to parse inner TLV: $e");
          }
        }
        _log.warning("[PACE Step3] Full APDU: ${step3data.hex()}");

        final step3Response =
            await icc.generalAuthenticatePACEstep2and3(data: step3data);
        //here the response is always 9000, otherwise exception is thrown

        ResponseAPDUStep2or3Pace apduStep2Pace =
            ResponseAPDUStep2or3Pace(step3Response);
        apduStep2Pace.parse(
            tokenAgreementAlgorithm: paceProtocol.tokenAgreementAlgorithm,
            fieldSize: domainParameter.selectedDomainParameter.size);
        ephemeralPublicICCenvelope = apduStep2Pace.public as PublicKeyPACEeCDH;
        _log.debug("PACE step 3 response from ICC is valid");
        _log.sdVerbose(
            "Ephemeral public ICC key: ${ephemeralPublicICCenvelope.toString()}");
      } on Exception catch (e) {
        _log.error("PACE(3); Failed: $e");
        throw PACEError("PACE(3); Failed: $e");
      }

      try {
        _log.debug("Starting PACE step 4 ...");
        ECPublicKey ephemeralPublicICCkey =
            domainParameter.transformPublic(pubKey: ephemeralPublicICCenvelope);
        _log.debug("Epehemeral public key is successfully transformed");
        _log.sdVerbose(
            "Ephemeral public ICC key: ${ECDHPace.ecPointToList(point: ephemeralPublicICCkey.Q!, fieldSize: domainParameter.selectedDomainParameter.size).toString()}");
        ECPoint ephemeralSharedSecretKey =
            domainParameter.getEphemeralSharedSecret(
                otherEphemeralPubKey: ephemeralPublicICCkey);

        // ECPoint ephemeralSharedSecretKey = domainParameter.getVanillaSharedSecret(otherEphemeralPubKey: ephemeralPublicICCkey)

        _log.sdVerbose("Ephemeral shared secret (X, Y): "
            "${ECDHPace.ecPointToList(point: ephemeralSharedSecretKey, fieldSize: domainParameter.selectedDomainParameter.size).toBytes().hex()}");

        // Uint8List seed = ECDHPace.ecPointToList(
        //         point: ephemeralSharedSecretKey,
        //         fieldSize: domainParameter.selectedDomainParameter.size)
        //     .toRelavantBytes();
        // _log.sdVerbose("Seed: ${seed.hex()}");

        final BigInt xCoord = ephemeralSharedSecretKey.x!.toBigInteger()!;
        final int fieldSizeInBytes =
            (domainParameter.selectedDomainParameter.size / 8).ceil();

        final Uint8List seed = Uint8List(fieldSizeInBytes);
        final xBytes = Utils.bigIntToUint8List(bigInt: xCoord);

// Manually left-pad the x-coordinate with zeros to match the field size.
        seed.setRange(
            fieldSizeInBytes - xBytes.length, fieldSizeInBytes, xBytes);
        _log.sdVerbose("Seed (x-coordinate of shared secret): ${seed.hex()}");

        Uint8List encKey =
            PACE.cacluateEncKey(paceProtocol: paceProtocol, seed: seed);
        Uint8List macKey =
            PACE.cacluateMacKey(paceProtocol: paceProtocol, seed: seed);

        _log.debug("ENC and Mac keys are successfully calculated");
        _log.sdVerbose("ENC key: ${encKey.hex()} "
            "MAC key: ${macKey.hex()}");

        Uint8List calcInputData = PACE.generateEncodingInputData(
            cryptographicMechanism: paceProtocol,
            publicKeyToSign: ephemeralPublicICCenvelope);

        // Uint8List calcInputData = PACE.generateSimpleAuthData(
        //     ephemeralPublic: domainParameter.getPubKeyEphemeral(),
        //     iccEphemeralPublic: ephemeralPublicICCenvelope);

        print("=== DETAILED T-BLOCK ANALYSIS ===");
        print("Protocol object: ${paceProtocol.toString()}");
        print("Protocol runtimeType: ${paceProtocol.runtimeType}");

// Try these possible properties:
        try {
          print("Protocol identifier: ${paceProtocol.identifier}");
        } catch (e) {
          print("No identifier property");
        }
        print("=== PACE PROTOCOL INSPECTION ===");
        print("PaceProtocol type: ${paceProtocol.runtimeType}");
        print("PaceProtocol string: ${paceProtocol.toString()}");
        print("Cipher algorithm: ${paceProtocol.cipherAlgoritm}");
        print("Key length: ${paceProtocol.keyLength}");
        print("Token agreement algo: ${paceProtocol.tokenAgreementAlgorithm}");
        print("Mapping type: ${paceProtocol.mappingType}");

        Uint8List inputToken = PACE.cacluateAuthToken(
            paceProtocol: paceProtocol,
            inputData: calcInputData,
            macKey: macKey);
        print("=== STEP 4 DEBUG ===");
        print("ENC key:   ${encKey.hex()}");
        print("MAC key:   ${macKey.hex()}");
        print("InputData (T-block): ${calcInputData.hex()}");
        print("AuthToken: ${inputToken.hex()}");

        // final ca1 = efCardAccess.paceInfo?.certificationAuthorityReference;
        // final ca2 = efCardAccess.paceInfo?.certificationAuthorityReference2;

        Uint8List step4data =
            generateGeneralAuthenticateDataStep4(authToken: inputToken);

        final pcCmac = FixedCMac.fromCipher(BlockCipher('AES'))
          ..init(KeyParameter(macKey));
        final pcMac = pcCmac.process(calcInputData);

        print('=== CMAC COMPARISON ===');
        print('FixedCMac:        ${inputToken.hex()}');
        print('PointyCastleCMac: ${pcMac.hex()}');

        if (!inputToken.equals(pcMac)) {
          print('>> MISMATCH between FixedCMac and PointyCastle CMac!');
        }

        print("=== T-BLOCK CONTENT CHECK ===");
        print(
            "Our ephemeral public key: ${domainParameter.getPubKeyEphemeral().toBytes().hex()}");
        print(
            "ICC's ephemeral public key: ${ephemeralPublicICCenvelope.toBytes().hex()}");
        print("Complete T-block: ${calcInputData.hex()}");

        // Check if both keys are in the T-block
        String ourKeyHex = domainParameter.getPubKeyEphemeral().toBytes().hex();
        String iccKeyHex = ephemeralPublicICCenvelope.toBytes().hex();
        String tBlockHex = calcInputData.hex();

        print("Our key in T-block? ${tBlockHex.contains(ourKeyHex)}");
        print("ICC key in T-block? ${tBlockHex.contains(iccKeyHex)}");

        final apduBytes = <int>[
          0x00, // CLA
          ISO7816_INS.GENERAL_AUTHENTICATE,
          0x00, 0x00,
          step4data.length, // Lc
          ...step4data,
          // no Le here, or use 0x00 if your transceive requires it
        ];
        print('=== APDU TO SEND ===');
        print(apduBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join());
        print("Step 4 APDU DATA: ${step4data.hex()}");
// parse the TLV so you can see tags/lengths
        var outer = TLV.fromBytes(step4data);
        var inner = TLV.fromBytes(outer.value);
        print("Outer TLV: tag=${outer.tag.hex()}, len=${outer.value.length}");
        print("Inner TLV: tag=${inner.tag.hex()}, len=${inner.value.length}");
        print("====================");

        final step4Response =
            await icc.generalAuthenticatePACEstep4(data: step4data);
        //here the response is always 9000, otherwise exception is thrown
        if (step4Response != null && step4Response.isNotEmpty) {
          ResponseAPDUStep4Pace apduStep4Pace =
              ResponseAPDUStep4Pace(step4Response);
          apduStep4Pace.parse();
          Uint8List computedAuthTokenICC = apduStep4Pace.authToken;

          _log.debug(
              "Checking if computed auth token is the same as auth token from ICC");

          Uint8List calcInputDataTerminalforCheck =
              PACE.generateEncodingInputData(
                  cryptographicMechanism: paceProtocol,
                  publicKeyToSign: ephemeralPublicICCenvelope);

          Uint8List inputTokenTerminalforCheck = PACE.cacluateAuthToken(
              paceProtocol: paceProtocol,
              inputData: calcInputDataTerminalforCheck,
              macKey: macKey);

          _log.sdVerbose(
              "Received auth token from ICC: ${computedAuthTokenICC.hex()}"
              ", Computed auth token: ${inputTokenTerminalforCheck.hex()}");

          if (!inputTokenTerminalforCheck.equals(computedAuthTokenICC)) {
            _log.error(
                "PACE(4); Auth token from ICC and terminal are not the same");
            throw PACEError(
                "PACE(4); Auth token from ICC and terminal are not the same");
          }
        } else {
          _log.warning(
              "Card returned SW=9000 with no data. This is a successful authentication. Skipping verification of card's token.");
        }

        _log.debug("Finished PACE SM key establishment");
        _log.debug("Setting up SM session ...");
        CipherAlgorithm cipherAlgo = paceProtocol.cipherAlgoritm;
        // grab the raw SEC1 bytes of each ephemeral key
        final ifdEphem = domainParameter.getPubKeyEphemeral().toBytes();
        final iccEphem = ephemeralPublicICCenvelope.toBytes();

        print("=== SSC INITIALIZATION DEBUG ===");
        print("IFD ephemeral raw: ${ifdEphem.hex()}");
        print("ICC ephemeral raw: ${iccEphem.hex()}");
        print("IFD ephemeral length: ${ifdEphem.length}");
        print("ICC ephemeral length: ${iccEphem.length}");

        // Log just the X coordinates (what SSC might use)
        if (ifdEphem.length >= 33) {
          print("IFD X coordinate: ${ifdEphem.sublist(1, 33).hex()}");
        }
        if (iccEphem.length >= 33) {
          print("ICC X coordinate: ${iccEphem.sublist(1, 33).hex()}");
        }

        // build the correct SSC as per ICAO‑9303 §9.8.7.3
        final ssc =
            SSC.anotherPACE(iccEphemeral: iccEphem, ifdEphemeral: ifdEphem);

        // final ssc = SSC(Uint8List(16), 128);
        // print("SSC after creation: ${ssc.toBytes().hex()}");
        // print("SSC length: ${ssc.toBytes().length}");

        // ssc.increment();
        print("SSC after increment: ${ssc.toBytes().hex()}");

        // and finally plug it into your SM layer
        final smCipher = (cipherAlgo == CipherAlgorithm.AES)
            ? AES_SMCipher(encKey, macKey, size: paceProtocol.keyLength)
            : DES_SMCipher(encKey, macKey);

        icc.sm = MrtdSM(smCipher, ssc);

        _log.debug("... SM (with ECDH) session is set up.");
      } on Exception catch (e) {
        _log.error("PACE <ECDH> (4); Failed: $e");
        throw PACEError("PACE <ECDH> (4); Failed: $e");
      }
    } on Exception catch (e) {
      _log.error("PACE <ECDH> key establishment failed: $e");
      throw PACEError("PACE <ECDH> key establishment failed: $e");
    }
  }

  static Future<void> dh(
      {required ICC icc,
      required Uint8List nonce,
      required int paceDomainParameterId,
      required OIEPaceProtocol paceProtocol}) async {
    try {
      _log.debug("PACE >DH< key establishment (from step 2 to step 4) ...");
      _log.sdVerbose("PACE >DH< key establishment (from step 2 to step 4); "
          "Decrypted nonce: ${nonce.hex()}, "
          "Pace domain parameter id(int): $paceDomainParameterId, "
          "Pace protocol: ${paceProtocol.toString()}");

      DHPace? domainParameter;
      PublicKeyPACEdH? publicICCenvelope;
      PublicKeyPACEdH? ephemeralPublicICCenvelope;
      try {
        _log.debug("Starting PACE step 2 ...");
        domainParameter = DomainParameterSelectorDH.getDomainParameter(
            id: paceDomainParameterId);
        //generating key pair
        domainParameter.generateKeyPair();
        //get public key
        PublicKeyPACEdH publicKeyPaceTerminal = domainParameter.getPubKey();

        _log.sdVerbose("Private key: ${domainParameter.toStringWithCaution()}");
        _log.sdVerbose("Public key: ${publicKeyPaceTerminal.toBytes().hex()}");

        Uint8List step2data = generateGeneralAuthenticateDataStep2and3(
          publicKeyBytes: publicKeyPaceTerminal.toBytes(),
          isEcdh: false,
          isEphemeral: false,
        );
        final step2Response =
            await icc.generalAuthenticatePACEstep2and3(data: step2data);
        //here the response is always 9000, otherwise exception is thrown

        ResponseAPDUStep2or3Pace apduStep2Pace =
            ResponseAPDUStep2or3Pace(step2Response);
        apduStep2Pace.parse(
            tokenAgreementAlgorithm: paceProtocol.tokenAgreementAlgorithm,
            fieldSize: domainParameter.selectedDomainParameter.size);

        //get public key from ICC
        publicICCenvelope = apduStep2Pace.public as PublicKeyPACEdH;
        _log.debug("PACE step 2 response from ICC is valid");
      } on Exception catch (e) {
        _log.error("PACE(2); Failed: $e");
        throw PACEError("PACE(2); Failed: $e");
      }

      try {
        _log.debug("Starting PACE step 3 ...");
        _log.debug("Public ICC Envelope: ${publicICCenvelope.toString()}");
        Uint8List generatorPoint = domainParameter.getMappedGenerator(
            otherPubKey: publicICCenvelope.toRelavantBytes(), nonce: nonce);

        _log.sdVerbose("Generator point: ${generatorPoint.hex()}");
        domainParameter.generateKeyPairWithCustomGenerator(
            ephemeralGenerator: Utils.uint8ListToBigInt(generatorPoint));

        //get public key
        PublicKeyPACEdH publicKeyEphemeralPaceTerminal =
            domainParameter.getPubKeyEphemeral();

        _log.sdVerbose(
            "Private key (ephemeral included): ${domainParameter.toStringWithCaution()}");
        _log.sdDebug(
            "Public key (ephemeral): ${publicKeyEphemeralPaceTerminal.toBytes().hex()}");

        Uint8List step3data = generateGeneralAuthenticateDataStep2and3(
            publicKeyBytes: publicKeyEphemeralPaceTerminal.toBytes(),
            isEcdh: false,
            isEphemeral: true);

        final step3Response =
            await icc.generalAuthenticatePACEstep2and3(data: step3data);
        //here the response is always 9000, otherwise exception is thrown

        ResponseAPDUStep2or3Pace apduStep2Pace =
            ResponseAPDUStep2or3Pace(step3Response);
        apduStep2Pace.parse(
            tokenAgreementAlgorithm: paceProtocol.tokenAgreementAlgorithm,
            fieldSize: domainParameter.selectedDomainParameter.size);
        ephemeralPublicICCenvelope = apduStep2Pace.public as PublicKeyPACEdH;
        _log.debug("PACE step 3 response from ICC is valid");
        _log.sdVerbose(
            "Ephemeral public ICC key: ${ephemeralPublicICCenvelope.toString()}");
      } on Exception catch (e) {
        _log.error("PACE(3); Failed: $e");
        throw PACEError("PACE(3); Failed: $e");
      }

      try {
        _log.debug("Starting PACE step 4 ...");
        _log.debug(
            "Ephemeral public ICC envelope: ${ephemeralPublicICCenvelope.toString()}");
        BigInt ephemeralSharedSecretKey =
            domainParameter.getEphemeralSharedSecret(
                otherEphemeralPubKey:
                    ephemeralPublicICCenvelope.toRelavantBytes());

        _log.sdVerbose("Ephemeral shared secret (X, Y): "
            "${Utils.bigIntToUint8List(bigInt: ephemeralSharedSecretKey).hex()}");

        //not sure if correct
        Uint8List seed =
            Utils.bigIntToUint8List(bigInt: ephemeralSharedSecretKey);
        _log.sdVerbose("Seed: ${seed.hex()}");

        Uint8List encKey =
            PACE.cacluateEncKey(paceProtocol: paceProtocol, seed: seed);
        Uint8List macKey =
            PACE.cacluateMacKey(paceProtocol: paceProtocol, seed: seed);

        _log.debug("ENC and Mac keys are successfully calculated");
        _log.sdVerbose("ENC key: ${encKey.hex()} "
            "MAC key: ${macKey.hex()}");

        Uint8List calcInputData = PACE.generateEncodingInputData(
            cryptographicMechanism: paceProtocol,
            publicKeyToSign: ephemeralPublicICCenvelope);

        Uint8List inputToken = PACE.cacluateAuthToken(
            paceProtocol: paceProtocol,
            inputData: calcInputData,
            macKey: macKey);

        Uint8List step4data =
            generateGeneralAuthenticateDataStep4(authToken: inputToken);
        final step4Response =
            await icc.generalAuthenticatePACEstep4(data: step4data);
        //here the response is always 9000, otherwise exception is thrown

        if (step4Response != null && step4Response.isNotEmpty) {
          ResponseAPDUStep4Pace apduStep4Pace =
              ResponseAPDUStep4Pace(step4Response);
          apduStep4Pace.parse();
          Uint8List computedAuthTokenICC = apduStep4Pace.authToken;

          Uint8List calcInputDataTerminalforCheck =
              PACE.generateEncodingInputData(
                  cryptographicMechanism: paceProtocol,
                  publicKeyToSign: ephemeralPublicICCenvelope);

          Uint8List inputTokenTerminalforCheck = PACE.cacluateAuthToken(
              paceProtocol: paceProtocol,
              inputData: calcInputDataTerminalforCheck,
              macKey: macKey);

          _log.sdVerbose(
              "Received auth token from ICC: ${computedAuthTokenICC.hex()}"
              ", Computed auth token: ${inputTokenTerminalforCheck.hex()}");

          if (!inputTokenTerminalforCheck.equals(computedAuthTokenICC)) {
            _log.error(
                "PACE(4); Auth token from ICC and terminal are not the same");
            throw PACEError(
                "PACE(4); Auth token from ICC and terminal are not the same");
          }

          _log.debug(
              "Checking if computed auth token is the same as auth token from ICC");
        } else {
          // This is the path your code will now take.
          _log.warning(
              "Card returned SW=9000 with no data. This is a successful authentication. Skipping verification of card's token.");
        }

        _log.debug("Finished PACE SM key establishment");
        _log.debug("Setting up SM session ...");
        CipherAlgorithm cipherAlgo = paceProtocol.cipherAlgoritm;
        if (cipherAlgo == CipherAlgorithm.AES) {
          _log.debug("PACE; Cipher algorithm: AES");
          icc.sm = MrtdSM(
              AES_SMCipher(encKey, macKey, size: paceProtocol.keyLength),
              AES_SSC());
        } else if (cipherAlgo == CipherAlgorithm.DESede) {
          _log.debug("PACE; Cipher algorithm: DESede");
          icc.sm = MrtdSM(DES_SMCipher(encKey, macKey), DESede_PACE_SSC());
        } else {
          _log.error("PACE; Cipher algorithm is not supported");
          throw PACEError("PACE.Cipher algorithm is not supported");
        }
        _log.debug("... SM (with DH) session is set up.");
      } on Exception catch (e) {
        _log.error("PACE <DH> (4); Failed: $e");
        throw PACEError("PACE <DH> (4); Failed: $e");
      }
    } on Exception catch (e) {
      _log.error("PACE <DH> key establishment failed: $e");
      throw PACEError("PACE <DH> key establishment failed: $e");
    }
  }

  static Future<void> initSession(
      {required AccessKey accessKey,
      required ICC icc,
      required EfCardAccess efCardAccess}) async {
    try {
      _log.debug("Starting PACE key establishment ...");
      if (efCardAccess.paceInfo == null) {
        _log.error("PACEInfo is not present in EF.CardAccess");
        throw PACEError("PACEInfo is not present in EF.CardAccess");
      }

      if (efCardAccess.paceInfo?.protocol == null) {
        _log.error("Protocol is not present in EF.CardAccess.paceInfo");
        throw PACEError("Protocol is not present in EF.CardAccess.paceInfo");
      }

      if (efCardAccess.paceInfo?.isPaceDomainParameterSupported == false) {
        _log.error("PACE domain parameter is not supported");
        throw PACEError("PACE domain parameter is not supported");
      }

      _log.sdVerbose("Access key: ${accessKey.toString()}");

      OIEPaceProtocol paceProtocol = efCardAccess.paceInfo!.protocol;
      _log.debug("Protocol: $paceProtocol");

      int paceDomainParameterId = efCardAccess.paceInfo!.parameterId!;
      // we already know that protocol is supported
      // we also know that domain parameter is supported

      // parameters for key establishment
      Uint8List decryptedNonce;

      //step 0
      Uint8List step0data =
          generateAuthenticationTemplateForMutualAuthenticationData(
              cryptographicMechanism:
                  Uint8List.fromList(paceProtocol.identifier),
              paceRefType: accessKey.PACE_REF_KEY_TAG);
      try {
        final step0Response = await icc.setAT(data: step0data);
        //here the response is always 9000, otherwise exception is thrown
        _log.finest("ICC response: ${step0Response}");
        _log.fine("Got PACE step 0 SUCCESSFUL response from ICC");
        _log.debug("PACE step 0 response from ICC is valid");
      } on Exception catch (e) {
        _log.error("PACE(0); Failed: $e");
        throw PACEError("PACE(0); Failed: $e");
      }

      //step 1
      try {
        await Future.delayed(Duration(milliseconds: 1000));
        Uint8List step1data = generateGeneralAuthenticateDataStep1();
        final step1Response =
            await icc.generalAuthenticatePACEstep1(data: step1data);
        //here the response is always 9000, otherwise exception is thrown
        _log.fine("Got PACE step 1 SUCCESSFUL response from ICC");

        //parse step1 response
        ResponseAPDUStep1Pace apduStep1Pace =
            ResponseAPDUStep1Pace(step1Response);
        apduStep1Pace.parse(); //if completed without exception data are valid

        decryptedNonce = PACE.decryptNonce(
            paceProtocol: paceProtocol,
            nonce: apduStep1Pace.nonce,
            accessKey: accessKey,
            paceDomainParameterId: paceDomainParameterId);
        _log.debug("PACE step 1 response from ICC is valid");
      } on Exception catch (e) {
        _log.error("PACE(1); Failed: $e");
        throw PACEError("PACE(1); Failed: $e");
      }

      //step 2, 3 and 4
      if (paceProtocol.tokenAgreementAlgorithm == TOKEN_AGREEMENT_ALGO.ECDH) {
        _log.debug("Going to ECDH key establishment (on step 2, 3 and 4)");
        await ecdh(
            icc: icc,
            nonce: decryptedNonce,
            paceDomainParameterId: paceDomainParameterId,
            paceProtocol: paceProtocol);
      } else if (paceProtocol.tokenAgreementAlgorithm ==
          TOKEN_AGREEMENT_ALGO.DH) {
        _log.debug("Going to DH key establishment (on step 2, 3 and 4)");
        await dh(
            icc: icc,
            nonce: decryptedNonce,
            paceDomainParameterId: paceDomainParameterId,
            paceProtocol: paceProtocol);
      } else {
        _log.error("PACE token agreement algorithm is not supported");
        throw PACEError("PACE token agreement algorithm is not supported");
      }
    } on Exception catch (e) {
      _log.error("PACE key establishment failed: $e");
      throw PACEError("PACE key establishment failed: $e");
    }
  }
}
