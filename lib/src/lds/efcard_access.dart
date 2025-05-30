// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';

import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import "package:dmrtd/src/lds/df1/dg.dart";
import "package:dmrtd/src/extension/logging_apis.dart";
import 'package:logging/logging.dart';
import 'package:pointycastle/asn1.dart';

import 'ef.dart';
import 'substruct/pace_info.dart';

class EfCardAccess extends ElementaryFile {
  static const FID = 0x011C;
  static const SFI = 0x1C;
  static const TAG = DgTag(0x6C);

  PaceInfo? paceInfo;

  bool get isPaceInfoSet => paceInfo != null;

  final _log = Logger("EfCardAccess");

  EfCardAccess.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  void parse(Uint8List content) {
    _log.sdVerbose("Parsing EF.CardAccess" + content.hex());

    var parser = ASN1Parser(content);
    if (!parser.hasNext()) {
      _log.error("Invalid structure of EF.CardAccess. No data to parse.");
      throw EfParseError(
          "Invalid structure of EF.CardAccess. No data to parse.");
    }

    // ASN1Set set = parser.nextObject() as ASN1Set;
    final rootObj = parser.nextObject();
    _log.info("EF.CardAccess ASN1 root object: ${rootObj.runtimeType}");

    List elements;
    if (rootObj is ASN1Set) {
      elements = rootObj.elements!;
    } else if (rootObj is ASN1Sequence) {
      elements = rootObj.elements!;
    } else {
      throw EfParseError(
          "EF.CardAccess: Unexpected ASN1 root type: ${rootObj.runtimeType}");
    }

    // there are 2 structures of EF.CardAccess but second one is not required
    // - PaceInfo
    // - PACEDomainParameterInfo

    // if (set.elements == null || set.elements!.length < 1) {
    //   _log.error("Invalid structure of EF.CardAccess. More than one element in set.");
    //   throw EfParseError("Invalid structure of EF.CardAccess. More than one element in set.");
    // }

    // if (set.elements![0] is! ASN1Sequence ){
    //   _log.error("Invalid structure of EF.CardAccess. First element in set is not ASN1Sequence.");
    //   throw EfParseError("Invalid structure of EF.CardAccess. First element in set is not ASN1Sequence.");
    // }

    // PaceInfo pi = PaceInfo(content: set.elements![0] as ASN1Sequence);
    // _log.info("PaceInfo parsed.");

    // _log.sdDebug("PaceInfo: $pi");

    // paceInfo = pi;

    // Walk all elements in the set
    for (var el in elements!) {
      if (el is ASN1Sequence) {
        // Check first element: should be ASN1ObjectIdentifier and match a known PACE OID
        if (el.elements != null &&
            el.elements!.isNotEmpty &&
            el.elements![0] is ASN1ObjectIdentifier) {
          String oid = (el.elements![0] as ASN1ObjectIdentifier)
                  .objectIdentifierAsString ??
              '';
          // List of supported OIDs, or check with your protocol OID table
          if (ASN1ObjectIdentifierType.instance
              .hasOIDWithIdentifierString(identifierString: oid)) {
            PaceInfo pi = PaceInfo(content: el);
            paceInfo = pi; // Save only the first valid PACEInfo you find
            _log.info("PaceInfo parsed and saved for protocol OID: $oid");
            // Optionally: break; // Only one PACEInfo is allowed!
          } else {
            _log.warning(
                "Skipping ASN1Sequence with unknown protocol OID: $oid");
          }
        } else {
          _log.warning(
              "Skipping ASN1Sequence: first element is not OID or empty.");
        }
      } else if (el.tag == 0x87 || el.tag == 0x88) {
        // Context-specific CA references
        if (paceInfo != null) {
          var bytes = el.valueBytes != null
              ? el.valueBytes!
              : Uint8List(
                  0); // You may need to extract the value properly depending on the ASN1 parser
          if (el.tag == 0x87) {
            paceInfo!.certificationAuthorityReference = bytes;
            _log.info(
                "Found certificationAuthorityReference (0x87): ${bytes.hex()}");
          } else {
            paceInfo!.certificationAuthorityReference2 = bytes;
            _log.info(
                "Found certificationAuthorityReference2 (0x88): ${bytes.hex()}");
          }
        }
      } else {
        _log.warning("Unknown element in EF.CardAccess SET: tag=${el.tag}");
      }
    }

    _log.severe(
        "PaceInfo substruct has been saved to efcardaccess member ( paceInfo )");

    //TODO: parse PACEDomainParameterInfo(9303 p11, 9.2.1)
    /*
      PACEDomainParameterInfo ::= SEQUENCE {
        protocol OBJECT IDENTIFIER(
        id-PACE-DH-GM |
        id-PACE-ECDH-GM |
        id-PACE-DH-IM |
        id-PACE-ECDH-IM |
        id-PACE-ECDH-CAM),
        domainParameter AlgorithmIdentifier,
        parameterId INTEGER OPTIONAL
      }
     */

    /*String paceOID = "id-PACE-ECDH-GM-AES-CBC-CMAC-128"; //0.4.0.127.0.7.2.2.4.2.2
    int parameterSpec = 2;
    PaceMappingType paceMappingType = PaceMappingType.GM;
    String aggrementAlgorithm = "ECDH";
    String cipherAlgorithm = "AES";
    String digestAlgorithm = "SHA-1";
    int keyLength = 128;
    String mrzKey = "PB1777140590020743305304";

    //List<int> buf = utf8.encode(mrzKey);
    Uint8List buf = Uint8List.fromList(utf8.encode(mrzKey));
    Digest sha1 = Digest("SHA-1");
    List<int> sha1Bytes = sha1.process(buf);
    String sha1Hex = sha1Bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

    var smskg = SecureMessagingSessionKeyGenerator();
    var key = await smskg.deriveKey(keySeed: hash, cipherAlgName: cipherAlg, keyLength: keyLength, nonce: null, mode: SecureMessagingSessionKeyDerivationMode.PACE_MODE, paceKeyReference: paceKeyType);
    return key;*/
  }
}
