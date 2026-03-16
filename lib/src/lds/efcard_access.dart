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

    try {
      _parseStandard(content);
    } catch (e) {
      _log.warning(
          "Standard ASN1 parsing of EF.CardAccess failed: $e");
      _log.info("Attempting fallback byte-level parsing...");
      _parseFallback(content);
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

  // ═══════════════════════════════════════════════════════════════════════
  // Standard ASN1 parser (original logic)
  // ═══════════════════════════════════════════════════════════════════════

  void _parseStandard(Uint8List content) {
    var parser = ASN1Parser(content);
    if (!parser.hasNext()) {
      throw EfParseError(
          "Invalid structure of EF.CardAccess. No data to parse.");
    }

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

    for (var el in elements) {
      if (el is ASN1Sequence) {
        if (el.elements != null &&
            el.elements!.isNotEmpty &&
            el.elements![0] is ASN1ObjectIdentifier) {
          String oid = (el.elements![0] as ASN1ObjectIdentifier)
                  .objectIdentifierAsString ??
              '';
          if (ASN1ObjectIdentifierType.instance
              .hasOIDWithIdentifierString(identifierString: oid)) {
            PaceInfo pi = PaceInfo(content: el);
            paceInfo = pi;
            _log.info("PaceInfo parsed and saved for protocol OID: $oid");
          } else {
            _log.warning(
                "Skipping ASN1Sequence with unknown protocol OID: $oid");
          }
        } else {
          _log.warning(
              "Skipping ASN1Sequence: first element is not OID or empty.");
        }
      } else if (el.tag == 0x87 || el.tag == 0x88) {
        if (paceInfo != null) {
          var bytes = el.valueBytes != null
              ? el.valueBytes!
              : Uint8List(0);
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
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Fallback byte-level parser for cards with broken ASN1 encoding
  // ═══════════════════════════════════════════════════════════════════════

  /// Scans raw EF.CardAccess bytes for PACE OID patterns and extracts
  /// protocol parameters manually.  This handles cards whose PACEInfo
  /// SEQUENCE has an off-by-one length bug (stray parameterId byte falls
  /// outside the SEQUENCE boundary) or non-standard OID encoding.
  void _parseFallback(Uint8List content) {
    // BSI TR-03110 PACE OIDs all contain: 7f 00 07 02 02 04
    // (encodes arc values 127.0.7.2.2.4 = bsi-de protocols pace)
    const paceMarker = [0x7f, 0x00, 0x07, 0x02, 0x02, 0x04];

    for (int i = 6; i < content.length - paceMarker.length; i++) {
      bool match = true;
      for (int j = 0; j < paceMarker.length; j++) {
        if (content[i + j] != paceMarker[j]) {
          match = false;
          break;
        }
      }
      if (!match) continue;

      // Found the PACE marker at position i.
      // Back up to find the OID tag (0x06) and its length byte.
      int oidTagPos = -1;
      for (int k = i - 1; k >= 0 && k >= i - 6; k--) {
        if (content[k] == 0x06 && k + 1 < content.length) {
          int oidLen = content[k + 1];
          // The OID value must reach past our marker position
          if (k + 2 + oidLen > i && k + 2 + oidLen <= content.length) {
            oidTagPos = k;
            break;
          }
        }
      }
      if (oidTagPos < 0) continue;

      int oidLen = content[oidTagPos + 1];
      Uint8List oidValueBytes =
          content.sublist(oidTagPos + 2, oidTagPos + 2 + oidLen);
      String oidStr = _decodeOidBytes(oidValueBytes);
      _log.info("Fallback: found PACE-like OID at offset $oidTagPos: $oidStr");

      // Check if this OID is registered (standard or our non-standard entry)
      if (!ASN1ObjectIdentifierType.instance
          .hasOIDWithIdentifierString(identifierString: oidStr)) {
        _log.warning("Fallback: OID '$oidStr' not in known PACE OIDs");
        continue;
      }

      // Walk bytes after the OID using a simple TLV scanner to find
      // INTEGER values for version and parameterId.
      int searchStart = oidTagPos + 2 + oidLen;
      int searchEnd = (searchStart + 30).clamp(0, content.length);
      int? version;
      int? parameterId;
      int pos = searchStart;

      while (pos < searchEnd - 2) {
        int tag = content[pos];
        if (pos + 1 >= content.length) break;
        int len = content[pos + 1];

        if (tag == 0x02 && len == 0x01 && pos + 2 < content.length) {
          // INTEGER with length 1
          int val = content[pos + 2];
          if (version == null) {
            version = val;
          } else if (parameterId == null) {
            parameterId = val;
          }
          pos += 3;
        } else if (tag == 0x04 && len > 0 && len < 20 &&
            pos + 2 + len <= content.length) {
          // OCTET STRING (may be a mis-encoded version field) — skip it
          pos += 2 + len;
        } else if (tag == 0x30 || tag == 0x31) {
          // Hit a SEQUENCE or SET — we've left the PACEInfo area
          break;
        } else {
          // Stray or unknown byte — skip 1
          pos += 1;
        }
      }

      // Default version to 2 per BSI TR-03110 spec
      if (version == null || version != 2) {
        _log.info(
            "Fallback: version=$version (expected 2), defaulting to 2");
        version = 2;
      }

      if (parameterId == null) {
        _log.warning(
            "Fallback: parameterId not found near OID $oidStr, skipping");
        continue;
      }

      _log.info("Fallback: extracted OID=$oidStr version=$version "
          "parameterId=$parameterId");

      // Build a corrected PACEInfo SEQUENCE from the extracted values
      // and parse it through the normal PaceInfo constructor.
      try {
        final seqContent = <int>[
          0x06, oidValueBytes.length, ...oidValueBytes,
          0x02, 0x01, version,
          0x02, 0x01, parameterId,
        ];
        final seqBytes =
            Uint8List.fromList([0x30, seqContent.length, ...seqContent]);

        final seqParser = ASN1Parser(seqBytes);
        final seq = seqParser.nextObject() as ASN1Sequence;
        paceInfo = PaceInfo(content: seq);
        _log.info("Fallback: PaceInfo created successfully "
            "(OID=$oidStr, parameterId=$parameterId)");
        return; // success — stop searching
      } catch (e2) {
        _log.warning(
            "Fallback: PaceInfo creation failed for OID $oidStr: $e2");
        continue;
      }
    }

    _log.warning(
        "Fallback: no usable PACE info found in EF.CardAccess raw bytes");
  }

  /// Decode DER-encoded OID value bytes into a dot-separated string.
  /// E.g. [0x04, 0x03, 0x00, 0x7f, ...] → "0.4.3.0.127...."
  static String _decodeOidBytes(Uint8List bytes) {
    if (bytes.isEmpty) return '';
    final components = <int>[];
    // First byte encodes two arcs: value = c1*40 + c2
    components.add(bytes[0] ~/ 40);
    components.add(bytes[0] % 40);
    // Remaining bytes use base-128 with high-bit continuation
    int value = 0;
    for (int i = 1; i < bytes.length; i++) {
      if (bytes[i] & 0x80 != 0) {
        value = (value << 7) | (bytes[i] & 0x7f);
      } else {
        value = (value << 7) | bytes[i];
        components.add(value);
        value = 0;
      }
    }
    return components.join('.');
  }
}
