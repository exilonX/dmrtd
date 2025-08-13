// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
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

    ASN1Object rootObj;
    try {
      // Step 1: Use the library's own robust TLV decoder to find the main object.
      // This avoids the strict parser failing on the raw byte stream.
      final mainTlv = TLV.decode(content);
      _log.info(
          "EF.CardAccess Root TLV: Tag=${mainTlv.tag.value.toRadixString(16)}, Length=${mainTlv.encodedLen}");

      // Step 2: Now, use the strict ASN.1 parser on the *value* of that object.
      var parser = ASN1Parser(mainTlv.value);
      if (!parser.hasNext()) {
        throw EfParseError(
            "Invalid structure of EF.CardAccess. No data to parse inside root TLV.");
      }
      rootObj = parser.nextObject();
      _log.info("EF.CardAccess ASN1 root object: ${rootObj.runtimeType}");
    } catch (e) {
      _log.severe("Failed to parse EF.CardAccess structure: $e");
      throw EfParseError("Failed to parse EF.CardAccess structure");
    }

    // --- The rest of your original parsing logic remains THE SAME ---

    List<ASN1Object> elements;
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
            // We only need one valid PACEInfo, so we can stop.
            break;
          } else {
            _log.warning(
                "Skipping ASN1Sequence with unknown protocol OID: $oid");
          }
        } else {
          _log.warning(
              "Skipping ASN1Sequence: first element is not OID or empty.");
        }
      } else {
        _log.warning("Unknown element in EF.CardAccess SET: tag=${el.tag}");
      }
    }

    if (paceInfo == null) {
      throw EfParseError("No valid PACE information found in EF.CardAccess");
    }

    _log.severe(
        "PaceInfo substruct has been saved to efcardaccess member ( paceInfo )");
  }
}
