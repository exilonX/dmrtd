// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/com/com_provider.dart';
import 'package:dmrtd/src/lds/tlv.dart';
import 'package:dmrtd/src/proto/pin_verifier.dart';
import 'package:dmrtd/src/utils.dart';
import 'package:logging/logging.dart';

import 'command_apdu.dart';
import 'iso7816.dart';
import 'response_apdu.dart';
import 'sm.dart';

class ICCError implements Exception {
  final String message;
  final StatusWord sw;
  final Uint8List? data;
  ICCError(this.message, this.sw, this.data);
  @override
  String toString() => 'ICC Error: $message $sw';
}

/// Defines ISO/IEC-7816 ICC API interface to send commands and receive data.
class ICC {
  final ComProvider _com;
  final _log = Logger("icc");
  SecureMessaging? sm;

  ICC(this._com);

  /// Can throw [ComProviderError].
  Future<void> connect() async {
    return await _com.connect();
  }

  /// Can throw [ComProviderError].
  Future<void> disconnect() async {
    return await _com.disconnect();
  }

  bool isConnected() {
    return _com.isConnected();
  }

  /// Sends EXTERNAL AUTHENTICATE command to ICC.
  /// ICC should return it's computed authentication data.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> externalAuthenticate(
      {required Uint8List data,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    print('APDU: ' +
        [cla, ISO7816_INS.EXTERNAL_AUTHENTICATE, 0x00, 0x00, data.length]
            .map((x) => x.toRadixString(16).padLeft(2, '0'))
            .join(' ') +
        ' ' +
        data.hex());
    print('Data length: ${data.length}');

    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.EXTERNAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("External authenticate failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  //start of pace protocol

  /// Sends SET 'AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION' command to ICC.
  /// ICC if it is ready returns (90 00) or not ready (not 90 00) - throws exception.
  /// Can throw [ICCError] or [ComProviderError].
  Future<bool> setAT(
      {required Uint8List data,
      int ne = 0,
      int cla = ISO7816_CLA.NO_SM}) async {
    _log.sdVerbose(
        "Sending SET 'AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION' command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.MANAGE_SECURITY_ENVIRONMENT,
        p1: 0xc1,
        p2: 0xa4,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError(
          "Authentication template failed", rapdu.status, rapdu.data);
    }
    return true;
  }

  /// Sends GENERAL AUTHENTICATE - step 1 command to ICC.
  /// ICC should return dynamic authentication data (with encrypted nonce in it).
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> generalAuthenticatePACEstep1(
      {required Uint8List data,
      int ne = 256,
      int cla = ISO7816_CLA.COMMAND_CHAINING}) async {
    //4.4.4.2 GENERAL AUTHENTICATE
    _log.sdVerbose("Sending GENERAL AUTHENTICATE - step 1 command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("General authentication template (step 1) failed",
          rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends GENERAL AUTHENTICATE - step 2 or 3' command to ICC.
  /// ICC should return dynamic authentication data (with encrypted nonce in it).
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> generalAuthenticatePACEstep2and3(
      {required Uint8List data,
      int ne = 256,
      int cla = ISO7816_CLA.COMMAND_CHAINING}) async {
    //4.4.4.2 GENERAL AUTHENTICATE
    _log.sdVerbose("Sending GENERAL AUTHENTICATE - step 2 or 3' command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("General authentication template (step 2 or 3) failed",
          rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends GENERAL AUTHENTICATE - step 4' command to ICC.
  /// ICC should return dynamic authentication data (with encrypted nonce in it).
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> generalAuthenticatePACEstep4(
      {required Uint8List data,
      int ne = 256,
      int cla = ISO7816_CLA.NO_SM}) async {
    //4.4.4.2 GENERAL AUTHENTICATE
    _log.sdVerbose("Sending GENERAL AUTHENTICATE - step 4' command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: data));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("General authentication template (step 4) failed",
          rapdu.status, rapdu.data);
    }
    return rapdu.data;
  }

  //end of pace protocol

  /// Sends INTERNAL AUTHENTICATE command to ICC.
  /// ICC should return it's computed authentication data.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> internalAuthenticate(
      {required Uint8List data,
      int p1 = 0x00,
      int p2 = 0x00,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.INTERNAL_AUTHENTICATE,
        p1: p1,
        p2: p2,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("Internal authenticate failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends GET CHALLENGE command to ICC and ICC should return
  /// [challengeLength] long challenge.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> getChallenge(
      {required int challengeLength, int cla = ISO7816_CLA.NO_SM}) async {
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.GET_CHALLENGE,
        p1: 0x00,
        p2: 0x00,
        ne: challengeLength));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("Get challenge failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends READ BINARY command to ICC.
  /// It returns [ne] long chunk of data at [offset].
  /// Max [offset] can be 32 766. [ne] must not overlap offset 32 767.
  /// Can throw [ICCError] if R-APDU returns no data and error status or [ComProviderError].
  ///
  /// Note: Use [readBinaryExt] to read data chunks at offsets greater than 32 767.
  Future<ResponseAPDU> readBinary(
      {required int offset,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    if (offset > 32766) {
      throw ArgumentError.value(
          offset, null, "Max read binary offset can be 32 767 bytes");
    }

    Uint8List rawOffset = Utils.intToBin(offset, minLen: 2);
    final p1 = rawOffset[0];
    final p2 = rawOffset[1];

    return await _readBinary(CommandAPDU(
        cla: cla, ins: ISO7816_INS.READ_BINARY, p1: p1, p2: p2, ne: ne));
  }

  /// Sends READ BINARY command to ICC.
  /// It returns file's [ne] long chunk of data at [offset].
  /// File is identified by [sfi].
  /// Max [offset] can be 255.
  /// Can throw [ICCError] if R-APDU returns no data and error status or [ComProviderError].
  Future<ResponseAPDU> readBinaryBySFI(
      {required int sfi,
      required int offset,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    if (offset > 255) {
      throw ArgumentError.value(
          offset, null, "readBinaryBySFI: Max offset can be 256 bytes");
    }
    if ((sfi & 0x80) == 0) {
      // bit 8 must be set
      throw ArgumentError.value(
          offset, null, "readBinaryBySFI: Invalid SFI identifier");
    }

    return await _readBinary(CommandAPDU(
        cla: cla, ins: ISO7816_INS.READ_BINARY, p1: sfi, p2: offset, ne: ne));
  }

  /// Sends Extended READ BINARY (odd ins 'B1') command to ICC.
  /// It returns [ne] long chunk of data at [offset].
  /// [offset] can be greater than 32 767.
  /// Can throw [ICCError] if R-APDU returns no data and error status or [ComProviderError].
  Future<ResponseAPDU> readBinaryExt(
      {required int offset,
      required int ne,
      int cla = ISO7816_CLA.NO_SM}) async {
    // Returned data will be encoded in BER-TLV with tag 0x53.
    // We add additional bytes to ne for this extra data.
    final enNeLen = TLV.encodeLength(ne).length;
    final addBytes = 1 /*byte = tag*/ + enNeLen;
    ne = ne <= 256 ? min(256, ne + addBytes) : ne + addBytes;

    final data = TLV.encodeIntValue(0x54, offset);
    final rapdu = await _readBinary(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.READ_BINARY_EXT,
        p1: 0x00,
        p2: 0x00,
        data: data,
        ne: ne));

    final rtlv = TLV.fromBytes(rapdu.data!);
    if (rtlv.tag != 0x53) {
      throw ICCError(
          "readBinaryExt failed. Received invalid BER-TLV encoded data with tag=0x${rtlv.tag.hex()}, expected tag=0x53",
          rapdu.status,
          rapdu.data);
    }
    return ResponseAPDU(rapdu.status, rtlv.value);
  }

  /// Sends SELECT FILE command to ICC.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFile(
      {required int p1,
      required int p2,
      int cla = ISO7816_CLA.NO_SM,
      Uint8List? data,
      int ne = 0}) async {
    final rapdu = await _transceive(CommandAPDU(
        cla: cla,
        ins: ISO7816_INS.SELECT_FILE,
        p1: p1,
        p2: p2,
        data: data,
        ne: ne));
    if (rapdu.status != StatusWord.success) {
      throw ICCError("Select File failed", rapdu.status, rapdu.data);
    }
    return rapdu.data;
  }

  /// Selects MF, DF or EF by file ID.
  /// If [fileId] is null, then MF is selected.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFileById(
      {required Uint8List fileId,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla, p1: ISO97816_SelectFileP1.byID, p2: p2, data: fileId, ne: ne);
  }

  /// Selects child DF by [childDF] ID.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectChildDF(
      {required Uint8List childDF,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla,
        p1: ISO97816_SelectFileP1.byChildDFID,
        p2: p2,
        data: childDF,
        ne: ne);
  }

  /// Selects EF under current DF by [efId].
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectEF(
      {required Uint8List efId,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla, p1: ISO97816_SelectFileP1.byEFID, p2: p2, data: efId, ne: ne);
  }

  /// Selects parent DF under current DF.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectParentDF(
      {int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0}) async {
    return await selectFile(
        cla: cla, p1: ISO97816_SelectFileP1.parentDF, p2: p2, ne: ne);
  }

  /// Selects file by DF name
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFileByDFName(
      {required Uint8List dfName,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    return await selectFile(
        cla: cla,
        p1: ISO97816_SelectFileP1.byDFName,
        p2: p2,
        data: dfName,
        ne: ne);
  }

  /// Selects file by [path].
  /// If [fromMF] is true, then file is selected by [path] starting from MF, otherwise from currentDF.
  /// [path] must not include MF/Current DF ID.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFileByPath(
      {required Uint8List path,
      required bool fromMF,
      int p2 = 0,
      int cla = ISO7816_CLA.NO_SM,
      int ne = 0}) async {
    final p1 = fromMF
        ? ISO97816_SelectFileP1.byPathFromMF
        : ISO97816_SelectFileP1.byPath;
    return await selectFile(cla: cla, p1: p1, p2: p2, data: path, ne: ne);
  }

  /// Can throw [ICCError] if no data is received SW is error
  Future<ResponseAPDU> _readBinary(final CommandAPDU cmd) async {
    assert(cmd.ins == ISO7816_INS.READ_BINARY_EXT ||
        cmd.ins == ISO7816_INS.READ_BINARY);

    final rapdu = await _transceive(cmd);
    if ((rapdu.data?.isEmpty ?? true) && rapdu.status.isError()) {
      // Should probably happen on Le errors (0x6700, 0x6CXX) and SM errors (0x6987 & 0x6988) are received.
      throw ICCError("Read binary failed", rapdu.status, rapdu.data);
    }
    return rapdu;
  }

  Future<ResponseAPDU> _transceive(final CommandAPDU cmd) async {
    _log.debug("Transceiving to ICC: $cmd");
    final rawCmd = _wrap(cmd).toBytes();

    _log.debug(
        "Sending ${rawCmd.length} byte(s) to ICC: data='${rawCmd.hex()}'");
    Uint8List rawResp = await _com.transceive(rawCmd);
    _log.debug("Received ${rawResp.length} byte(s) from ICC");
    _log.sdDebug(" data='${rawResp.hex()}'");

    final rapdu = _unwrap(ResponseAPDU.fromBytes(rawResp));
    _log.debug(
        "Received response from ICC: ${rapdu.status} data_len=${rapdu.data?.length ?? 0}");
    _log.sdDebug(" data=${rapdu.data?.hex()}");
    return rapdu;
  }

  CommandAPDU _wrap(final CommandAPDU cmd) {
    if (sm != null) {
      return sm!.protect(cmd);
    }
    return cmd;
  }

  ResponseAPDU _unwrap(final ResponseAPDU resp) {
    if (sm != null) {
      return sm!.unprotect(resp);
    }
    return resp;
  }

  /// Sends a full CommandAPDU and returns the ResponseAPDU.
  ///
  /// This is the primary method for sending commands to the card, as it
  /// automatically handles Secure Messaging (wrapping/unwrapping) if a
  /// session is active. It also provides a central point for status word error handling.
  ///
  /// Throws [ICCError] if the card returns any non-success status word.
  Future<ResponseAPDU> transceiveApdu(CommandAPDU apdu) async {
    // This logic is based on the private _transceive, but is made public
    // and self-contained for generic use.
    _log.debug("Transceiving to ICC: $apdu");

    // 1. Protect the APDU with Secure Messaging, if active.
    final cmdToSend = sm?.protect(apdu) ?? apdu;
    final rawCmd = cmdToSend.toBytes();

    _log.debug(
        "Sending ${rawCmd.length} byte(s) to ICC: data='${rawCmd.hex()}'");
    final rawResp = await _com.transceive(rawCmd);
    _log.debug("Received ${rawResp.length} byte(s) from ICC");

    // 2. Unprotect the response, if Secure Messaging is active.
    final rapdu = sm != null
        ? sm!.unprotect(ResponseAPDU.fromBytes(rawResp))
        : ResponseAPDU.fromBytes(rawResp);

    _log.debug(
        "Received response from ICC: ${rapdu.status} data_len=${rapdu.data?.length ?? 0}");
    _log.sdDebug(" data=${rapdu.data?.hex()}");

    // 3. Centralized error check.
    if (rapdu.status.isError()) {
      throw ICCError("APDU command failed", rapdu.status, rapdu.data);
    }
    return rapdu;
  }

  /// Verifies a user-provided PIN against the card.
  ///
  /// Constructs and sends a VERIFY APDU command and interprets the specific
  /// status word responses related to PIN authentication.
  ///
  /// [pin]: The PIN string. Must be 1-12 characters.
  /// [pinRef]: The P2 parameter identifying the PIN. Defaults to 0x03 from the trace.
  /// Throws [PinVerificationFailedException] or [PinPermanentlyBlockedException] on failure.
  /// Throws [ICCError] for other unexpected card errors.
  Future<void> verifyPinSM(String pin, {int pinRef = 0x03}) async {
    if (pin.isEmpty) throw ArgumentError('PIN cannot be empty');
    final bytes = utf8.encode(pin);
    if (bytes.length > 12)
      throw ArgumentError('PIN must be 12 characters or less');

    final padded = Uint8List(12)..fillRange(0, 12, 0xFF);
    padded.setRange(0, bytes.length, bytes);

    final apdu = CommandAPDU(
      cla: ISO7816_CLA.NO_SM,
      ins: ISO7816_INS.VERIFY,
      p1: 0x00,
      p2: pinRef,
      data: padded,
    );

    try {
      // Use the new generic method. It will throw an ICCError on any non-9000 status.
      await transceiveApdu(apdu);
      // If we get here, the status was 9000 (success), so we just return.
    } on ICCError catch (e) {
      // The command failed. Now we interpret the specific error code.
      final status = e.sw;

      if (status.sw1 == StatusWord.authenticationFailed.sw1) {
        // 0x63
        final retries = status.sw2 & 0x0F;
        if (retries == 0) {
          throw PinPermanentlyBlockedException();
        } else {
          throw PinVerificationFailedException(retries);
        }
      }

      if (status.sw1 == 0x69 && status.sw2 == 0x83) {
        // 0x6983: Auth method blocked
        throw PinPermanentlyBlockedException();
      }

      // For any other error, re-throw the original, unhandled ICCError.
      rethrow;
    }
  }

  /// Initiates the T=1 protocol with the card by sending a Protocol and Parameter Selection (PPS) request.
  /// This is a low-level command that must be sent before many application-level APDUs.
  /// It replicates the behavior seen in Frames 517-524 of the successful Wireshark trace.
  /// This does NOT establish a secure channel.
  Future<void> initiateT1Protocol() async {
    _log.info("Initiating T=1 protocol with PPS command...");
    // The PPS command is not a standard APDU and is sent to the communication provider directly.
    // Command: FF 11 96 78
    //   FF: PPS
    //   11: PPSS (indicates PPS1 is present)
    //   96: PPS1 (T=1, Fi=9, Di=6)
    //   78: PCK (Checksum)
    final ppsCommand = Uint8List.fromList([0xFF, 0x11, 0x96, 0x78]);

    try {
      // We send this directly through the ComProvider, as it's not an APDU
      // and must not be wrapped by Secure Messaging.
      final ppsResponse = await _com.transceive(ppsCommand);
      _log.info("PPS response received: ${ppsResponse.hex()}");

      // A valid PPS response should echo the command minus the PPSS byte.
      // We can add more robust checking here if needed, but for now, we'll
      // assume success if no exception is thrown.

      // The log also shows a SetParameters CCID command, but this is handled by
      // the reader/driver level and is not something we need to send from the app.
      _log.info("T=1 protocol initiated successfully.");
    } catch (e) {
      _log.severe("Failed to initiate T=1 protocol via PPS: $e");
      rethrow;
    }
  }

  /// Performs a direct PIN authentication and reads specified data files by replicating a known-good trace.
  /// This flow bypasses any high-level BAC/PACE logic and sends raw APDUs.
  /// It is designed for the specific Romanian eID profile observed.
  ///
  /// Throws [ICCError] for any card communication errors.
  /// Throws [PinVerificationFailedException] or [PinPermanentlyBlockedException] on PIN failure.
  Future<Map<int, Uint8List>> directPinAuthAndRead(
      String pin, List<int> filesToRead) async {
    final Map<int, Uint8List> readResults = {};

    // Use the raw communication provider to ensure no other logic interferes.
    final com = _com;

    // =======================================================================
    // STEP 1: PROPRIETARY MSE:SET COMMAND (from Frame 525)
    // This is the first command after protocol negotiation.
    // =======================================================================
    _log.info("Step 1/5: Sending proprietary MSE:SET command...");
    var apdu = CommandAPDU(cla: 0x00, ins: 0xC1, p1: 0x01, p2: 0xFE, ne: 62);
    var rawResp = await com.transceive(apdu.toBytes());
    var rapdu = ResponseAPDU.fromBytes(rawResp);
    if (rapdu.status.isError()) {
      throw ICCError("Proprietary MSE:SET (0xC1) command failed", rapdu.status,
          rapdu.data);
    }
    _log.info(
        "Proprietary MSE:SET successful. Response data: ${rapdu.data?.hex()}");

    // =======================================================================
    // STEP 2: SELECT eID APPLICATION (from Frame 529)
    // =======================================================================
    _log.info("Step 2/5: Selecting main eID application...");
    final aid = Uint8List.fromList(
        [0xA0, 0x00, 0x00, 0x03, 0x97, 0x43, 0x49, 0x44, 0x5F, 0x01, 0x00]);
    apdu = CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: aid);
    rawResp = await com.transceive(apdu.toBytes());
    rapdu = ResponseAPDU.fromBytes(rawResp);
    if (rapdu.status.isError()) {
      throw ICCError(
          "Failed to select eID application", rapdu.status, rapdu.data);
    }
    _log.info("eID Application selected successfully.");

    // =======================================================================
    // STEP 3: PREREQUISITE 'GET DATA' COMMAND (from Frame 533)
    // =======================================================================
    _log.info("Step 3/5: Sending prerequisite GET DATA command...");
    apdu = CommandAPDU(cla: 0x00, ins: 0xCA, p1: 0x7F, p2: 0x68, ne: 0);
    rawResp = await com.transceive(apdu.toBytes());
    rapdu = ResponseAPDU.fromBytes(rawResp);
    if (rapdu.status.isError()) {
      throw ICCError(
          "Prerequisite GET DATA command failed", rapdu.status, rapdu.data);
    }
    _log.info("Prerequisite command successful.");

    // =======================================================================
    // STEP 4: VERIFY PIN (from Frame 2933)
    // =======================================================================
    _log.info("Step 4/5: Verifying PIN...");
    final paddedPin = Uint8List(12)..fillRange(0, 12, 0xFF);
    final pinBytes = utf8.encode(pin);
    paddedPin.setRange(0, pinBytes.length, pinBytes);
    apdu =
        CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x03, data: paddedPin);
    rawResp = await com.transceive(apdu.toBytes());
    rapdu = ResponseAPDU.fromBytes(rawResp);

    if (rapdu.status.sw1 == 0x63) {
      final retries = rapdu.status.sw2 & 0x0F;
      if (retries == 0) throw PinPermanentlyBlockedException();
      throw PinVerificationFailedException(retries);
    }
    if (rapdu.status.sw1 == 0x69 && rapdu.status.sw2 == 0x83) {
      throw PinPermanentlyBlockedException();
    }
    if (rapdu.status.isError()) {
      throw ICCError("PIN verification failed", rapdu.status, rapdu.data);
    }
    _log.info("PIN Verification successful!");

    // =======================================================================
    // STEP 5: READ SENSITIVE DATA FILES
    // =======================================================================
    _log.info("Step 5/5: Reading sensitive data files...");
    for (final fileId in filesToRead) {
      final fileIdBytes = Uint8List(2)
        ..buffer.asByteData().setUint16(0, fileId, Endian.big);
      _log.info(
          "Reading file 0x${fileId.toRadixString(16).padLeft(4, '0')}...");

      apdu = CommandAPDU(
          cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: fileIdBytes);
      rawResp = await com.transceive(apdu.toBytes());
      if (ResponseAPDU.fromBytes(rawResp).status.isError()) {
        _log.warning(
            "Could not select file 0x${fileId.toRadixString(16)}: ${ResponseAPDU.fromBytes(rawResp).status}. Skipping.");
        continue;
      }

      final fileDataBuilder = BytesBuilder();
      int offset = 0;
      while (true) {
        apdu = CommandAPDU(
            cla: 0x00,
            ins: 0xB0,
            p1: (offset >> 8) & 0xFF,
            p2: offset & 0xFF,
            ne: 256);
        rawResp = await com.transceive(apdu.toBytes());
        rapdu = ResponseAPDU.fromBytes(rawResp);

        if (rapdu.data != null && rapdu.data!.isNotEmpty) {
          fileDataBuilder.add(rapdu.data!);
          offset += rapdu.data!.length;
        }

        if (rapdu.status == StatusWord.success) {
          break;
        }
        if (rapdu.status.sw1 == 0x62 && rapdu.status.sw2 == 0x82) {
          break;
        }
        if (rapdu.status.isError()) {
          throw ICCError("Failed to read file 0x${fileId.toRadixString(16)}",
              rapdu.status, rapdu.data);
        }
      }

      readResults[fileId] = fileDataBuilder.toBytes();
      _log.info(
          "Successfully read ${readResults[fileId]!.length} bytes from file 0x${fileId.toRadixString(16)}");
    }

    return readResults;
  }

  Future<void> verifyPinRaw(String pin, {int pinRef = 0x03}) async {
    if (pin.isEmpty) throw ArgumentError('PIN cannot be empty');
    final bytes = utf8.encode(pin);
    if (bytes.length > 12) {
      throw ArgumentError('PIN must be 12 characters or less');
    }

    final padded = Uint8List(12)..fillRange(0, 12, 0xFF);
    padded.setRange(0, bytes.length, bytes);

    final apdu = CommandAPDU(
      cla: ISO7816_CLA.NO_SM, // This should be 0x00
      ins: ISO7816_INS.VERIFY,
      p1: 0x00,
      p2: pinRef,
      data: padded,
    );

    _log.debug("Sending VERIFY command without SM wrapping: $apdu");
    final rawCmd = apdu.toBytes();

    _log.debug(
        "Sending ${rawCmd.length} byte(s) to ICC: data='${rawCmd.hex()}'");
    final rawResp = await _com.transceive(rawCmd);
    _log.debug("Received ${rawResp.length} byte(s) from ICC");

    final rapdu = ResponseAPDU.fromBytes(rawResp);
    _log.debug("Received response from ICC: ${rapdu.status}");

    // Now we must handle the status word checks manually.
    final status = rapdu.status;
    if (status == StatusWord.success) {
      // Success!
      return;
    }

    // Handle specific PIN failure codes
    if (status.sw1 == StatusWord.authenticationFailed.sw1) {
      // 0x63
      final retries = status.sw2 & 0x0F;
      if (retries == 0) {
        throw PinPermanentlyBlockedException();
      } else {
        throw PinVerificationFailedException(retries);
      }
    }

    if (status.sw1 == 0x69 && status.sw2 == 0x83) {
      // 0x6983: Auth method blocked
      throw PinPermanentlyBlockedException();
    }

    // For any other failure, throw a generic ICCError.
    throw ICCError('PIN verification failed', status, rapdu.data);
  }
}
