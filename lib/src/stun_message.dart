/*
 * Copyright (C) 2025 halifox
 *
 * This file is part of dart_stun.
 *
 * dart_stun is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * dart_stun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with dart_stun. If not, see <http://www.gnu.org/licenses/>.
 */

import 'dart:typed_data';

import 'package:bit_buffer/bit_buffer.dart';
import 'package:stun/src/stun_message_rfc3489.dart' as rfc3489;
import 'package:stun/src/stun_message_rfc5389.dart' as rfc5389;
import 'package:stun/src/stun_message_rfc5780.dart' as rfc5780;

//6.  STUN Message Structure
//
//    STUN messages are encoded in binary using network-oriented format
//    (most significant byte or octet first, also commonly known as big-
//    endian).  The transmission order is described in detail in Appendix B
//    of RFC 791 [RFC0791].  Unless otherwise noted, numeric constants are
//    in decimal (base 10).
//
//    All STUN messages MUST start with a 20-byte header followed by zero
//    or more Attributes.  The STUN header contains a STUN message type,
//    magic cookie, transaction ID, and message length.
//
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |0 0|     STUN Message Type     |         Message Length        |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                         Magic Cookie                          |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                                                               |
//       |                     Transaction ID (96 bits)                  |
//       |                                                               |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                   Figure 2: Format of STUN Message Header
//
//    The most significant 2 bits of every STUN message MUST be zeroes.
//    This can be used to differentiate STUN packets from other protocols
//    when STUN is multiplexed with other protocols on the same port.
//
//    The message type defines the message class (request, success
//    response, failure response, or indication) and the message method
//    (the primary function) of the STUN message.  Although there are four
//    message classes, there are only two types of transactions in STUN:
//    request/response transactions (which consist of a request message and
//    a response message) and indication transactions (which consist of a
//    single indication message).  Response classes are split into error
//    and success responses to aid in quickly processing the STUN message.
//
//    The message type field is decomposed further into the following
//    structure:
//
//                         0                 1
//                         2  3  4 5 6 7 8 9 0 1 2 3 4 5
//
//                        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//                        |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
//                        |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
//                        +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                 Figure 3: Format of STUN Message Type Field
//
//    Here the bits in the message type field are shown as most significant
//    (M11) through least significant (M0).  M11 through M0 represent a 12-
//    bit encoding of the method.  C1 and C0 represent a 2-bit encoding of
//    the class.  A class of 0b00 is a request, a class of 0b01 is an
//    indication, a class of 0b10 is a success response, and a class of
//    0b11 is an error response.  This specification defines a single
//    method, Binding.  The method and class are orthogonal, so that for
//    each method, a request, success response, error response, and
//    indication are possible for that method.  Extensions defining new
//    methods MUST indicate which classes are permitted for that method.
//
//    For example, a Binding request has class=0b00 (request) and
//    method=0b000000000001 (Binding) and is encoded into the first 16 bits
//    as 0x0001.  A Binding response has class=0b10 (success response) and
//    method=0b000000000001, and is encoded into the first 16 bits as
//    0x0101.
//
//       Note: This unfortunate encoding is due to assignment of values in
//       [RFC3489] that did not consider encoding Indications, Success, and
//       Errors using bit fields.
//
//    The magic cookie field MUST contain the fixed value 0x2112A442 in
//    network byte order.  In RFC 3489 [RFC3489], this field was part of
//    the transaction ID; placing the magic cookie in this location allows
//    a server to detect if the client will understand certain attributes
//    that were added in this revised specification.  In addition, it aids
//    in distinguishing STUN packets from packets of other protocols when
//    STUN is multiplexed with those other protocols on the same port.
//
//    The transaction ID is a 96-bit identifier, used to uniquely identify
//    STUN transactions.  For request/response transactions, the
//    transaction ID is chosen by the STUN client for the request and
//    echoed by the server in the response.  For indications, it is chosen
//    by the agent sending the indication.  It primarily serves to
//    correlate requests with responses, though it also plays a small role
//    in helping to prevent certain types of attacks.  The server also uses
//    the transaction ID as a key to identify each transaction uniquely
//    across all clients.  As such, the transaction ID MUST be uniformly
//    and randomly chosen from the interval 0 .. 2**96-1, and SHOULD be
//    cryptographically random.  Resends of the same request reuse the same
//    transaction ID, but the client MUST choose a new transaction ID for
//    new transactions unless the new request is bit-wise identical to the
//    previous request and sent from the same transport address to the same
//    IP address.  Success and error responses MUST carry the same
//    transaction ID as their corresponding request.  When an agent is
//    acting as a STUN server and STUN client on the same port, the
//    transaction IDs in requests sent by the agent have no relationship to
//    the transaction IDs in requests received by the agent.
//
//    The message length MUST contain the size, in bytes, of the message
//    not including the 20-byte STUN header.  Since all STUN attributes are
//    padded to a multiple of 4 bytes, the last 2 bits of this field are
//    always zero.  This provides another way to distinguish STUN packets
//    from packets of other protocols.
//
//    Following the STUN fixed portion of the header are zero or more
//    attributes.  Each attribute is TLV (Type-Length-Value) encoded.  The
//    details of the encoding, and of the attributes themselves are given
//    in Section 15.

enum StunProtocol {
  RFC3489,
  RFC5389,
  RFC5780,
  MIX,
}

class StunMessage {
  int head;
  int type;
  int length;
  int cookie;
  int transactionId;
  StunProtocol stunProtocol;

  List<StunAttributes> attributes;

  static const int HEAD = 0x00;

  static const int CLASS_REQUEST = 0x000;
  static const int CLASS_RESPONSE_SUCCESS = 0x100;
  static const int CLASS_RESPONSE_ERROR = 0x010;
  static const int CLASS_INDICATION = 0x110;
  static const int CLASS_MASK = 0x110;

  static const int METHOD_RESERVED = 0x000;
  static const int METHOD_BINDING = 0x001;
  static const int METHOD_SHARED_SECRET = 0x002;
  static const int METHOD_MASK = 0x3EEF;

  static final Map<int, String> TYPE_STRINGS = {
    METHOD_RESERVED | CLASS_REQUEST: "Reserve Request",
    METHOD_RESERVED | CLASS_RESPONSE_SUCCESS: "Reserve Success Response",
    METHOD_RESERVED | CLASS_RESPONSE_ERROR: "Reserve Error Response",
    METHOD_RESERVED | CLASS_INDICATION: "Reserve Indication",
    METHOD_BINDING | CLASS_REQUEST: "Binding Request",
    METHOD_BINDING | CLASS_RESPONSE_SUCCESS: "Binding Success Response",
    METHOD_BINDING | CLASS_RESPONSE_ERROR: "Binding Error Response",
    METHOD_BINDING | CLASS_INDICATION: "Binding Indication",
    METHOD_SHARED_SECRET | CLASS_REQUEST: "Shared Secret Request",
    METHOD_SHARED_SECRET | CLASS_RESPONSE_SUCCESS: "Shared Secret Success Response",
    METHOD_SHARED_SECRET | CLASS_RESPONSE_ERROR: "Shared Secret Error Response",
    METHOD_SHARED_SECRET | CLASS_INDICATION: "Shared Secret Indication",
  };

  String? get typeDisplayName => TYPE_STRINGS[type];

  static const int MAGIC_COOKIE = 0x2112A442;

  StunMessage(this.head, this.type, this.length, this.cookie, this.transactionId, this.attributes, this.stunProtocol);

  factory StunMessage.form(Uint8List data, StunProtocol stunProtocol) {
    //if error: drop this
    BitBuffer bitBuffer = BitBuffer.formUInt8List(data, order: BitOrder.MSBFirst);
    BitBufferReader reader = bitBuffer.reader();
    int head = reader.getUnsignedInt(binaryDigits: 2);
    assert(head == 0);
    int type = reader.getUnsignedInt(binaryDigits: 14);
    int typeClass = type & CLASS_MASK;
    int typeMethod = type & METHOD_MASK;
    switch (typeClass) {
      case CLASS_REQUEST:
        throw Exception('Invalid class type: CLASS_REQUEST');
      case CLASS_RESPONSE_SUCCESS:
        switch (typeMethod) {
          case METHOD_BINDING:
            int length = reader.getUnsignedInt(binaryDigits: 16);
            //todo assert length
            int cookie = reader.getUnsignedInt(binaryDigits: 32);
            bool hasMagicCookie = cookie == MAGIC_COOKIE;
            int transactionId = reader.getUnsignedInt(binaryDigits: 96);
            List<StunAttributes> attributes = resolveAttributes(reader, stunProtocol);
            //todo assert FINGERPRINT
            return StunMessage(head, type, length, cookie, transactionId, attributes, stunProtocol);
          default:
            throw Exception();
        }
      case CLASS_RESPONSE_ERROR:
        throw Exception('Response Error');
      case CLASS_INDICATION:
        throw Exception('Invalid class type: CLASS_INDICATION');
      default:
        throw Exception();
    }
  }

  static List<StunAttributes> resolveAttributes(BitBufferReader reader, StunProtocol stunProtocol) {
    List<StunAttributes> attributes = [];
    while (reader.remainingSize > 0) {
      int attributeType = reader.getUnsignedInt(binaryDigits: 16);
      int attributeLength = reader.getUnsignedInt(binaryDigits: 16);
      switch (stunProtocol) {
        case StunProtocol.RFC5780:
          StunAttributes? attribute = rfc5780.resolveAttribute(reader, attributeType, attributeLength) ?? //
              rfc5389.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          } else {
            reader.getIntList(attributeLength * 8);
          }

        case StunProtocol.RFC5389:
          StunAttributes? attribute = rfc5389.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          } else {
            reader.getIntList(attributeLength * 8);
          }
        case StunProtocol.RFC3489:
          StunAttributes? attribute = rfc3489.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          } else {
            reader.getIntList(attributeLength * 8);
          }
        case StunProtocol.MIX:
          StunAttributes? attribute = rfc5780.resolveAttribute(reader, attributeType, attributeLength) ?? //
              rfc5389.resolveAttribute(reader, attributeType, attributeLength) ?? //
              rfc3489.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          } else {
            reader.getIntList(attributeLength * 8);
          }
      }
    }
    return attributes;
  }

  Uint8List toUInt8List() {
    BitBuffer bitBuffer = BitBuffer();
    BitBufferWriter writer = bitBuffer.writer();
    writer.putUnsignedInt(head, binaryDigits: 2, order: BitOrder.MSBFirst);
    writer.putUnsignedInt(type, binaryDigits: 14, order: BitOrder.MSBFirst);
    writer.putUnsignedInt(length, binaryDigits: 16, order: BitOrder.MSBFirst);
    writer.putUnsignedInt(cookie, binaryDigits: 32, order: BitOrder.MSBFirst);
    writer.putUnsignedInt(transactionId, binaryDigits: 96, order: BitOrder.MSBFirst);
    Uint8List buffer = bitBuffer.toUInt8List();
    return buffer;
  }

  @override
  String toString() {
    StringBuffer buffer = StringBuffer();
    buffer.writeln('Message Type: 0x${type.toRadixString(16).padLeft(4, '0').toUpperCase()} (${typeDisplayName})');
    buffer.writeln('Message Length: $length');
    buffer.writeln('Message Cookie: 0x${cookie.toRadixString(16).toUpperCase()}');
    buffer.writeln('Message Transaction ID: 0x${transactionId.toRadixString(16).padLeft(24, '0').toUpperCase()}');
    buffer.writeln('Attributes:');
    for (StunAttributes attribute in attributes) {
      buffer.writeln(attribute.toString());
    }

    return buffer.toString();
  }
}

abstract class StunAttributes {
  static const int TYPE_RESERVED = 0x0000;
  static const int TYPE_MAPPED_ADDRESS = 0x0001;
  static const int TYPE_RESPONSE_ADDRESS = 0x0002;
  static const int TYPE_CHANGE_ADDRESS = 0x0003;
  static const int TYPE_CHANGE_REQUEST = 0x0003; // rfc5780
  static const int TYPE_SOURCE_ADDRESS = 0x0004;
  static const int TYPE_CHANGED_ADDRESS = 0x0005;
  static const int TYPE_USERNAME = 0x0006;
  static const int TYPE_PASSWORD = 0x0007;
  static const int TYPE_MESSAGE_INTEGRITY = 0x0008;
  static const int TYPE_ERROR_CODE = 0x0009;
  static const int TYPE_UNKNOWN_ATTRIBUTES = 0x000A;
  static const int TYPE_REFLECTED_FROM = 0x000B;
  static const int TYPE_REALM = 0x0014;
  static const int TYPE_NONCE = 0x0015;
  static const int TYPE_XOR_MAPPED_ADDRESS = 0x0020;
  static const int TYPE_PADDING = 0x0026; // rfc5780
  static const int TYPE_RESPONSE_PORT = 0x0027; // rfc5780

  // Comprehension-optional range (0x8000-0xFFFF):
  static const int TYPE_SOFTWARE = 0x8022;
  static const int TYPE_ALTERNATE_SERVER = 0x8023;
  static const int TYPE_FINGERPRINT = 0x8028;
  static const int TYPE_RESPONSE_ORIGIN = 0x802b; // rfc5780
  static const int TYPE_OTHER_ADDRESS = 0x802c; // rfc5780

  static final Map<int, String> TYPE_STRINGS = {
    TYPE_RESERVED: "RESERVED",
    TYPE_MAPPED_ADDRESS: "MAPPED-ADDRESS",
    TYPE_RESPONSE_ADDRESS: "RESPONSE-ADDRESS",
    TYPE_CHANGE_ADDRESS: "CHANGE-ADDRESS",
    TYPE_CHANGE_REQUEST: "CHANGE-REQUEST",
    TYPE_SOURCE_ADDRESS: "SOURCE-ADDRESS",
    TYPE_CHANGED_ADDRESS: "CHANGED-ADDRESS",
    TYPE_USERNAME: "USERNAME",
    TYPE_PASSWORD: "PASSWORD",
    TYPE_MESSAGE_INTEGRITY: "MESSAGE-INTEGRITY",
    TYPE_ERROR_CODE: "ERROR-CODE",
    TYPE_UNKNOWN_ATTRIBUTES: "UNKNOWN-ATTRIBUTES",
    TYPE_REFLECTED_FROM: "REFLECTED-FROM",
    TYPE_REALM: "REALM",
    TYPE_NONCE: "NONCE",
    TYPE_XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    TYPE_PADDING: "PADDING",
    TYPE_RESPONSE_PORT: "RESPONSE-PORT",
    TYPE_SOFTWARE: "SOFTWARE",
    TYPE_ALTERNATE_SERVER: "ALTERNATE-SERVER",
    TYPE_FINGERPRINT: "FINGERPRINT",
    TYPE_RESPONSE_ORIGIN: "RESPONSE-ORIGIN",
    TYPE_OTHER_ADDRESS: "OTHER-ADDRESS",
  };

  int type;
  int length;

  StunAttributes(this.type, this.length);

  String? get typeDisplayName => "${TYPE_STRINGS[type] ?? "Undefined"}(0x${type.toRadixString(16).padLeft(4, "0")})";

  @override
  String toString() {
    return """
  ${typeDisplayName}: 暂未设置解析规则
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
  """;
  }
}
