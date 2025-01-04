import 'dart:typed_data';

import 'package:bit_buffer/bit_buffer.dart';
import 'package:stun/stun_message_rfc3489.dart' as rfc3489;
import 'package:stun/stun_message_rfc5389.dart' as rfc5389;

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

  factory StunMessage.form(Uint8List data) {
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
            StunProtocol stunProtocol = hasMagicCookie ? StunProtocol.RFC5389 : StunProtocol.RFC3489;
            int transactionId = reader.getUnsignedInt(binaryDigits: 96);
            //todo assert transactionId
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
        case StunProtocol.RFC5389:
          StunAttributes? attribute = rfc5389.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          }
        case StunProtocol.RFC3489:
          StunAttributes? attribute = rfc3489.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          }
        case StunProtocol.MIX:
          StunAttributes? attribute = rfc5389.resolveAttribute(reader, attributeType, attributeLength);
          if (attribute != null) {
            attributes.add(attribute);
          } else {
            StunAttributes? attribute = rfc3489.resolveAttribute(reader, attributeType, attributeLength);
            if (attribute != null) {
              attributes.add(attribute);
            }
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

//15.  STUN Attributes
//
//    After the STUN header are zero or more attributes.  Each attribute
//    MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
//    Each STUN attribute MUST end on a 32-bit boundary.  As mentioned
//    above, all fields in an attribute are transmitted most significant
//    bit first.
//
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |         Type                  |            Length             |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                         Value (variable)                ....
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                     Figure 4: Format of STUN Attributes
//
//    The value in the length field MUST contain the length of the Value
//    part of the attribute, prior to padding, measured in bytes.  Since
//    STUN aligns attributes on 32-bit boundaries, attributes whose content
//    is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
//    padding so that its value contains a multiple of 4 bytes.  The
//    padding bits are ignored, and may be any value.
//
//    Any attribute type MAY appear more than once in a STUN message.
//    Unless specified otherwise, the order of appearance is significant:
//    only the first occurrence needs to be processed by a receiver, and
//    any duplicates MAY be ignored by a receiver.
//
//    To allow future revisions of this specification to add new attributes
//    if needed, the attribute space is divided into two ranges.
//    Attributes with type values between 0x0000 and 0x7FFF are
//    comprehension-required attributes, which means that the STUN agent
//    cannot successfully process the message unless it understands the
//    attribute.  Attributes with type values between 0x8000 and 0xFFFF are
//    comprehension-optional attributes, which means that those attributes
//    can be ignored by the STUN agent if it does not understand them.
//
//    The set of STUN attribute types is maintained by IANA.  The initial
//    set defined by this specification is found in Section 18.2.
//
//    The rest of this section describes the format of the various
//    attributes defined in this specification.
abstract class StunAttributes {
  //18.2.  STUN Attribute Registry
  //
  //    A STUN Attribute type is a hex number in the range 0x0000 - 0xFFFF.
  //    STUN attribute types in the range 0x0000 - 0x7FFF are considered
  //    comprehension-required; STUN attribute types in the range 0x8000 -
  //    0xFFFF are considered comprehension-optional.  A STUN agent handles
  //    unknown comprehension-required and comprehension-optional attributes
  //    differently.
  //
  //    The initial STUN Attributes types are:
  //
  //    Comprehension-required range (0x0000-0x7FFF):
  //      0x0000: (Reserved)
  //      0x0001: MAPPED-ADDRESS
  //      0x0002: (Reserved; was RESPONSE-ADDRESS)
  //      0x0003: (Reserved; was CHANGE-ADDRESS)
  //      0x0004: (Reserved; was SOURCE-ADDRESS)
  //      0x0005: (Reserved; was CHANGED-ADDRESS)
  //      0x0006: USERNAME
  //      0x0007: (Reserved; was PASSWORD)
  //      0x0008: MESSAGE-INTEGRITY
  //      0x0009: ERROR-CODE
  //      0x000A: UNKNOWN-ATTRIBUTES
  //      0x000B: (Reserved; was REFLECTED-FROM)
  //      0x0014: REALM
  //      0x0015: NONCE
  //      0x0020: XOR-MAPPED-ADDRESS
  //
  //    Comprehension-optional range (0x8000-0xFFFF)
  //      0x8022: SOFTWARE
  //      0x8023: ALTERNATE-SERVER
  //      0x8028: FINGERPRINT
  //
  //    STUN Attribute types in the first half of the comprehension-required
  //    range (0x0000 - 0x3FFF) and in the first half of the comprehension-
  //    optional range (0x8000 - 0xBFFF) are assigned by IETF Review
  //    [RFC5226].  STUN Attribute types in the second half of the
  //    comprehension-required range (0x4000 - 0x7FFF) and in the second half
  //    of the comprehension-optional range (0xC000 - 0xFFFF) are assigned by
  //    Designated Expert [RFC5226].  The responsibility of the expert is to
  //    verify that the selected codepoint(s) are not in use, and that the
  //    request is not for an abnormally large number of codepoints.
  //    Technical review of the extension itself is outside the scope of the
  //    designated expert responsibility.
  static const int TYPE_RESERVED = 0x0000;
  static const int TYPE_MAPPED_ADDRESS = 0x0001;
  static const int TYPE_RESPONSE_ADDRESS = 0x0002;
  static const int TYPE_CHANGE_ADDRESS = 0x0003;
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
  static const int TYPE_SOFTWARE = 0x8022;
  static const int TYPE_ALTERNATE_SERVER = 0x8023;
  static const int TYPE_FINGERPRINT = 0x8028;
  static final Map<int, String> TYPE_STRINGS = {
    TYPE_RESERVED: "RESERVED",
    TYPE_MAPPED_ADDRESS: "MAPPED-ADDRESS",
    TYPE_RESPONSE_ADDRESS: "RESPONSE-ADDRESS",
    TYPE_CHANGE_ADDRESS: "CHANGE-ADDRESS",
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
    TYPE_SOFTWARE: "SOFTWARE",
    TYPE_ALTERNATE_SERVER: "ALTERNATE-SERVER",
    TYPE_FINGERPRINT: "FINGERPRINT",
  };

  int type;
  int length;

  StunAttributes(this.type, this.length);

  String? get typeDisplayName => TYPE_STRINGS[type];

  @override
  String toString();
}
