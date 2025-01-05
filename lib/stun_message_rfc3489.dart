import 'package:bit_buffer/bit_buffer.dart';
import 'package:stun/stun_message.dart';

// 11.2  Message Attributes
//
//    After the header are 0 or more attributes.  Each attribute is TLV
//    encoded, with a 16 bit type, 16 bit length, and variable value:
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |         Type                  |            Length             |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                             Value                             ....
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The following types are defined:
//
//    0x0001: MAPPED-ADDRESS
//    0x0002: RESPONSE-ADDRESS
//    0x0003: CHANGE-REQUEST
//    0x0004: SOURCE-ADDRESS
//    0x0005: CHANGED-ADDRESS
//    0x0006: USERNAME
//    0x0007: PASSWORD
//    0x0008: MESSAGE-INTEGRITY
//    0x0009: ERROR-CODE
//    0x000a: UNKNOWN-ATTRIBUTES
//    0x000b: REFLECTED-FROM
//
//    To allow future revisions of this specification to add new attributes
//    if needed, the attribute space is divided into optional and mandatory
//    ones.  Attributes with values greater than 0x7fff are optional, which
//    means that the message can be processed by the client or server even
//    though the attribute is not understood.  Attributes with values less
//    than or equal to 0x7fff are mandatory to understand, which means that
//    the client or server cannot process the message unless it understands
//    the attribute.
//
//    The MESSAGE-INTEGRITY attribute MUST be the last attribute within a
//    message.  Any attributes that are known, but are not supposed to be
//    present in a message (MAPPED-ADDRESS in a request, for example) MUST
//    be ignored.
//
//    Table 2 indicates which attributes are present in which messages.  An
//    M indicates that inclusion of the attribute in the message is
//    mandatory, O means its optional, C means it's conditional based on
//    some other aspect of the message, and N/A means that the attribute is
//    not applicable to that message type.
//
//
//
//
//
// Rosenberg, et al.           Standards Track                    [Page 26]
//
// RFC 3489                          STUN                        March 2003
//
//
//                                          Binding  Shared  Shared  Shared
//                        Binding  Binding  Error    Secret  Secret  Secret
//    Att.                Req.     Resp.    Resp.    Req.    Resp.   Error
//                                                                   Resp.
//    _____________________________________________________________________
//    MAPPED-ADDRESS      N/A      M        N/A      N/A     N/A     N/A
//    RESPONSE-ADDRESS    O        N/A      N/A      N/A     N/A     N/A
//    CHANGE-REQUEST      O        N/A      N/A      N/A     N/A     N/A
//    SOURCE-ADDRESS      N/A      M        N/A      N/A     N/A     N/A
//    CHANGED-ADDRESS     N/A      M        N/A      N/A     N/A     N/A
//    USERNAME            O        N/A      N/A      N/A     M       N/A
//    PASSWORD            N/A      N/A      N/A      N/A     M       N/A
//    MESSAGE-INTEGRITY   O        O        N/A      N/A     N/A     N/A
//    ERROR-CODE          N/A      N/A      M        N/A     N/A     M
//    UNKNOWN-ATTRIBUTES  N/A      N/A      C        N/A     N/A     C
//    REFLECTED-FROM      N/A      C        N/A      N/A     N/A     N/A
//
//    Table 2: Summary of Attributes
//
//    The length refers to the length of the value element, expressed as an
//    unsigned integral number of bytes.
StunAttributes? resolveAttribute(BitBufferReader reader, int type, int length) {
  switch (type) {
    case StunAttributes.TYPE_MAPPED_ADDRESS:
      return MappedAddressAttribute.form(reader, type, length);

    case StunAttributes.TYPE_RESPONSE_ADDRESS:
      return ResponseAddress.form(reader, type, length);

    case StunAttributes.TYPE_CHANGE_ADDRESS:
      return ChangeRequest.form(reader, type, length);

    case StunAttributes.TYPE_SOURCE_ADDRESS:
      return SourceAddress.form(reader, type, length);

    case StunAttributes.TYPE_CHANGED_ADDRESS:
      return ChangedAddress.form(reader, type, length);

    case StunAttributes.TYPE_USERNAME:
      return Username.form(reader, type, length);

    case StunAttributes.TYPE_PASSWORD:
      return Password.form(reader, type, length);

    case StunAttributes.TYPE_MESSAGE_INTEGRITY:
      return MessageIntegrity.form(reader, type, length);

    case StunAttributes.TYPE_ERROR_CODE:
      return ErrorCodeAttribute.form(reader, type, length);

    case StunAttributes.TYPE_UNKNOWN_ATTRIBUTES:
      return UnknownAttributes.form(reader, type, length);

    case StunAttributes.TYPE_REFLECTED_FROM:
      return ReflectedFrom.form(reader, type, length);

    default:
      return null;
  }
}

// 11.2.1 MAPPED-ADDRESS
//
//    The MAPPED-ADDRESS attribute indicates the mapped IP address and
//    port.  It consists of an eight bit address family, and a sixteen bit
//    port, followed by a fixed length value representing the IP address.
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |x x x x x x x x|    Family     |           Port                |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                             Address                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The port is a network byte ordered representation of the mapped port.
//    The address family is always 0x01, corresponding to IPv4.  The first
//    8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
//    aligning parameters on natural boundaries.  The IPv4 address is 32
//    bits.
class MappedAddressAttribute extends StunAttributes {
  static const int FAMILY_IPV4 = 0x01;
  static const int FAMILY_IPV6 = 0x02;
  static final FAMILY_STRINGS = {
    FAMILY_IPV4: "IPv4",
    FAMILY_IPV6: "IPv6",
  };

  String? get familyDisplayName => FAMILY_STRINGS[family];

  int head;
  int family;
  int port;
  int address;

  MappedAddressAttribute(super.type, super.length, this.head, this.family, this.port, this.address);

  factory MappedAddressAttribute.form(BitBufferReader reader, int type, int length) {
    assert(length == 8 || length == 20);
    int head = reader.getUnsignedInt(binaryDigits: 8);
    int family = reader.getUnsignedInt(binaryDigits: 8);
    int port = reader.getUnsignedInt(binaryDigits: 16);
    int address;
    switch (family) {
      case FAMILY_IPV4:
        address = reader.getUnsignedInt(binaryDigits: 32);
      case FAMILY_IPV6:
        address = reader.getUnsignedInt(binaryDigits: 128);
      default:
        throw ArgumentError();
    }
    return MappedAddressAttribute(type, length, head, family, port, address);
  }

  String? get addressDisplayName {
    BitBuffer bitBuffer = BitBuffer();
    BitBufferWriter writer = bitBuffer.writer();
    BitBufferReader reader = bitBuffer.reader();
    switch (family) {
      case FAMILY_IPV4:
        writer.putUnsignedInt(address, binaryDigits: 32, order: BitOrder.MSBFirst);
        return "${reader.getUnsignedInt(binaryDigits: 8, order: BitOrder.MSBFirst)}.${reader.getUnsignedInt(binaryDigits: 8, order: BitOrder.MSBFirst)}.${reader.getUnsignedInt(binaryDigits: 8, order: BitOrder.MSBFirst)}.${reader.getUnsignedInt(binaryDigits: 8, order: BitOrder.MSBFirst)}";
      case FAMILY_IPV6:
        writer.putUnsignedInt(address, binaryDigits: 128, order: BitOrder.MSBFirst);
        return "";
      default:
        return "";
    }
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}: ${addressDisplayName}:${port}
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    Reserved: ${head}
    Protocol Family: ${familyDisplayName} (0x0$family)
    Port: ${port}
    IP: ${addressDisplayName}
  """;
  }
}

// 11.2.2 RESPONSE-ADDRESS
//
//    The RESPONSE-ADDRESS attribute indicates where the response to a
//    Binding Request should be sent.  Its syntax is identical to MAPPED-
//    ADDRESS.
typedef ResponseAddress = MappedAddressAttribute;

// 11.2.3  CHANGED-ADDRESS
//
//    The CHANGED-ADDRESS attribute indicates the IP address and port where
//    responses would have been sent from if the "change IP" and "change
//    port" flags had been set in the CHANGE-REQUEST attribute of the
//    Binding Request.  The attribute is always present in a Binding
//    Response, independent of the value of the flags.  Its syntax is
//    identical to MAPPED-ADDRESS.
typedef ChangedAddress = MappedAddressAttribute;

// 11.2.4 CHANGE-REQUEST
//
//    The CHANGE-REQUEST attribute is used by the client to request that
//    the server use a different address and/or port when sending the
//    response.  The attribute is 32 bits long, although only two bits (A
//    and B) are used:
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The meaning of the flags is:
//
//    A: This is the "change IP" flag.  If true, it requests the server
//       to send the Binding Response with a different IP address than the
//       one the Binding Request was received on.
//
//    B: This is the "change port" flag.  If true, it requests the
//       server to send the Binding Response with a different port than the
//       one the Binding Request was received on.
class ChangeRequest extends StunAttributes {
  bool flagChangeIp;

  bool flagChangePort;

  ChangeRequest(super.type, super.length, this.flagChangeIp, this.flagChangePort);

  factory ChangeRequest.form(BitBufferReader reader, int type, int length) {
    int flag = reader.getUnsignedInt(binaryDigits: 32);
    int flagChangeIp = flag & 0x02;
    int flagChangePort = flag & 0x04;
    return ChangeRequest(type, length, flagChangeIp != 0, flagChangePort != 0);
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}:
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    flagChangeIp: ${flagChangeIp}
    flagChangePort: ${flagChangePort}
  """;
  }
}

// 11.2.5 SOURCE-ADDRESS
//
//    The SOURCE-ADDRESS attribute is present in Binding Responses.  It
//    indicates the source IP address and port that the server is sending
//    the response from.  Its syntax is identical to that of MAPPED-
//    ADDRESS.
typedef SourceAddress = MappedAddressAttribute;

// 11.2.6 USERNAME
//
//    The USERNAME attribute is used for message integrity.  It serves as a
//    means to identify the shared secret used in the message integrity
//    check.  The USERNAME is always present in a Shared Secret Response,
//    along with the PASSWORD.  It is optionally present in a Binding
//    Request when message integrity is used.
//
//    The value of USERNAME is a variable length opaque value.  Its length
//    MUST be a multiple of 4 (measured in bytes) in order to guarantee
//    alignment of attributes on word boundaries.
class Username extends StunAttributes {
  String username;

  Username(super.type, super.length, this.username);

  factory Username.form(BitBufferReader reader, int type, int length) {
    String username = reader.getStringByUtf8(length * 8, binaryDigits: 8, order: BitOrder.MSBFirst);
    return Username(type, length, username);
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}:
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    username: ${username}
  """;
  }
}

// 11.2.7 PASSWORD
//
//    The PASSWORD attribute is used in Shared Secret Responses.  It is
//    always present in a Shared Secret Response, along with the USERNAME.
//
//    The value of PASSWORD is a variable length value that is to be used
//    as a shared secret.  Its length MUST be a multiple of 4 (measured in
//    bytes) in order to guarantee alignment of attributes on word
//    boundaries.
class Password extends StunAttributes {
  String password;

  Password(super.type, super.length, this.password);

  factory Password.form(BitBufferReader reader, int type, int length) {
    String password = reader.getStringByUtf8(length * 8, binaryDigits: 8, order: BitOrder.MSBFirst);
    return Password(type, length, password);
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}:
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    password: ${password}
  """;
  }
}

// 11.2.8 MESSAGE-INTEGRITY
//
//    The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [13] of the
//    STUN message.  It can be present in Binding Requests or Binding
//    Responses.  Since it uses the SHA1 hash, the HMAC will be 20 bytes.
//    The text used as input to HMAC is the STUN message, including the
//    header, up to and including the attribute preceding the MESSAGE-
//    INTEGRITY attribute. That text is then padded with zeroes so as to be
//    a multiple of 64 bytes.  As a result, the MESSAGE-INTEGRITY attribute
//    MUST be the last attribute in any STUN message.  The key used as
//    input to HMAC depends on the context.
class MessageIntegrity extends StunAttributes {
  List<int> key;

  MessageIntegrity(super.type, super.length, this.key);

  factory MessageIntegrity.form(BitBufferReader reader, int type, int length) {
    List<int> hmacSha1Digest = reader.getIntList(length * 8, binaryDigits: 8, order: BitOrder.MSBFirst);
    return MessageIntegrity(type, length, hmacSha1Digest);
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}:
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    key: ${key}
  """;
  }
}

// 11.2.9 ERROR-CODE
//
//    The ERROR-CODE attribute is present in the Binding Error Response and
//    Shared Secret Error Response.  It is a numeric value in the range of
//    100 to 699 plus a textual reason phrase encoded in UTF-8, and is
//    consistent in its code assignments and semantics with SIP [10] and
//    HTTP [15].  The reason phrase is meant for user consumption, and can
//    be anything appropriate for the response code.  The lengths of the
//    reason phrases MUST be a multiple of 4 (measured in bytes).  This can
//    be accomplished by added spaces to the end of the text, if necessary.
//    Recommended reason phrases for the defined response codes are
//    presented below.
//
//    To facilitate processing, the class of the error code (the hundreds
//    digit) is encoded separately from the rest of the code.
//
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                   0                     |Class|     Number    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |      Reason Phrase (variable)                                ..
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The class represents the hundreds digit of the response code.  The
//    value MUST be between 1 and 6.  The number represents the response
//    code modulo 100, and its value MUST be between 0 and 99.
//
//    The following response codes, along with their recommended reason
//    phrases (in brackets) are defined at this time:
//
//    400 (Bad Request): The request was malformed.  The client should not
//         retry the request without modification from the previous
//         attempt.
//
//    401 (Unauthorized): The Binding Request did not contain a MESSAGE-
//         INTEGRITY attribute.
//
//    420 (Unknown Attribute): The server did not understand a mandatory
//         attribute in the request.
//
//    430 (Stale Credentials): The Binding Request did contain a MESSAGE-
//         INTEGRITY attribute, but it used a shared secret that has
//         expired.  The client should obtain a new shared secret and try
//         again.
//
//    431 (Integrity Check Failure): The Binding Request contained a
//         MESSAGE-INTEGRITY attribute, but the HMAC failed verification.
//         This could be a sign of a potential attack, or client
//         implementation error.
//
//    432 (Missing Username): The Binding Request contained a MESSAGE-
//         INTEGRITY attribute, but not a USERNAME attribute.  Both must be
//         present for integrity checks.
//
//    433 (Use TLS): The Shared Secret request has to be sent over TLS, but
//         was not received over TLS.
//
//    500 (Server Error): The server has suffered a temporary error. The
//         client should try again.
//
//    600 (Global Failure:) The server is refusing to fulfill the request.
//         The client should not retry.
//
class ErrorCodeAttribute extends StunAttributes {
  int code;
  String reason;

  ErrorCodeAttribute(super.type, super.length, this.code, this.reason);

  factory ErrorCodeAttribute.form(BitBufferReader reader, int type, int length) {
    int head = reader.getUnsignedInt(binaryDigits: 21);
    int clz = reader.getUnsignedInt(binaryDigits: 3);
    int number = reader.getUnsignedInt(binaryDigits: 8);
    int code = clz * 100 + number;
    int lenReason = length * 8 - 21 - 3 - 8;
    String reason = reader.getStringByUtf8(lenReason, binaryDigits: 8, order: BitOrder.MSBFirst);
    return ErrorCodeAttribute(type, length, code, reason);
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}:
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    code: ${code}
    reason: ${reason}
  """;
  }
}

// 11.2.10 UNKNOWN-ATTRIBUTES
//
//    The UNKNOWN-ATTRIBUTES attribute is present only in a Binding Error
//    Response or Shared Secret Error Response when the response code in
//    the ERROR-CODE attribute is 420.
//
//    The attribute contains a list of 16 bit values, each of which
//    represents an attribute type that was not understood by the server.
//    If the number of unknown attributes is an odd number, one of the
//    attributes MUST be repeated in the list, so that the total length of
//    the list is a multiple of 4 bytes.
//
//    0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |      Attribute 1 Type           |     Attribute 2 Type        |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |      Attribute 3 Type           |     Attribute 4 Type    ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
class UnknownAttributes extends StunAttributes {
  List<int> types;

  UnknownAttributes(super.type, super.length, this.types);

  factory UnknownAttributes.form(BitBufferReader reader, int type, int length) {
    List<int> types = [];
    for (int i = 0; i < length; i += 16) {
      int type = reader.getUnsignedInt(binaryDigits: 16);
      types.add(type);
    }
    return UnknownAttributes(type, length, types);
  }

  @override
  String toString() {
    return """
  ${typeDisplayName}:
    Attribute Type: ${typeDisplayName}
    Attribute Length: ${length}
    types: ${types}
  """;
  }
}

// 11.2.11 REFLECTED-FROM
//
//    The REFLECTED-FROM attribute is present only in Binding Responses,
//    when the Binding Request contained a RESPONSE-ADDRESS attribute.  The
//    attribute contains the identity (in terms of IP address) of the
//    source where the request came from.  Its purpose is to provide
//    traceability, so that a STUN server cannot be used as a reflector for
//    denial-of-service attacks.
//
//    Its syntax is identical to the MAPPED-ADDRESS attribute.
typedef ReflectedFrom = MappedAddressAttribute;
