import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../common/binary_utils.dart';
import '../common/crypto_utils.dart';
import '../common/exceptions.dart';

const int stunHeaderLength = 20;
const int stunMagicCookie = 0x2112A442;
const int stunFingerprintXor = 0x5354554e;

enum StunProtocol {
  rfc3489,
  rfc5389,
  rfc5780,
}

enum StunMessageClass {
  request,
  indication,
  successResponse,
  errorResponse,
}

enum StunMethod {
  binding(0x0001),
  sharedSecret(0x0002);

  const StunMethod(this.code);

  final int code;
}

enum StunAddressFamily {
  ipv4(0x01),
  ipv6(0x02);

  const StunAddressFamily(this.code);

  final int code;
}

class StunTransportAddress {
  const StunTransportAddress({
    required this.address,
    required this.port,
  });

  final InternetAddress address;
  final int port;

  Uint8List get rawAddress => address.rawAddress;

  StunAddressFamily get family => address.type == InternetAddressType.IPv6
      ? StunAddressFamily.ipv6
      : StunAddressFamily.ipv4;

  @override
  String toString() {
    final host = address.type == InternetAddressType.IPv6
        ? '[${address.address}]'
        : address.address;
    return '$host:$port';
  }

  @override
  bool operator ==(Object other) {
    return other is StunTransportAddress &&
        port == other.port &&
        bytesEqual(rawAddress, other.rawAddress);
  }

  @override
  int get hashCode {
    return Object.hash(
      port,
      Object.hashAll(rawAddress),
    );
  }
}

class StunCredentials {
  const StunCredentials.shortTerm({
    this.username,
    required this.password,
  })  : realm = null,
        nonce = null,
        useLongTerm = false;

  const StunCredentials.longTerm({
    required this.username,
    required this.password,
    required this.realm,
    required this.nonce,
  }) : useLongTerm = true;

  final String? username;
  final String password;
  final String? realm;
  final String? nonce;
  final bool useLongTerm;

  Uint8List integrityKey() {
    if (useLongTerm) {
      final user = username ?? '';
      final realmValue = realm ?? '';
      return md5String('$user:$realmValue:$password');
    }
    return Uint8List.fromList(utf8.encode(password));
  }
}

abstract class StunAttribute {
  const StunAttribute();

  int get type;

  String get name;

  bool get comprehensionRequired => (type & 0x8000) == 0;
}

abstract class StunAddressAttribute extends StunAttribute {
  const StunAddressAttribute(this.value);

  final StunTransportAddress value;

  @override
  String toString() => '$name($value)';
}

class StunMappedAddressAttribute extends StunAddressAttribute {
  const StunMappedAddressAttribute(super.value);

  @override
  int get type => 0x0001;

  @override
  String get name => 'MAPPED-ADDRESS';
}

class StunResponseAddressAttribute extends StunAddressAttribute {
  const StunResponseAddressAttribute(super.value);

  @override
  int get type => 0x0002;

  @override
  String get name => 'RESPONSE-ADDRESS';
}

class StunChangeRequestAttribute extends StunAttribute {
  const StunChangeRequestAttribute({
    this.changeIp = false,
    this.changePort = false,
  });

  final bool changeIp;
  final bool changePort;

  @override
  int get type => 0x0003;

  @override
  String get name => 'CHANGE-REQUEST';

  @override
  String toString() {
    return 'CHANGE-REQUEST(changeIp: $changeIp, changePort: $changePort)';
  }
}

class StunSourceAddressAttribute extends StunAddressAttribute {
  const StunSourceAddressAttribute(super.value);

  @override
  int get type => 0x0004;

  @override
  String get name => 'SOURCE-ADDRESS';
}

class StunChangedAddressAttribute extends StunAddressAttribute {
  const StunChangedAddressAttribute(super.value);

  @override
  int get type => 0x0005;

  @override
  String get name => 'CHANGED-ADDRESS';
}

class StunUsernameAttribute extends StunAttribute {
  const StunUsernameAttribute(this.username);

  final String username;

  @override
  int get type => 0x0006;

  @override
  String get name => 'USERNAME';

  @override
  String toString() => 'USERNAME($username)';
}

class StunPasswordAttribute extends StunAttribute {
  const StunPasswordAttribute(this.password);

  final String password;

  @override
  int get type => 0x0007;

  @override
  String get name => 'PASSWORD';

  @override
  String toString() => 'PASSWORD(***)';
}

class StunMessageIntegrityAttribute extends StunAttribute {
  const StunMessageIntegrityAttribute({this.hmac});

  final Uint8List? hmac;

  @override
  int get type => 0x0008;

  @override
  String get name => 'MESSAGE-INTEGRITY';

  @override
  String toString() {
    return hmac == null ? 'MESSAGE-INTEGRITY(auto)' : 'MESSAGE-INTEGRITY';
  }
}

class StunErrorCodeAttribute extends StunAttribute {
  const StunErrorCodeAttribute({
    required this.code,
    required this.reasonPhrase,
  });

  final int code;
  final String reasonPhrase;

  @override
  int get type => 0x0009;

  @override
  String get name => 'ERROR-CODE';

  @override
  String toString() => 'ERROR-CODE($code $reasonPhrase)';
}

class StunUnknownAttributesAttribute extends StunAttribute {
  const StunUnknownAttributesAttribute(this.attributeTypes);

  final List<int> attributeTypes;

  @override
  int get type => 0x000a;

  @override
  String get name => 'UNKNOWN-ATTRIBUTES';
}

class StunReflectedFromAttribute extends StunAddressAttribute {
  const StunReflectedFromAttribute(super.value);

  @override
  int get type => 0x000b;

  @override
  String get name => 'REFLECTED-FROM';
}

class StunRealmAttribute extends StunAttribute {
  const StunRealmAttribute(this.realm);

  final String realm;

  @override
  int get type => 0x0014;

  @override
  String get name => 'REALM';

  @override
  String toString() => 'REALM($realm)';
}

class StunNonceAttribute extends StunAttribute {
  const StunNonceAttribute(this.nonce);

  final String nonce;

  @override
  int get type => 0x0015;

  @override
  String get name => 'NONCE';

  @override
  String toString() => 'NONCE($nonce)';
}

class StunXorMappedAddressAttribute extends StunAddressAttribute {
  const StunXorMappedAddressAttribute(super.value);

  @override
  int get type => 0x0020;

  @override
  String get name => 'XOR-MAPPED-ADDRESS';
}

class StunPaddingAttribute extends StunAttribute {
  const StunPaddingAttribute(this.value);

  final Uint8List value;

  @override
  int get type => 0x0026;

  @override
  String get name => 'PADDING';

  @override
  String toString() => 'PADDING(${value.length} bytes)';
}

class StunResponsePortAttribute extends StunAttribute {
  const StunResponsePortAttribute(this.port);

  final int port;

  @override
  int get type => 0x0027;

  @override
  String get name => 'RESPONSE-PORT';

  @override
  String toString() => 'RESPONSE-PORT($port)';
}

class StunSoftwareAttribute extends StunAttribute {
  const StunSoftwareAttribute(this.description);

  final String description;

  @override
  int get type => 0x8022;

  @override
  String get name => 'SOFTWARE';

  @override
  String toString() => 'SOFTWARE($description)';
}

class StunAlternateServerAttribute extends StunAddressAttribute {
  const StunAlternateServerAttribute(super.value);

  @override
  int get type => 0x8023;

  @override
  String get name => 'ALTERNATE-SERVER';
}

class StunFingerprintAttribute extends StunAttribute {
  const StunFingerprintAttribute({this.fingerprint});

  final int? fingerprint;

  @override
  int get type => 0x8028;

  @override
  String get name => 'FINGERPRINT';

  @override
  String toString() =>
      fingerprint == null ? 'FINGERPRINT(auto)' : 'FINGERPRINT';
}

class StunResponseOriginAttribute extends StunAddressAttribute {
  const StunResponseOriginAttribute(super.value);

  @override
  int get type => 0x802b;

  @override
  String get name => 'RESPONSE-ORIGIN';
}

class StunOtherAddressAttribute extends StunAddressAttribute {
  const StunOtherAddressAttribute(super.value);

  @override
  int get type => 0x802c;

  @override
  String get name => 'OTHER-ADDRESS';
}

class StunUnknownAttribute extends StunAttribute {
  const StunUnknownAttribute({
    required this.type,
    required this.value,
  });

  @override
  final int type;
  final Uint8List value;

  @override
  String get name => 'UNKNOWN(0x${type.toRadixString(16).padLeft(4, '0')})';

  @override
  String toString() => '$name(${value.length} bytes)';
}

class StunMessage {
  StunMessage({
    required this.method,
    required this.messageClass,
    Uint8List? transactionId,
    List<StunAttribute> attributes = const <StunAttribute>[],
  })  : transactionId = _normalizeTransactionId(
          transactionId ?? generateTransactionId(),
        ),
        attributes = List.unmodifiable(attributes),
        _rawMessage = null,
        _messageIntegrityOffset = null,
        _fingerprintOffset = null;

  StunMessage._decoded({
    required this.method,
    required this.messageClass,
    required this.transactionId,
    required this.attributes,
    required Uint8List rawMessage,
    required int? messageIntegrityOffset,
    required int? fingerprintOffset,
  })  : _rawMessage = rawMessage,
        _messageIntegrityOffset = messageIntegrityOffset,
        _fingerprintOffset = fingerprintOffset;

  final StunMethod method;
  final StunMessageClass messageClass;
  final Uint8List transactionId;
  final List<StunAttribute> attributes;
  final Uint8List? _rawMessage;
  final int? _messageIntegrityOffset;
  final int? _fingerprintOffset;

  bool get isLegacy => !_hasMagicCookie(transactionId);

  int get type => _encodeMessageType(method.code, messageClass);

  static Uint8List generateTransactionId({bool legacy = false}) {
    final bytes = randomBytes(16);
    if (!legacy) {
      writeUint32Into(bytes, 0, stunMagicCookie);
    } else if (_hasMagicCookie(bytes)) {
      bytes[0] ^= 0xff;
    }
    return bytes;
  }

  factory StunMessage.bindingRequest({
    bool legacy = false,
    List<StunAttribute> attributes = const <StunAttribute>[],
  }) {
    return StunMessage(
      method: StunMethod.binding,
      messageClass: StunMessageClass.request,
      transactionId: generateTransactionId(legacy: legacy),
      attributes: attributes,
    );
  }

  factory StunMessage.decode(
    Uint8List bytes, {
    bool validateFingerprint = false,
  }) {
    if (bytes.length < stunHeaderLength) {
      throw const StunParseException('STUN message is shorter than 20 bytes.');
    }
    final messageType = readUint16(bytes, 0);
    if ((messageType & 0xc000) != 0) {
      throw const StunParseException(
        'Top two STUN message type bits must be zero.',
      );
    }
    final bodyLength = readUint16(bytes, 2);
    if (bodyLength % 4 != 0) {
      throw const StunParseException(
        'STUN message length must be a multiple of 4.',
      );
    }
    if (bytes.length < stunHeaderLength + bodyLength) {
      throw const StunParseException(
        'STUN message is truncated compared with the declared length.',
      );
    }

    final transactionId = Uint8List.fromList(bytes.sublist(4, 20));
    final method = _decodeMethod(messageType);
    final messageClass = _decodeClass(messageType);
    final decodedAttributes = <StunAttribute>[];
    var offset = stunHeaderLength;
    int? integrityOffset;
    int? fingerprintOffset;
    while (offset < stunHeaderLength + bodyLength) {
      if (offset + 4 > bytes.length) {
        throw const StunParseException('Attribute header is truncated.');
      }
      final attributeType = readUint16(bytes, offset);
      final attributeLength = readUint16(bytes, offset + 2);
      final valueStart = offset + 4;
      final valueEnd = valueStart + attributeLength;
      if (valueEnd > bytes.length) {
        throw StunParseException(
          'Attribute 0x${attributeType.toRadixString(16)} is truncated.',
        );
      }
      final value = Uint8List.fromList(bytes.sublist(valueStart, valueEnd));
      final attribute = _decodeAttribute(attributeType, value, transactionId);
      decodedAttributes.add(attribute);
      if (attribute is StunMessageIntegrityAttribute) {
        integrityOffset = offset;
      } else if (attribute is StunFingerprintAttribute) {
        fingerprintOffset = offset;
      }
      offset = valueEnd + paddingLength(attributeLength);
    }
    if (offset != stunHeaderLength + bodyLength) {
      throw const StunParseException(
        'STUN attribute padding does not line up with message length.',
      );
    }
    final message = StunMessage._decoded(
      method: method,
      messageClass: messageClass,
      transactionId: transactionId,
      attributes: List.unmodifiable(decodedAttributes),
      rawMessage:
          Uint8List.fromList(bytes.sublist(0, stunHeaderLength + bodyLength)),
      messageIntegrityOffset: integrityOffset,
      fingerprintOffset: fingerprintOffset,
    );
    if (validateFingerprint &&
        message.attribute<StunFingerprintAttribute>() != null &&
        !message.validateFingerprint()) {
      throw const StunProtocolException('STUN fingerprint validation failed.');
    }
    return message;
  }

  T? attribute<T extends StunAttribute>() {
    for (final value in attributes) {
      if (value is T) {
        return value;
      }
    }
    return null;
  }

  List<T> attributesOf<T extends StunAttribute>() {
    return attributes.whereType<T>().toList(growable: false);
  }

  StunMessage copyWith({
    StunMethod? method,
    StunMessageClass? messageClass,
    Uint8List? transactionId,
    List<StunAttribute>? attributes,
  }) {
    return StunMessage(
      method: method ?? this.method,
      messageClass: messageClass ?? this.messageClass,
      transactionId: transactionId ?? this.transactionId,
      attributes: attributes ?? this.attributes,
    );
  }

  Uint8List encode({
    StunCredentials? credentials,
    bool includeFingerprint = false,
    String? software,
  }) {
    final prepared = _prepareAttributes(
      attributes: attributes,
      credentials: credentials,
      includeFingerprint: includeFingerprint,
      software: software,
      transactionId: transactionId,
    );
    final bodyLength = prepared.fold<int>(
      0,
      (sum, element) => sum + 4 + addPadding(element.value).length,
    );
    final builder = BytesBuilder(copy: false);
    writeUint16(builder, type);
    writeUint16(builder, bodyLength);
    builder.add(transactionId);

    int? integrityOffset;
    int? fingerprintOffset;
    for (final encodedAttribute in prepared) {
      final attributeOffset = builder.length;
      writeUint16(builder, encodedAttribute.type);
      writeUint16(builder, encodedAttribute.value.length);
      builder.add(addPadding(encodedAttribute.value));
      if (encodedAttribute.original is StunMessageIntegrityAttribute) {
        integrityOffset = attributeOffset;
      } else if (encodedAttribute.original is StunFingerprintAttribute) {
        fingerprintOffset = attributeOffset;
      }
    }

    final bytes = builder.takeBytes();
    if (integrityOffset != null) {
      final integrityAttribute = prepared.firstWhere(
          (entry) => entry.original is StunMessageIntegrityAttribute);
      final key = credentials?.integrityKey();
      final rawHmac =
          (integrityAttribute.original as StunMessageIntegrityAttribute).hmac;
      final hmacValue = rawHmac ??
          (key == null
              ? throw const StunProtocolException(
                  'MESSAGE-INTEGRITY requires credentials or a raw HMAC value.',
                )
              : _computeMessageIntegrity(bytes, integrityOffset, key));
      bytes.setRange(
        integrityOffset + 4,
        integrityOffset + 24,
        hmacValue,
      );
      writeUint16Into(bytes, 2, bodyLength);
    }
    if (fingerprintOffset != null) {
      final fingerprint = _computeFingerprint(bytes, fingerprintOffset);
      writeUint32Into(bytes, fingerprintOffset + 4, fingerprint);
    }
    return bytes;
  }

  bool validateFingerprint() {
    final raw = _rawMessage;
    final offset = _fingerprintOffset;
    final fingerprintAttribute = this.attribute<StunFingerprintAttribute>();
    if (raw == null ||
        offset == null ||
        fingerprintAttribute?.fingerprint == null) {
      return false;
    }
    return _computeFingerprint(raw, offset) ==
        fingerprintAttribute!.fingerprint;
  }

  bool validateMessageIntegrity(StunCredentials credentials) {
    final raw = _rawMessage;
    final offset = _messageIntegrityOffset;
    final integrityAttribute = this.attribute<StunMessageIntegrityAttribute>();
    if (raw == null || offset == null || integrityAttribute?.hmac == null) {
      return false;
    }
    final expected =
        _computeMessageIntegrity(raw, offset, credentials.integrityKey());
    return bytesEqual(expected, integrityAttribute!.hmac!);
  }

  @override
  String toString() {
    final className = switch (messageClass) {
      StunMessageClass.request => 'request',
      StunMessageClass.indication => 'indication',
      StunMessageClass.successResponse => 'success',
      StunMessageClass.errorResponse => 'error',
    };
    return 'StunMessage(method: ${method.name}, class: $className, '
        'transactionId: ${hexEncode(transactionId)}, attributes: $attributes)';
  }
}

class _EncodedAttribute {
  const _EncodedAttribute({
    required this.type,
    required this.value,
    required this.original,
  });

  final int type;
  final Uint8List value;
  final StunAttribute original;
}

Uint8List _normalizeTransactionId(Uint8List transactionId) {
  if (transactionId.length != 16) {
    throw const StunProtocolException(
      'STUN transaction identifiers must be 16 bytes.',
    );
  }
  return Uint8List.fromList(transactionId);
}

bool _hasMagicCookie(Uint8List transactionId) {
  return readUint32(transactionId, 0) == stunMagicCookie;
}

int _encodeMessageType(int method, StunMessageClass messageClass) {
  var type = 0;
  type |= method & 0x000f;
  type |= (method & 0x0070) << 1;
  type |= (method & 0x0f80) << 2;
  final classBits = switch (messageClass) {
    StunMessageClass.request => 0,
    StunMessageClass.indication => 1,
    StunMessageClass.successResponse => 2,
    StunMessageClass.errorResponse => 3,
  };
  type |= (classBits & 0x01) << 4;
  type |= (classBits & 0x02) << 7;
  return type;
}

StunMethod _decodeMethod(int messageType) {
  final methodCode = (messageType & 0x000f) |
      ((messageType & 0x00e0) >> 1) |
      ((messageType & 0x3e00) >> 2);
  return StunMethod.values.firstWhere(
    (method) => method.code == methodCode,
    orElse: () => throw StunParseException(
      'Unsupported STUN method 0x${methodCode.toRadixString(16)}.',
    ),
  );
}

StunMessageClass _decodeClass(int messageType) {
  final c0 = (messageType >> 4) & 0x01;
  final c1 = (messageType >> 8) & 0x01;
  return switch ((c1 << 1) | c0) {
    0 => StunMessageClass.request,
    1 => StunMessageClass.indication,
    2 => StunMessageClass.successResponse,
    _ => StunMessageClass.errorResponse,
  };
}

List<_EncodedAttribute> _prepareAttributes({
  required List<StunAttribute> attributes,
  required StunCredentials? credentials,
  required bool includeFingerprint,
  required String? software,
  required Uint8List transactionId,
}) {
  final prepared = <StunAttribute>[...attributes];
  if (software != null &&
      !prepared.any((attribute) => attribute is StunSoftwareAttribute)) {
    prepared.add(StunSoftwareAttribute(software));
  }
  if (credentials != null) {
    if (credentials.username != null &&
        !prepared.any((attribute) => attribute is StunUsernameAttribute)) {
      prepared.add(StunUsernameAttribute(credentials.username!));
    }
    if (credentials.useLongTerm &&
        credentials.realm != null &&
        !prepared.any((attribute) => attribute is StunRealmAttribute)) {
      prepared.add(StunRealmAttribute(credentials.realm!));
    }
    if (credentials.useLongTerm &&
        credentials.nonce != null &&
        !prepared.any((attribute) => attribute is StunNonceAttribute)) {
      prepared.add(StunNonceAttribute(credentials.nonce!));
    }
    if (!prepared
        .any((attribute) => attribute is StunMessageIntegrityAttribute)) {
      prepared.add(const StunMessageIntegrityAttribute());
    }
  }
  if (includeFingerprint &&
      !prepared.any((attribute) => attribute is StunFingerprintAttribute)) {
    prepared.add(const StunFingerprintAttribute());
  }

  final regular = <StunAttribute>[];
  StunMessageIntegrityAttribute? integrity;
  StunFingerprintAttribute? fingerprint;
  for (final attribute in prepared) {
    if (attribute is StunMessageIntegrityAttribute) {
      integrity = attribute;
    } else if (attribute is StunFingerprintAttribute) {
      fingerprint = attribute;
    } else {
      regular.add(attribute);
    }
  }

  final ordered = <StunAttribute>[
    ...regular,
    if (integrity != null) integrity,
    if (fingerprint != null) fingerprint,
  ];
  return ordered
      .map(
        (attribute) => _EncodedAttribute(
          type: attribute.type,
          value: _encodeAttributeValue(attribute, transactionId),
          original: attribute,
        ),
      )
      .toList(growable: false);
}

Uint8List _encodeAttributeValue(
  StunAttribute attribute,
  Uint8List transactionId,
) {
  if (attribute is StunAddressAttribute &&
      attribute is! StunXorMappedAddressAttribute) {
    return _encodeAddressValue(attribute.value);
  }
  switch (attribute) {
    case StunXorMappedAddressAttribute value:
      return _encodeXorAddressValue(value.value, transactionId);
    case StunChangeRequestAttribute value:
      final flags = (value.changeIp ? 0x04 : 0) | (value.changePort ? 0x02 : 0);
      final data = ByteData(4)..setUint32(0, flags, Endian.big);
      return data.buffer.asUint8List();
    case StunUsernameAttribute value:
      return Uint8List.fromList(utf8.encode(value.username));
    case StunPasswordAttribute value:
      return Uint8List.fromList(utf8.encode(value.password));
    case StunMessageIntegrityAttribute value:
      return value.hmac == null
          ? Uint8List(20)
          : Uint8List.fromList(value.hmac!);
    case StunErrorCodeAttribute value:
      final builder = BytesBuilder(copy: false);
      builder.add(const <int>[0, 0]);
      final klass = value.code ~/ 100;
      final number = value.code % 100;
      builder.add([klass & 0x07, number]);
      builder.add(utf8.encode(value.reasonPhrase));
      return builder.takeBytes();
    case StunUnknownAttributesAttribute value:
      return uint16ListToBytes(value.attributeTypes);
    case StunRealmAttribute value:
      return Uint8List.fromList(utf8.encode(value.realm));
    case StunNonceAttribute value:
      return Uint8List.fromList(utf8.encode(value.nonce));
    case StunPaddingAttribute value:
      return Uint8List.fromList(value.value);
    case StunResponsePortAttribute value:
      final data = ByteData(4)..setUint16(0, value.port, Endian.big);
      return data.buffer.asUint8List();
    case StunSoftwareAttribute value:
      return Uint8List.fromList(utf8.encode(value.description));
    case StunFingerprintAttribute value:
      final data = ByteData(4)
        ..setUint32(0, value.fingerprint ?? 0, Endian.big);
      return data.buffer.asUint8List();
    case StunUnknownAttribute value:
      return Uint8List.fromList(value.value);
  }
  throw StunProtocolException('Unsupported STUN attribute: ${attribute.name}');
}

Uint8List _encodeAddressValue(StunTransportAddress value) {
  final builder = BytesBuilder(copy: false);
  builder.addByte(0x00);
  builder.addByte(value.family.code);
  writeUint16(builder, value.port);
  builder.add(value.rawAddress);
  return builder.takeBytes();
}

Uint8List _encodeXorAddressValue(
  StunTransportAddress value,
  Uint8List transactionId,
) {
  final encoded = _encodeAddressValue(value);
  final xPort = value.port ^ ((stunMagicCookie >> 16) & 0xffff);
  writeUint16Into(encoded, 2, xPort);
  if (value.family == StunAddressFamily.ipv4) {
    final cookie = ByteData(4)..setUint32(0, stunMagicCookie, Endian.big);
    for (var index = 0; index < 4; index++) {
      encoded[4 + index] = encoded[4 + index] ^ cookie.getUint8(index);
    }
  } else {
    for (var index = 0; index < 16; index++) {
      encoded[4 + index] = encoded[4 + index] ^ transactionId[index];
    }
  }
  return encoded;
}

StunAttribute _decodeAttribute(
  int type,
  Uint8List value,
  Uint8List transactionId,
) {
  switch (type) {
    case 0x0001:
      return StunMappedAddressAttribute(_decodeAddressValue(value));
    case 0x0002:
      return StunResponseAddressAttribute(_decodeAddressValue(value));
    case 0x0003:
      if (value.length < 4) {
        throw const StunParseException('CHANGE-REQUEST is truncated.');
      }
      final flags = readUint32(value, 0);
      return StunChangeRequestAttribute(
        changeIp: (flags & 0x04) != 0,
        changePort: (flags & 0x02) != 0,
      );
    case 0x0004:
      return StunSourceAddressAttribute(_decodeAddressValue(value));
    case 0x0005:
      return StunChangedAddressAttribute(_decodeAddressValue(value));
    case 0x0006:
      return StunUsernameAttribute(utf8.decode(value));
    case 0x0007:
      return StunPasswordAttribute(utf8.decode(value));
    case 0x0008:
      return StunMessageIntegrityAttribute(hmac: Uint8List.fromList(value));
    case 0x0009:
      if (value.length < 4) {
        throw const StunParseException('ERROR-CODE is truncated.');
      }
      final klass = value[2] & 0x07;
      final number = value[3];
      return StunErrorCodeAttribute(
        code: klass * 100 + number,
        reasonPhrase: value.length > 4 ? utf8.decode(value.sublist(4)) : '',
      );
    case 0x000a:
      final attributeTypes = <int>[];
      for (var offset = 0; offset + 1 < value.length; offset += 2) {
        attributeTypes.add(readUint16(value, offset));
      }
      return StunUnknownAttributesAttribute(attributeTypes);
    case 0x000b:
      return StunReflectedFromAttribute(_decodeAddressValue(value));
    case 0x0014:
      return StunRealmAttribute(utf8.decode(value));
    case 0x0015:
      return StunNonceAttribute(utf8.decode(value));
    case 0x0020:
      return StunXorMappedAddressAttribute(
        _decodeXorAddressValue(value, transactionId),
      );
    case 0x0026:
      return StunPaddingAttribute(Uint8List.fromList(value));
    case 0x0027:
      if (value.length < 2) {
        throw const StunParseException('RESPONSE-PORT is truncated.');
      }
      return StunResponsePortAttribute(readUint16(value, 0));
    case 0x8022:
      return StunSoftwareAttribute(utf8.decode(value));
    case 0x8023:
      return StunAlternateServerAttribute(_decodeAddressValue(value));
    case 0x8028:
      if (value.length < 4) {
        throw const StunParseException('FINGERPRINT is truncated.');
      }
      return StunFingerprintAttribute(fingerprint: readUint32(value, 0));
    case 0x802b:
      return StunResponseOriginAttribute(_decodeAddressValue(value));
    case 0x802c:
      return StunOtherAddressAttribute(_decodeAddressValue(value));
    default:
      return StunUnknownAttribute(type: type, value: Uint8List.fromList(value));
  }
}

StunTransportAddress _decodeAddressValue(Uint8List value) {
  if (value.length < 8) {
    throw const StunParseException('STUN address attribute is too short.');
  }
  final family = value[1];
  final port = readUint16(value, 2);
  switch (family) {
    case 0x01:
      return StunTransportAddress(
        address: InternetAddress.fromRawAddress(value.sublist(4, 8)),
        port: port,
      );
    case 0x02:
      if (value.length < 20) {
        throw const StunParseException('IPv6 address attribute is truncated.');
      }
      return StunTransportAddress(
        address: InternetAddress.fromRawAddress(value.sublist(4, 20)),
        port: port,
      );
    default:
      throw StunParseException('Unsupported STUN address family: $family');
  }
}

StunTransportAddress _decodeXorAddressValue(
  Uint8List value,
  Uint8List transactionId,
) {
  if (value.length < 8) {
    throw const StunParseException('XOR address attribute is too short.');
  }
  final family = value[1];
  final xPort = readUint16(value, 2);
  final port = xPort ^ ((stunMagicCookie >> 16) & 0xffff);
  if (family == 0x01) {
    final raw = Uint8List(4);
    final cookie = ByteData(4)..setUint32(0, stunMagicCookie, Endian.big);
    for (var index = 0; index < 4; index++) {
      raw[index] = value[4 + index] ^ cookie.getUint8(index);
    }
    return StunTransportAddress(
      address: InternetAddress.fromRawAddress(raw),
      port: port,
    );
  }
  if (family == 0x02) {
    if (value.length < 20) {
      throw const StunParseException(
          'IPv6 XOR address attribute is truncated.');
    }
    final raw = Uint8List(16);
    for (var index = 0; index < 16; index++) {
      raw[index] = value[4 + index] ^ transactionId[index];
    }
    return StunTransportAddress(
      address: InternetAddress.fromRawAddress(raw),
      port: port,
    );
  }
  throw StunParseException('Unsupported XOR address family: $family');
}

Uint8List _computeMessageIntegrity(
  Uint8List fullMessage,
  int integrityOffset,
  Uint8List key,
) {
  final digestInput = Uint8List.fromList(fullMessage);
  final bodyLength = integrityOffset + 24 - stunHeaderLength;
  writeUint16Into(digestInput, 2, bodyLength);
  digestInput.fillRange(integrityOffset + 4, integrityOffset + 24, 0);
  return hmacSha1(key, digestInput.sublist(0, integrityOffset + 24));
}

int _computeFingerprint(Uint8List fullMessage, int fingerprintOffset) {
  final digestInput = Uint8List.fromList(fullMessage);
  return crc32(digestInput.sublist(0, fingerprintOffset)) ^ stunFingerprintXor;
}
