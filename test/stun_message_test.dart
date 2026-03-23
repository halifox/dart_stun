import 'dart:io';
import 'dart:typed_data';

import 'package:stun/stun.dart';
import 'package:stun/src/common/exceptions.dart';
import 'package:test/test.dart';

void main() {
  group('StunMessage', () {
    test('encodes and decodes a binding request with fingerprint', () {
      final message = StunMessage.bindingRequest(
        attributes: const <StunAttribute>[
          StunSoftwareAttribute('dart_stun-test'),
          StunChangeRequestAttribute(changeIp: true, changePort: true),
        ],
      );

      final encoded = message.encode(includeFingerprint: true);
      final decoded = StunMessage.decode(encoded, validateFingerprint: true);

      expect(decoded.method, equals(StunMethod.binding));
      expect(decoded.messageClass, equals(StunMessageClass.request));
      expect(decoded.attribute<StunSoftwareAttribute>()?.description,
          equals('dart_stun-test'));
      expect(
        decoded.attribute<StunChangeRequestAttribute>()?.changeIp,
        isTrue,
      );
      expect(
        decoded.attribute<StunChangeRequestAttribute>()?.changePort,
        isTrue,
      );
    });

    test('encodes and validates short-term message integrity', () {
      const credentials = StunCredentials.shortTerm(
        username: 'demo',
        password: 'secret',
      );
      final message = StunMessage.bindingRequest(
        attributes: const <StunAttribute>[
          StunUsernameAttribute('demo'),
        ],
      );

      final encoded = message.encode(
        credentials: credentials,
        includeFingerprint: true,
      );
      final decoded = StunMessage.decode(encoded, validateFingerprint: true);

      expect(decoded.validateMessageIntegrity(credentials), isTrue);
      expect(decoded.attribute<StunFingerprintAttribute>(), isNotNull);
    });

    test('round-trips address and padding attributes', () {
      final transactionId = StunMessage.generateTransactionId();
      final address = StunTransportAddress(
        address: InternetAddress.loopbackIPv4,
        port: 43210,
      );
      final message = StunMessage(
        method: StunMethod.binding,
        messageClass: StunMessageClass.successResponse,
        transactionId: transactionId,
        attributes: <StunAttribute>[
          StunMappedAddressAttribute(address),
          StunXorMappedAddressAttribute(address),
          StunResponseOriginAttribute(address),
          StunOtherAddressAttribute(address),
          StunResponsePortAttribute(40000),
          StunPaddingAttribute(Uint8List.fromList(<int>[1, 2, 3])),
        ],
      );

      final decoded = StunMessage.decode(
        message.encode(includeFingerprint: true),
        validateFingerprint: true,
      );

      expect(decoded.attribute<StunMappedAddressAttribute>()?.value, address);
      expect(
        decoded.attribute<StunXorMappedAddressAttribute>()?.value,
        address,
      );
      expect(
        decoded.attribute<StunResponseOriginAttribute>()?.value,
        address,
      );
      expect(decoded.attribute<StunOtherAddressAttribute>()?.value, address);
      expect(
        decoded.attribute<StunResponsePortAttribute>()?.port,
        equals(40000),
      );
      expect(
        decoded.attribute<StunPaddingAttribute>()?.value.length,
        equals(3),
      );
    });

    test('preserves unknown attributes', () {
      final message = StunMessage.bindingRequest(
        attributes: <StunAttribute>[
          StunUnknownAttribute(
            type: 0x1337,
            value: Uint8List.fromList(<int>[0xaa, 0xbb, 0xcc, 0xdd]),
          ),
        ],
      );

      final decoded = StunMessage.decode(message.encode());
      final unknown = decoded.attribute<StunUnknownAttribute>();

      expect(unknown, isNotNull);
      expect(unknown?.type, equals(0x1337));
      expect(
        unknown?.value,
        orderedEquals(Uint8List.fromList(<int>[0xaa, 0xbb, 0xcc, 0xdd])),
      );
    });

    test('throws on truncated message header', () {
      expect(
        () => StunMessage.decode(Uint8List(8)),
        throwsA(isA<StunParseException>()),
      );
    });

    test('throws on invalid declared length', () {
      final bytes = Uint8List.fromList(<int>[
        0x00, 0x01,
        0x00, 0x08,
        0x21, 0x12, 0xa4, 0x42,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
      ]);

      expect(
        () => StunMessage.decode(bytes),
        throwsA(isA<StunParseException>()),
      );
    });

    test('throws on unsupported address family', () {
      final message = StunMessage(
        method: StunMethod.binding,
        messageClass: StunMessageClass.successResponse,
        attributes: <StunAttribute>[
          StunUnknownAttribute(
            type: 0x0001,
            value: Uint8List.fromList(<int>[
              0x00, 0x09,
              0x12, 0x34,
              0x7f, 0x00, 0x00, 0x01,
            ]),
          ),
        ],
      );

      expect(
        () => StunMessage.decode(message.encode()),
        throwsA(isA<StunParseException>()),
      );
    });
  });
}
