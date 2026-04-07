import 'dart:async';
import 'dart:io';

import 'package:stun/stun.dart';
import 'package:stun/src/common/exceptions.dart';
import 'package:test/test.dart';

void main() {
  tearDown(() {
    StunLog.enabled = false;
    StunLog.logger = null;
  });

  group('StunClient features', () {
    test('automatically follows ALTERNATE-SERVER redirects', () async {
      final targetServer = await _UdpStunServer.bind(
        onPacket: (socket, datagram, request) {
          final response = _successResponse(
            request,
            datagram,
          );
          socket.send(response.encode(includeFingerprint: true),
              datagram.address, datagram.port);
        },
      );
      addTearDown(targetServer.close);

      final redirectServer = await _UdpStunServer.bind(
        onPacket: (socket, datagram, request) {
          final response = StunMessage(
            method: StunMethod.binding,
            messageClass: StunMessageClass.errorResponse,
            transactionId: request.transactionId,
            attributes: <StunAttribute>[
              const StunErrorCodeAttribute(
                code: 300,
                reasonPhrase: 'Try Alternate',
              ),
              StunAlternateServerAttribute(
                StunTransportAddress(
                  address: InternetAddress.loopbackIPv4,
                  port: targetServer.port,
                ),
              ),
            ],
          );
          socket.send(response.encode(includeFingerprint: true),
              datagram.address, datagram.port);
        },
      );
      addTearDown(redirectServer.close);

      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: redirectServer.port,
        requestTimeout: const Duration(milliseconds: 200),
        initialRto: const Duration(milliseconds: 50),
        maxRetransmissions: 1,
        responseTimeoutMultiplier: 1,
      );

      final result = await client.sendForResult(client.createBindingRequest());

      expect(result.isSuccess, isTrue);
      expect(result.redirectCount, equals(1));
      expect(result.endpoint.port, equals(targetServer.port));
      expect(result.attemptedEndpoints, hasLength(2));
    });

    test('returns structured error results for STUN error responses', () async {
      final server = await _UdpStunServer.bind(
        onPacket: (socket, datagram, request) {
          final response = StunMessage(
            method: StunMethod.binding,
            messageClass: StunMessageClass.errorResponse,
            transactionId: request.transactionId,
            attributes: const <StunAttribute>[
              StunErrorCodeAttribute(
                code: 420,
                reasonPhrase: 'Unknown Attribute',
              ),
            ],
          );
          socket.send(response.encode(includeFingerprint: true),
              datagram.address, datagram.port);
        },
      );
      addTearDown(server.close);

      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: server.port,
        requestTimeout: const Duration(milliseconds: 200),
        initialRto: const Duration(milliseconds: 50),
        maxRetransmissions: 1,
        responseTimeoutMultiplier: 1,
      );

      final result = await client.sendForResult(client.createBindingRequest());
      final rawResponse =
          await client.sendAndAwait(client.createBindingRequest());

      expect(result.isError, isTrue);
      expect(result.errorCode, equals(420));
      expect(result.reasonPhrase, equals('Unknown Attribute'));
      expect(rawResponse.messageClass, equals(StunMessageClass.errorResponse));
    });

    test('reuses a local UDP port across session requests and keepalive',
        () async {
      final server = await _UdpStunServer.bind(
        onPacket: (socket, datagram, request) {
          final response = _successResponse(request, datagram);
          socket.send(response.encode(includeFingerprint: true),
              datagram.address, datagram.port);
        },
      );
      addTearDown(server.close);

      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: server.port,
        requestTimeout: const Duration(milliseconds: 200),
        initialRto: const Duration(milliseconds: 50),
        maxRetransmissions: 1,
        responseTimeoutMultiplier: 1,
      );
      final session = await client.openSession();
      addTearDown(session.close);

      await session.sendAndAwait(client.createBindingRequest());
      await session.sendAndAwait(client.createBindingRequest());
      expect(server.remotePorts.toSet(), hasLength(1));

      final ticked = Completer<void>();
      late final StunKeepaliveHandle handle;
      handle = session.startKeepalive(
        interval: const Duration(milliseconds: 30),
        onResponse: (_) {
          if (server.requestCount >= 4 && !ticked.isCompleted) {
            handle.stop();
            ticked.complete();
          }
        },
      );
      await ticked.future.timeout(const Duration(seconds: 1));
      await handle.done;
      final countAfterStop = server.requestCount;
      await Future<void>.delayed(const Duration(milliseconds: 80));
      expect(server.requestCount, equals(countAfterStop));
    });

    test('probes server capability support', () async {
      final server = await _UdpStunServer.bind(
        onPacket: (socket, datagram, request) {
          final responsePort = request.attribute<StunResponsePortAttribute>();
          final destinationPort = responsePort?.port ?? datagram.port;
          final response = _successResponse(
            request,
            datagram,
            extraAttributes: <StunAttribute>[
              StunOtherAddressAttribute(
                StunTransportAddress(
                  address: InternetAddress.loopbackIPv4,
                  port: 41001,
                ),
              ),
              StunResponseOriginAttribute(
                StunTransportAddress(
                  address: InternetAddress.loopbackIPv4,
                  port: 41000,
                ),
              ),
            ],
          );
          socket.send(
            response.encode(includeFingerprint: true),
            datagram.address,
            destinationPort,
          );
        },
      );
      addTearDown(server.close);

      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: server.port,
        requestTimeout: const Duration(milliseconds: 200),
        initialRto: const Duration(milliseconds: 50),
        maxRetransmissions: 1,
        responseTimeoutMultiplier: 1,
      );

      final result = await client.probeServerCapabilities();

      expect(result.capabilities.otherAddress, NatCapabilitySupport.supported);
      expect(
          result.capabilities.responseOrigin, NatCapabilitySupport.supported);
      expect(result.capabilities.changeRequest, NatCapabilitySupport.supported);
      expect(result.capabilities.responsePort, NatCapabilitySupport.supported);
      expect(result.capabilities.padding, NatCapabilitySupport.supported);
      expect(result.warnings, isEmpty);
    });

    test('filters resolved endpoints to the requested IPv4 family', () async {
      final client = StunClient(
        target: const StunServerTarget(
          host: 'localhost',
          port: 3478,
          transport: Transport.udp,
          enableDnsDiscovery: false,
          enableDnsCache: false,
        ),
        addressType: InternetAddressType.IPv4,
      );

      final endpoints = await client.resolveEndpoints();

      expect(endpoints, isNotEmpty);
      expect(
        endpoints.every(
          (endpoint) => endpoint.address.type == InternetAddressType.IPv4,
        ),
        isTrue,
      );
    });

    test('filters resolved endpoints to the requested IPv6 family', () async {
      final client = StunClient(
        target: const StunServerTarget(
          host: 'localhost',
          port: 3478,
          transport: Transport.udp,
          enableDnsDiscovery: false,
          enableDnsCache: false,
        ),
        addressType: InternetAddressType.IPv6,
      );

      final endpoints = await client.resolveEndpoints();

      expect(endpoints, isNotEmpty);
      expect(
        endpoints.every(
          (endpoint) => endpoint.address.type == InternetAddressType.IPv6,
        ),
        isTrue,
      );
    });

    test('throws when the requested address family is unavailable', () async {
      final client = StunClient(
        target: const StunServerTarget(
          host: '127.0.0.1',
          port: 3478,
          transport: Transport.udp,
          enableDnsDiscovery: false,
          enableDnsCache: false,
        ),
        addressType: InternetAddressType.IPv6,
      );

      await expectLater(
        client.resolveEndpoints(),
        throwsA(isA<StunDiscoveryException>()),
      );
    });

    test('emits structured logger events through callback', () async {
      final server = await _UdpStunServer.bind(
        onPacket: (socket, datagram, request) {
          final response = _successResponse(request, datagram);
          socket.send(response.encode(includeFingerprint: true),
              datagram.address, datagram.port);
        },
      );
      addTearDown(server.close);

      final events = <StunLogEvent>[];
      StunLog.logger = (event) {
        events.add(event);
      };

      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: server.port,
        requestTimeout: const Duration(milliseconds: 200),
        initialRto: const Duration(milliseconds: 50),
        maxRetransmissions: 1,
        responseTimeoutMultiplier: 1,
      );

      await client.sendAndAwait(client.createBindingRequest());

      expect(events.any((event) => event.action == 'request'), isTrue);
      expect(events.any((event) => event.action == 'response'), isTrue);
      expect(
        events
            .where((event) => event.action == 'request')
            .any((event) => event.fields.containsKey('transactionId')),
        isTrue,
      );
    });

    test('round-trips NatBehaviorReport json', () {
      final report = NatBehaviorReport(
        reachability: NatReachability.reachable,
        serverEndpoint: StunServerEndpoint(
          host: 'example.test',
          address: InternetAddress.loopbackIPv4,
          port: 3478,
          transport: Transport.udp,
        ),
        localAddress: StunTransportAddress(
          address: InternetAddress.loopbackIPv4,
          port: 40000,
        ),
        mappedAddress: StunTransportAddress(
          address: InternetAddress('203.0.113.1'),
          port: 50000,
        ),
        isNatted: true,
        mappingBehavior: NatMappingBehavior.endpointIndependent,
        filteringBehavior: NatFilteringBehavior.addressDependent,
        bindingLifetimeEstimate: const Duration(seconds: 30),
        hairpinning: NatProbeStatus.yes,
        fragmentHandling: NatProbeStatus.no,
        algDetected: false,
        serverCapabilities: const StunServerCapabilities(
          otherAddress: NatCapabilitySupport.supported,
          responseOrigin: NatCapabilitySupport.supported,
          changeRequest: NatCapabilitySupport.unsupported,
          responsePort: NatCapabilitySupport.unknown,
          padding: NatCapabilitySupport.supported,
        ),
        legacyNatType: NatLegacyType.restrictedCone,
        warnings: const <String>['warning-1'],
      );

      final decoded = NatBehaviorReport.fromJson(report.toJson());

      expect(decoded.reachability, equals(report.reachability));
      expect(decoded.serverEndpoint, equals(report.serverEndpoint));
      expect(decoded.localAddress, equals(report.localAddress));
      expect(decoded.mappedAddress, equals(report.mappedAddress));
      expect(decoded.isNatted, equals(report.isNatted));
      expect(decoded.mappingBehavior, equals(report.mappingBehavior));
      expect(decoded.filteringBehavior, equals(report.filteringBehavior));
      expect(
        decoded.bindingLifetimeEstimate,
        equals(report.bindingLifetimeEstimate),
      );
      expect(decoded.hairpinning, equals(report.hairpinning));
      expect(decoded.fragmentHandling, equals(report.fragmentHandling));
      expect(decoded.algDetected, equals(report.algDetected));
      expect(decoded.serverCapabilities, equals(report.serverCapabilities));
      expect(decoded.legacyNatType, equals(report.legacyNatType));
      expect(decoded.warnings, equals(report.warnings));
    });
  });
}

StunMessage _successResponse(
  StunMessage request,
  Datagram datagram, {
  List<StunAttribute> extraAttributes = const <StunAttribute>[],
}) {
  final mapped = StunTransportAddress(
    address: datagram.address,
    port: datagram.port,
  );
  return StunMessage(
    method: StunMethod.binding,
    messageClass: StunMessageClass.successResponse,
    transactionId: request.transactionId,
    attributes: <StunAttribute>[
      StunMappedAddressAttribute(mapped),
      StunXorMappedAddressAttribute(mapped),
      ...extraAttributes,
    ],
  );
}

class _UdpStunServer {
  _UdpStunServer._(this._socket, this._subscription);

  final RawDatagramSocket _socket;
  final StreamSubscription<RawSocketEvent> _subscription;
  final List<int> remotePorts = <int>[];
  int requestCount = 0;

  int get port => _socket.port;

  static Future<_UdpStunServer> bind({
    required FutureOr<void> Function(
      RawDatagramSocket socket,
      Datagram datagram,
      StunMessage request,
    ) onPacket,
  }) async {
    final socket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    late final _UdpStunServer server;
    late final StreamSubscription<RawSocketEvent> subscription;
    subscription = socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = socket.receive();
      if (datagram == null) {
        return;
      }
      final request = StunMessage.decode(datagram.data);
      server.requestCount += 1;
      server.remotePorts.add(datagram.port);
      unawaited(Future<void>.sync(() => onPacket(socket, datagram, request)));
    });
    server = _UdpStunServer._(socket, subscription);
    return server;
  }

  Future<void> close() async {
    await _subscription.cancel();
    _socket.close();
  }
}
