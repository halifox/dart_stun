import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:stun/stun.dart';
import 'package:stun/src/client/stun_discovery.dart';
import 'package:stun/src/common/exceptions.dart';
import 'package:test/test.dart';

void main() {
  tearDown(() {
    StunLog.enabled = false;
  });

  group('StunLog', () {
    test('does not print when disabled', () async {
      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: 3478,
      );
      final message = client.createBindingRequest();
      final encoded = client.encodeMessage(message);

      final lines = await capturePrints(() {
        client.parseMessage(encoded, validateFingerprint: true);
      });

      expect(lines, isEmpty);
    });

    test('prints request, response and parsed logs for UDP request', () async {
      final server = await _LocalStunUdpServer.bind();
      addTearDown(server.close);

      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: server.port,
        requestTimeout: const Duration(seconds: 1),
        initialRto: const Duration(milliseconds: 200),
        maxRetransmissions: 2,
        responseTimeoutMultiplier: 2,
      );

      final lines = await capturePrints(() async {
        StunLog.enabled = true;
        final response =
            await client.sendAndAwait(client.createBindingRequest());
        expect(response.messageClass, StunMessageClass.successResponse);
      });

      expect(lines, isNotEmpty);
      expect(lines.any((line) => line.contains('[stun] request')), isTrue);
      expect(lines.any((line) => line.contains('[stun] udp-send')), isTrue);
      expect(lines.any((line) => line.contains('[stun] udp-recv')), isTrue);
      expect(lines.any((line) => line.contains('[stun] udp-parsed')), isTrue);
      expect(lines.any((line) => line.contains('[stun] response')), isTrue);
    });

    test('defaults to linear backoff for UDP retransmissions', () async {
      final client = StunClient(
        target: const StunServerTarget(
          host: '127.0.0.1',
          port: 9,
          transport: Transport.udp,
        ),
        requestTimeout: const Duration(milliseconds: 100),
        initialRto: const Duration(milliseconds: 50),
        maxRetransmissions: 3,
        responseTimeoutMultiplier: 1,
      );

      final lines = await capturePrints(() async {
        StunLog.enabled = true;
        await expectLater(
          client.sendAndAwait(client.createBindingRequest()),
          throwsA(isA<StunTimeoutException>()),
        );
      });

      final sendLines = lines
          .where((line) => line.contains('[stun] udp-send'))
          .toList(growable: false);
      expect(sendLines, hasLength(3));
      expect(sendLines[0], contains('waitMs=50'));
      expect(sendLines[1], contains('waitMs=100'));
      expect(sendLines[2], contains('waitMs=150'));
    });

    test('uses configured linear backoff for UDP retransmissions', () async {
      final client = StunClient.create(
        transport: Transport.udp,
        serverHost: '127.0.0.1',
        serverPort: 9,
        requestTimeout: const Duration(milliseconds: 100),
        initialRto: const Duration(milliseconds: 50),
        backoffStrategy: StunBackoffStrategy.linear,
        maxRetransmissions: 3,
        responseTimeoutMultiplier: 1,
      );

      final lines = await capturePrints(() async {
        StunLog.enabled = true;
        await expectLater(
          client.sendAndAwait(client.createBindingRequest()),
          throwsA(isA<StunTimeoutException>()),
        );
      });

      final sendLines = lines
          .where((line) => line.contains('[stun] udp-send'))
          .toList(growable: false);
      expect(sendLines, hasLength(3));
      expect(sendLines[0], contains('waitMs=50'));
      expect(sendLines[1], contains('waitMs=100'));
      expect(sendLines[2], contains('waitMs=150'));
    });

    test('uses exponential backoff for UDP retransmissions', () async {
      final client = StunClient.fromUri(
        'stun:127.0.0.1:9?transport=udp',
        requestTimeout: const Duration(milliseconds: 100),
        initialRto: const Duration(milliseconds: 50),
        backoffStrategy: StunBackoffStrategy.exponential,
        maxRetransmissions: 3,
        responseTimeoutMultiplier: 1,
      );

      final lines = await capturePrints(() async {
        StunLog.enabled = true;
        await expectLater(
          client.sendAndAwait(client.createBindingRequest()),
          throwsA(isA<StunTimeoutException>()),
        );
      });

      final sendLines = lines
          .where((line) => line.contains('[stun] udp-send'))
          .toList(growable: false);
      expect(sendLines, hasLength(3));
      expect(sendLines[0], contains('waitMs=50'));
      expect(sendLines[1], contains('waitMs=100'));
      expect(sendLines[2], contains('waitMs=200'));
    });

    test('NatDetector.fromUri passes through configured backoff', () async {
      final detector = NatDetector.fromUri(
        'stun:127.0.0.1:9?transport=udp',
        requestTimeout: const Duration(milliseconds: 100),
        initialRto: const Duration(milliseconds: 50),
        backoffStrategy: StunBackoffStrategy.exponential,
        maxRetransmissions: 3,
        responseTimeoutMultiplier: 1,
        initialBindingLifetimeProbe: const Duration(milliseconds: 100),
        maxBindingLifetimeProbe: const Duration(milliseconds: 100),
        bindingLifetimePrecision: const Duration(milliseconds: 50),
      );

      final lines = await capturePrints(() async {
        StunLog.enabled = true;
        final report = await detector.check();
        expect(report.reachability, NatReachability.udpBlocked);
      });

      final sendLines = lines
          .where((line) => line.contains('[stun] udp-send'))
          .toList(growable: false);
      expect(sendLines, hasLength(3));
      expect(sendLines[0], contains('waitMs=50'));
      expect(sendLines[1], contains('waitMs=100'));
      expect(sendLines[2], contains('waitMs=200'));
    });

    test('prints DNS query and parsed result logs during discovery', () async {
      final dnsServer = await _LocalDnsServer.bind();
      addTearDown(dnsServer.close);

      final target = StunServerTarget.uri(
        'stun:example.test',
        dnsServers: <InternetAddress>[InternetAddress.loopbackIPv4],
      );

      final lines = await capturePrints(() async {
        StunLog.enabled = true;
        final endpoints = await resolveStunTarget(target);
        expect(endpoints, isNotEmpty);
        expect(endpoints.first.port, 41000);
        expect(endpoints.first.transport, Transport.udp);
      });

      expect(
        lines.any(
          (line) =>
              line.contains('[dns] query') &&
              line.contains('name=example.test') &&
              line.contains('type=35'),
        ),
        isTrue,
      );
      expect(
        lines.any(
          (line) =>
              line.contains('[dns] query') &&
              line.contains('name=_stun._udp.example.test') &&
              line.contains('type=33'),
        ),
        isTrue,
      );
      expect(lines.any((line) => line.contains('[dns] response')), isTrue);
      expect(lines.any((line) => line.contains('[dns] srv-fallback')), isTrue);
      expect(
        lines.any(
          (line) => line.contains('[dns] discover-result host=example.test'),
        ),
        isTrue,
      );
    });

    test('falls back to later resolved endpoints after a timeout', () async {
      final liveServer = await _LocalStunUdpServer.bind();
      addTearDown(liveServer.close);
      final deadPort = await allocateUnusedPort();
      final dnsServer = await _ProgrammableLocalDnsServer.bind(
        hosts: <String, List<_SrvAnswer>>{
          'fallback.test': <_SrvAnswer>[
            _SrvAnswer(priority: 0, weight: 20, port: deadPort),
            _SrvAnswer(priority: 0, weight: 10, port: liveServer.port),
          ],
        },
      );
      addTearDown(dnsServer.close);

      final client = StunClient.fromUri(
        'stun:fallback.test',
        dnsServers: <InternetAddress>[InternetAddress.loopbackIPv4],
        requestTimeout: const Duration(milliseconds: 200),
        initialRto: const Duration(milliseconds: 80),
        maxRetransmissions: 2,
        responseTimeoutMultiplier: 2,
      );

      final result = await client.sendForResult(client.createBindingRequest());

      expect(result.isSuccess, isTrue);
      expect(result.endpoint.port, equals(liveServer.port));
      expect(result.attemptedEndpoints, hasLength(2));
    });

    test('caches DNS discovery results', () async {
      final dnsServer = await _ProgrammableLocalDnsServer.bind(
        hosts: <String, List<_SrvAnswer>>{
          'cache.test': <_SrvAnswer>[
            const _SrvAnswer(priority: 0, weight: 10, port: 41000),
          ],
        },
      );
      addTearDown(dnsServer.close);

      final target = StunServerTarget.uri(
        'stun:cache.test',
        dnsServers: <InternetAddress>[InternetAddress.loopbackIPv4],
        enableDnsCache: true,
        dnsCacheTtl: const Duration(seconds: 30),
      );

      final first = await resolveStunTarget(target);
      final firstQueryCount = dnsServer.queryCount;
      final second = await resolveStunTarget(target);

      expect(first, isNotEmpty);
      expect(second, isNotEmpty);
      expect(dnsServer.queryCount, equals(firstQueryCount));
    });
  });
}

Future<List<String>> capturePrints(FutureOr<void> Function() action) async {
  final lines = <String>[];
  await runZoned(
    () async {
      await action();
    },
    zoneSpecification: ZoneSpecification(
      print: (_, __, ___, String message) {
        lines.add(message);
      },
    ),
  );
  return lines;
}

Future<int> allocateUnusedPort() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  socket.close();
  return port;
}

class _LocalStunUdpServer {
  _LocalStunUdpServer._(this._socket, this._subscription);

  final RawDatagramSocket _socket;
  final StreamSubscription<RawSocketEvent> _subscription;

  int get port => _socket.port;

  static Future<_LocalStunUdpServer> bind() async {
    final socket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
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
      final mapped = StunTransportAddress(
        address: datagram.address,
        port: datagram.port,
      );
      final response = StunMessage(
        method: StunMethod.binding,
        messageClass: StunMessageClass.successResponse,
        transactionId: request.transactionId,
        attributes: <StunAttribute>[
          StunMappedAddressAttribute(mapped),
          StunXorMappedAddressAttribute(mapped),
        ],
      );
      socket.send(response.encode(includeFingerprint: true), mapped.address,
          mapped.port);
    });
    return _LocalStunUdpServer._(socket, subscription);
  }

  Future<void> close() async {
    await _subscription.cancel();
    _socket.close();
  }
}

class _LocalDnsServer {
  _LocalDnsServer._(this._socket, this._subscription);

  final RawDatagramSocket _socket;
  final StreamSubscription<RawSocketEvent> _subscription;

  static Future<_LocalDnsServer> bind() async {
    final socket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 53);
    late final StreamSubscription<RawSocketEvent> subscription;
    subscription = socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = socket.receive();
      if (datagram == null) {
        return;
      }
      final query = datagram.data;
      final qName = _readQuestionName(query);
      final response = switch (qName) {
        'example.test' =>
          _buildDnsResponse(query, answers: const <Uint8List>[]),
        '_stun._udp.example.test' => _buildDnsResponse(
            query,
            answers: <Uint8List>[
              _buildSrvAnswer(
                port: 41000,
                target: 'localhost',
              ),
            ],
          ),
        _ =>
          _buildDnsResponse(query, flags: 0x8183, answers: const <Uint8List>[]),
      };
      socket.send(response, datagram.address, datagram.port);
    });
    return _LocalDnsServer._(socket, subscription);
  }

  Future<void> close() async {
    await _subscription.cancel();
    _socket.close();
  }
}

class _SrvAnswer {
  const _SrvAnswer({
    required this.priority,
    required this.weight,
    required this.port,
  });

  final int priority;
  final int weight;
  final int port;
}

class _ProgrammableLocalDnsServer {
  _ProgrammableLocalDnsServer._(
    this._socket,
    this._subscription,
    this.hosts,
  );

  final RawDatagramSocket _socket;
  final StreamSubscription<RawSocketEvent> _subscription;
  final Map<String, List<_SrvAnswer>> hosts;
  int queryCount = 0;

  static Future<_ProgrammableLocalDnsServer> bind({
    required Map<String, List<_SrvAnswer>> hosts,
  }) async {
    final socket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 53);
    late final _ProgrammableLocalDnsServer server;
    late final StreamSubscription<RawSocketEvent> subscription;
    subscription = socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = socket.receive();
      if (datagram == null) {
        return;
      }
      server.queryCount += 1;
      final query = datagram.data;
      final qName = _readQuestionName(query);
      final response = switch (qName) {
        final String host when server.hosts.containsKey(host) =>
          _buildDnsResponse(query, answers: const <Uint8List>[]),
        final String srvName
            when srvName.startsWith('_stun._udp.') &&
                server.hosts.containsKey(
                  srvName.replaceFirst('_stun._udp.', ''),
                ) =>
          _buildDnsResponse(
            query,
            answers: server.hosts[srvName.replaceFirst('_stun._udp.', '')]!
                .map(_buildProgrammableSrvAnswer)
                .toList(growable: false),
          ),
        _ =>
          _buildDnsResponse(query, flags: 0x8183, answers: const <Uint8List>[]),
      };
      socket.send(response, datagram.address, datagram.port);
    });
    server = _ProgrammableLocalDnsServer._(socket, subscription, hosts);
    return server;
  }

  Future<void> close() async {
    await _subscription.cancel();
    _socket.close();
  }
}

String _readQuestionName(Uint8List query) {
  final labels = <String>[];
  var offset = 12;
  while (offset < query.length) {
    final length = query[offset];
    if (length == 0) {
      break;
    }
    final start = offset + 1;
    final end = start + length;
    labels.add(String.fromCharCodes(query.sublist(start, end)));
    offset = end;
  }
  return labels.join('.');
}

Uint8List _buildDnsResponse(
  Uint8List query, {
  int flags = 0x8180,
  required List<Uint8List> answers,
}) {
  final builder = BytesBuilder(copy: false);
  builder.add(query.sublist(0, 2));
  builder.add(_uint16(flags));
  builder.add(query.sublist(4, 6));
  builder.add(_uint16(answers.length));
  builder.add(_uint16(0));
  builder.add(_uint16(0));
  builder.add(query.sublist(12));
  for (final answer in answers) {
    builder.add(answer);
  }
  return builder.takeBytes();
}

Uint8List _buildSrvAnswer({
  required int port,
  required String target,
}) {
  final rdata = BytesBuilder(copy: false)
    ..add(_uint16(0))
    ..add(_uint16(0))
    ..add(_uint16(port))
    ..add(_encodeDomain(target));
  final rdataBytes = rdata.takeBytes();
  final answer = BytesBuilder(copy: false)
    ..add(_uint16(0xc00c))
    ..add(_uint16(33))
    ..add(_uint16(1))
    ..add(_uint32(60))
    ..add(_uint16(rdataBytes.length))
    ..add(rdataBytes);
  return answer.takeBytes();
}

Uint8List _buildProgrammableSrvAnswer(_SrvAnswer answer) {
  final rdata = BytesBuilder(copy: false)
    ..add(_uint16(answer.priority))
    ..add(_uint16(answer.weight))
    ..add(_uint16(answer.port))
    ..add(_encodeDomain('127.0.0.1'));
  final rdataBytes = rdata.takeBytes();
  final response = BytesBuilder(copy: false)
    ..add(_uint16(0xc00c))
    ..add(_uint16(33))
    ..add(_uint16(1))
    ..add(_uint32(60))
    ..add(_uint16(rdataBytes.length))
    ..add(rdataBytes);
  return response.takeBytes();
}

Uint8List _encodeDomain(String name) {
  final builder = BytesBuilder(copy: false);
  for (final label in name.split('.')) {
    builder.addByte(label.length);
    builder.add(label.codeUnits);
  }
  builder.addByte(0);
  return builder.takeBytes();
}

Uint8List _uint16(int value) {
  final data = ByteData(2)..setUint16(0, value);
  return data.buffer.asUint8List();
}

Uint8List _uint32(int value) {
  final data = ByteData(4)..setUint32(0, value);
  return data.buffer.asUint8List();
}
