import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import '../common/stun_log.dart';
import '../common/binary_utils.dart';
import '../common/exceptions.dart';
import '../message/stun_message.dart';
import 'stun_backoff_strategy.dart';
import 'stun_server_target.dart';

class StunInboundPacket {
  const StunInboundPacket({
    required this.message,
    required this.remoteAddress,
    required this.remotePort,
  });

  final StunMessage message;
  final InternetAddress remoteAddress;
  final int remotePort;
}

class StunUdpBinding {
  StunUdpBinding._(this._socket) {
    _socket.readEventsEnabled = true;
    _socket.writeEventsEnabled = false;
    _subscription = _socket.listen(_onSocketEvent);
  }

  final RawDatagramSocket _socket;
  late final StreamSubscription<RawSocketEvent> _subscription;
  final Map<String, List<Completer<StunInboundPacket>>> _waiters =
      <String, List<Completer<StunInboundPacket>>>{};

  static Future<StunUdpBinding> bind({
    InternetAddress? localAddress,
    int localPort = 0,
    required InternetAddressType addressType,
  }) async {
    final bindAddress = localAddress ??
        (addressType == InternetAddressType.IPv6
            ? InternetAddress.anyIPv6
            : InternetAddress.anyIPv4);
    final socket = await RawDatagramSocket.bind(bindAddress, localPort);
    return StunUdpBinding._(socket);
  }

  InternetAddress get localAddress => _socket.address;

  int get localPort => _socket.port;

  Future<void> close() async {
    await _subscription.cancel();
    _socket.close();
  }

  void send(Uint8List bytes, InternetAddress address, int port) {
    _socket.send(bytes, address, port);
  }

  Future<StunInboundPacket?> request({
    required StunMessage message,
    required Uint8List payload,
    required StunServerEndpoint endpoint,
    Duration initialRto = const Duration(milliseconds: 500),
    StunBackoffStrategy backoffStrategy = StunBackoffStrategy.linear,
    int maxRetransmissions = 7,
    int responseTimeoutMultiplier = 16,
  }) async {
    final transactionId = message.transactionId;
    final waiter = _register(transactionId);
    try {
      for (var attempt = 0; attempt < maxRetransmissions; attempt++) {
        final rto = _retryDelay(
          initialRto,
          attempt,
          backoffStrategy,
        );
        StunLog.log(
          '[stun] udp-send attempt=${attempt + 1}/$maxRetransmissions '
          'waitMs=${rto.inMilliseconds} bytes=${payload.length} '
          'endpoint=${summarizeEndpoint(endpoint)} '
          '${summarizeStunMessage(message)}',
        );
        send(payload, endpoint.address, endpoint.port);
        final waitDuration = attempt == maxRetransmissions - 1
            ? _scaleDuration(rto, responseTimeoutMultiplier)
            : rto;
        try {
          return await waiter.future.timeout(waitDuration);
        } on TimeoutException {
          if (attempt == maxRetransmissions - 1) {
            return null;
          }
        }
      }
      return null;
    } finally {
      _deregister(transactionId, waiter);
    }
  }

  Future<StunInboundPacket?> waitForTransaction(
    Uint8List transactionId,
    Duration timeout,
  ) async {
    final waiter = _register(transactionId);
    try {
      return await waiter.future.timeout(timeout);
    } on TimeoutException {
      return null;
    } finally {
      _deregister(transactionId, waiter);
    }
  }

  void _onSocketEvent(RawSocketEvent event) {
    if (event != RawSocketEvent.read) {
      return;
    }
    while (true) {
      final datagram = _socket.receive();
      if (datagram == null) {
        break;
      }
      StunLog.log(
        '[stun] udp-read bytes=${datagram.data.length} '
        'remote=${datagram.address.address}:${datagram.port}',
      );
      try {
        final message = StunMessage.decode(datagram.data);
        StunLog.log(
          '[stun] udp-recv bytes=${datagram.data.length} '
          'remote=${datagram.address.address}:${datagram.port}',
        );
        StunLog.log(
          '[stun] udp-parsed remote=${datagram.address.address}:${datagram.port} '
          '${summarizeStunMessage(message)}',
        );
        final key = hexEncode(message.transactionId);
        final waiters = _waiters[key];
        if (waiters == null || waiters.isEmpty) {
          continue;
        }
        final packet = StunInboundPacket(
          message: message,
          remoteAddress: datagram.address,
          remotePort: datagram.port,
        );
        for (final waiter in waiters.toList(growable: false)) {
          if (!waiter.isCompleted) {
            waiter.complete(packet);
          }
        }
        _waiters.remove(key);
      } catch (error) {
        StunLog.log(
          '[stun] udp-parse-failed bytes=${datagram.data.length} '
          'remote=${datagram.address.address}:${datagram.port} error=$error',
        );
        continue;
      }
    }
  }

  Completer<StunInboundPacket> _register(Uint8List transactionId) {
    final key = hexEncode(transactionId);
    final completer = Completer<StunInboundPacket>();
    _waiters.putIfAbsent(key, () => <Completer<StunInboundPacket>>[]).add(
          completer,
        );
    return completer;
  }

  void _deregister(
    Uint8List transactionId,
    Completer<StunInboundPacket> completer,
  ) {
    final key = hexEncode(transactionId);
    final waiters = _waiters[key];
    if (waiters == null) {
      return;
    }
    waiters.remove(completer);
    if (waiters.isEmpty) {
      _waiters.remove(key);
    }
  }
}

class _StreamBuffer {
  final Queue<int> _queue = Queue<int>();

  void add(Uint8List bytes) {
    _queue.addAll(bytes);
  }

  int get length => _queue.length;

  Uint8List take(int count) {
    final result = Uint8List(count);
    for (var index = 0; index < count; index++) {
      result[index] = _queue.removeFirst();
    }
    return result;
  }
}

Future<StunMessage> readSingleStunMessageFromStream(
  Stream<Uint8List> stream, {
  required Duration timeout,
}) async {
  final buffer = _StreamBuffer();
  final iterator = StreamIterator<Uint8List>(stream);
  try {
    while (true) {
      if (buffer.length >= stunHeaderLength) {
        final header = buffer.take(stunHeaderLength);
        final length = readUint16(header, 2);
        while (buffer.length < length) {
          final hasNext = await iterator.moveNext().timeout(timeout);
          if (!hasNext) {
            throw const StunTimeoutException(
              'STUN stream ended before a complete message was read.',
            );
          }
          buffer.add(iterator.current);
        }
        final body = buffer.take(length);
        final message = StunMessage.decode(
          Uint8List.fromList(<int>[...header, ...body]),
          validateFingerprint: true,
        );
        StunLog.log(
          '[stun] stream-parsed bytes=${stunHeaderLength + length} '
          '${summarizeStunMessage(message)}',
        );
        return message;
      }
      final hasNext = await iterator.moveNext().timeout(timeout);
      if (!hasNext) {
        break;
      }
      buffer.add(iterator.current);
    }
  } finally {
    await iterator.cancel();
  }
  throw const StunTimeoutException('Timed out waiting for STUN stream data.');
}

Duration _scaleDuration(Duration duration, int multiplier) {
  return Duration(microseconds: duration.inMicroseconds * multiplier);
}

Duration _retryDelay(
  Duration initialRto,
  int attempt,
  StunBackoffStrategy backoffStrategy,
) {
  final multiplier = switch (backoffStrategy) {
    StunBackoffStrategy.linear => attempt + 1,
    StunBackoffStrategy.exponential => 1 << attempt,
  };
  return Duration(
    microseconds: initialRto.inMicroseconds * multiplier,
  );
}
