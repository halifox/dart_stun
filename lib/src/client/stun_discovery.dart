import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../common/binary_utils.dart';
import '../common/exceptions.dart';
import '../common/stun_log.dart';
import 'stun_server_target.dart';

class _ResolvedEndpoints {
  const _ResolvedEndpoints({
    required this.endpoints,
    required this.ttl,
  });

  final List<StunServerEndpoint> endpoints;
  final Duration ttl;
}

class _CachedResolvedEndpoints {
  const _CachedResolvedEndpoints({
    required this.resolved,
    required this.expiresAt,
  });

  final _ResolvedEndpoints resolved;
  final DateTime expiresAt;
}

final Map<String, _CachedResolvedEndpoints> _resolvedEndpointCache =
    <String, _CachedResolvedEndpoints>{};

Future<List<StunServerEndpoint>> resolveStunTarget(
  StunServerTarget target,
) async {
  if (target.isLiteralAddress) {
    final literalAddress =
        InternetAddress.tryParse(target.host) ?? InternetAddress(target.host);
    StunLog.log(
      '[dns] literal-endpoint host=${target.host} port=${target.effectivePort} '
      'transport=${target.transport.name}',
    );
    return <StunServerEndpoint>[
      StunServerEndpoint(
        host: target.host,
        address: literalAddress,
        port: target.effectivePort,
        transport: target.transport,
      ),
    ];
  }

  if (target.enableDnsCache) {
    final cached = _lookupCachedEndpoints(target);
    if (cached != null) {
      StunLog.log(
        '[dns] cache-hit host=${target.host} transport=${target.transport.name} '
        'endpoints=${cached.length}',
        category: 'dns',
        action: 'cache-hit',
        fields: <String, Object?>{
          'host': target.host,
          'transport': target.transport.name,
          'endpoints': cached.length,
        },
      );
      return cached;
    }
  }

  if (target.originalUri != null &&
      !target.hasExplicitPort &&
      target.enableDnsDiscovery) {
    StunLog.log(
      '[dns] discover host=${target.host} transport=${target.transport.name}',
    );
    final discovered = await _discoverFromDns(target);
    if (discovered.endpoints.isNotEmpty) {
      _storeResolvedEndpoints(target, discovered);
      StunLog.log(
        '[dns] discover-result host=${target.host} endpoints=${discovered.endpoints.length}',
      );
      return discovered.endpoints;
    }
  }

  StunLog.log('[dns] lookup host=${target.host}');
  final addresses = await InternetAddress.lookup(target.host);
  final resolved = _ResolvedEndpoints(
    endpoints: addresses
        .map(
          (address) => StunServerEndpoint(
            host: target.host,
            address: address,
            port: target.effectivePort,
            transport: target.transport,
          ),
        )
        .toList(growable: false),
    ttl: target.dnsCacheTtl,
  );
  _storeResolvedEndpoints(target, resolved);
  StunLog.log(
    '[dns] lookup-result host=${target.host} addresses=${addresses.length}',
  );
  return resolved.endpoints;
}

Future<_ResolvedEndpoints> _discoverFromDns(
  StunServerTarget target,
) async {
  final resolver = _DnsResolver(
    nameServers:
        target.dnsServers.isNotEmpty ? target.dnsServers : _defaultDnsServers,
  );
  final naptrRecords = await resolver.lookupNaptr(target.host);
  StunLog.log(
    '[dns] naptr host=${target.host} records=${naptrRecords.length}',
  );
  final endpoints = <StunServerEndpoint>[];
  var ttl = target.dnsCacheTtl;
  ttl = _minDnsTtl(
    ttl,
    naptrRecords.map((record) => Duration(seconds: record.ttl)),
  );

  for (final naptr in _selectNaptrRecords(target, naptrRecords)) {
    if (naptr.flags.toLowerCase() == 's') {
      final srvTransport = _transportFromNaptrService(naptr.service);
      if (srvTransport == null) {
        continue;
      }
      final srvRecords = await resolver.lookupSrv(naptr.replacement);
      ttl = _minDnsTtl(
        ttl,
        srvRecords.map((record) => Duration(seconds: record.ttl)),
      );
      StunLog.log(
        '[dns] srv name=${naptr.replacement} transport=${srvTransport.name} '
        'records=${srvRecords.length}',
      );
      endpoints.addAll(
        await _srvRecordsToEndpoints(
          host: target.host,
          transport: srvTransport,
          srvRecords: srvRecords,
        ),
      );
    }
  }
  if (endpoints.isNotEmpty) {
    return _ResolvedEndpoints(
      endpoints: List.unmodifiable(endpoints),
      ttl: ttl,
    );
  }

  final fallbackServiceNames = _serviceNamesFor(target);
  for (final serviceName in fallbackServiceNames) {
    final srvRecords = await resolver.lookupSrv(serviceName.name);
    ttl = _minDnsTtl(
      ttl,
      srvRecords.map((record) => Duration(seconds: record.ttl)),
    );
    StunLog.log(
      '[dns] srv-fallback name=${serviceName.name} '
      'transport=${serviceName.transport.name} records=${srvRecords.length}',
    );
    endpoints.addAll(
      await _srvRecordsToEndpoints(
        host: target.host,
        transport: serviceName.transport,
        srvRecords: srvRecords,
      ),
    );
  }
  return _ResolvedEndpoints(
    endpoints: List.unmodifiable(endpoints),
    ttl: ttl,
  );
}

Iterable<_NaptrRecord> _selectNaptrRecords(
  StunServerTarget target,
  List<_NaptrRecord> records,
) {
  final allowedServices = switch (target.transport) {
    Transport.udp => const {'STUN+D2U', 'STUN+D2T'},
    Transport.tcp => const {'STUN+D2T'},
    Transport.tls => const {'STUNS+D2T'},
  };
  final filtered = records
      .where((record) => allowedServices.contains(record.service.toUpperCase()))
      .toList()
    ..sort(
      (left, right) {
        final order = left.order.compareTo(right.order);
        if (order != 0) {
          return order;
        }
        return left.preference.compareTo(right.preference);
      },
    );
  return filtered;
}

List<_SrvServiceName> _serviceNamesFor(StunServerTarget target) {
  switch (target.transport) {
    case Transport.udp:
      return <_SrvServiceName>[
        _SrvServiceName('_stun._udp.${target.host}', Transport.udp),
        _SrvServiceName('_stun._tcp.${target.host}', Transport.tcp),
      ];
    case Transport.tcp:
      return <_SrvServiceName>[
        _SrvServiceName('_stun._tcp.${target.host}', Transport.tcp),
      ];
    case Transport.tls:
      return <_SrvServiceName>[
        _SrvServiceName('_stuns._tcp.${target.host}', Transport.tls),
      ];
  }
}

Future<List<StunServerEndpoint>> _srvRecordsToEndpoints({
  required String host,
  required Transport transport,
  required List<_SrvRecord> srvRecords,
}) async {
  final records = [...srvRecords]..sort(
      (left, right) {
        final priority = left.priority.compareTo(right.priority);
        if (priority != 0) {
          return priority;
        }
        return right.weight.compareTo(left.weight);
      },
    );
  final endpoints = <StunServerEndpoint>[];
  for (final record in records) {
    final addresses = await InternetAddress.lookup(record.target);
    endpoints.addAll(
      addresses.map(
        (address) => StunServerEndpoint(
          host: host,
          address: address,
          port: record.port,
          transport: transport,
        ),
      ),
    );
  }
  return endpoints;
}

List<StunServerEndpoint>? _lookupCachedEndpoints(StunServerTarget target) {
  final entry = _resolvedEndpointCache[_dnsCacheKey(target)];
  if (entry == null) {
    return null;
  }
  if (DateTime.now().isAfter(entry.expiresAt)) {
    _resolvedEndpointCache.remove(_dnsCacheKey(target));
    return null;
  }
  return entry.resolved.endpoints;
}

void _storeResolvedEndpoints(
  StunServerTarget target,
  _ResolvedEndpoints resolved,
) {
  if (!target.enableDnsCache || resolved.endpoints.isEmpty) {
    return;
  }
  final expiresAt = DateTime.now().add(resolved.ttl);
  _resolvedEndpointCache[_dnsCacheKey(target)] = _CachedResolvedEndpoints(
    resolved: resolved,
    expiresAt: expiresAt,
  );
}

String _dnsCacheKey(StunServerTarget target) {
  final servers = target.dnsServers.map((server) => server.address).join(',');
  return '${target.host}|${target.effectivePort}|${target.transport.name}|'
      '${target.enableDnsDiscovery}|$servers';
}

Duration _minDnsTtl(Duration fallback, Iterable<Duration> values) {
  var current = fallback;
  for (final value in values) {
    if (value <= Duration.zero) {
      continue;
    }
    if (value < current) {
      current = value;
    }
  }
  return current;
}

Transport? _transportFromNaptrService(String service) {
  switch (service.toUpperCase()) {
    case 'STUN+D2U':
      return Transport.udp;
    case 'STUN+D2T':
      return Transport.tcp;
    case 'STUNS+D2T':
      return Transport.tls;
  }
  return null;
}

class _SrvServiceName {
  const _SrvServiceName(this.name, this.transport);

  final String name;
  final Transport transport;
}

class _DnsResolver {
  const _DnsResolver({
    required this.nameServers,
  });

  final List<InternetAddress> nameServers;

  Future<List<_SrvRecord>> lookupSrv(String name) async {
    final response = await _query(name, _DnsRecordType.srv);
    return response
        .where((record) => record.type == _DnsRecordType.srv)
        .map(_parseSrvRecord)
        .toList(growable: false);
  }

  Future<List<_NaptrRecord>> lookupNaptr(String name) async {
    final response = await _query(name, _DnsRecordType.naptr);
    return response
        .where((record) => record.type == _DnsRecordType.naptr)
        .map(_parseNaptrRecord)
        .toList(growable: false);
  }

  Future<List<_DnsRecord>> _query(String name, int type) async {
    for (final nameServer in nameServers) {
      RawDatagramSocket? socket;
      try {
        socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
        final queryId = DateTime.now().microsecondsSinceEpoch & 0xffff;
        final message = _encodeQuery(name, type, queryId);
        StunLog.log(
          '[dns] query server=${nameServer.address} name=$name type=$type id=$queryId',
        );
        final completer = Completer<List<_DnsRecord>>();
        late StreamSubscription<RawSocketEvent> subscription;
        subscription = socket.listen((event) {
          if (event != RawSocketEvent.read) {
            return;
          }
          final datagram = socket!.receive();
          if (datagram == null) {
            return;
          }
          final data = datagram.data;
          if (data.length < 12 || readUint16(data, 0) != queryId) {
            return;
          }
          try {
            final records = _parseResponse(data);
            StunLog.log(
              '[dns] response server=${datagram.address.address} '
              'id=$queryId bytes=${data.length} records=${records.length}',
            );
            completer.complete(records);
          } catch (error, stackTrace) {
            StunLog.log(
              '[dns] parse-failed server=${datagram.address.address} '
              'id=$queryId error=$error',
            );
            completer.completeError(error, stackTrace);
          } finally {
            subscription.cancel();
          }
        });
        socket.send(message, nameServer, 53);
        final response = await completer.future.timeout(
          const Duration(seconds: 2),
        );
        socket.close();
        return response;
      } on TimeoutException {
        StunLog.log(
          '[dns] timeout server=${nameServer.address} name=$name type=$type',
        );
        socket?.close();
      } on SocketException catch (error) {
        StunLog.log(
          '[dns] socket-error server=${nameServer.address} name=$name '
          'type=$type error=$error',
        );
        socket?.close();
      } on StunParseException catch (error) {
        StunLog.log(
          '[dns] parse-error server=${nameServer.address} name=$name '
          'type=$type error=$error',
        );
        socket?.close();
      }
    }
    return const <_DnsRecord>[];
  }
}

Uint8List _encodeQuery(String name, int type, int queryId) {
  final builder = BytesBuilder(copy: false);
  writeUint16(builder, queryId);
  writeUint16(builder, 0x0100);
  writeUint16(builder, 1);
  writeUint16(builder, 0);
  writeUint16(builder, 0);
  writeUint16(builder, 0);
  for (final label in name.split('.')) {
    builder.addByte(label.length);
    builder.add(label.codeUnits);
  }
  builder.addByte(0);
  writeUint16(builder, type);
  writeUint16(builder, 1);
  return builder.takeBytes();
}

List<_DnsRecord> _parseResponse(Uint8List message) {
  if (message.length < 12) {
    throw const StunParseException('DNS response is truncated.');
  }
  final flags = readUint16(message, 2);
  final responseCode = flags & 0x000f;
  if (responseCode != 0) {
    return const <_DnsRecord>[];
  }
  final questionCount = readUint16(message, 4);
  final answerCount = readUint16(message, 6);
  final authorityCount = readUint16(message, 8);
  final additionalCount = readUint16(message, 10);
  var offset = 12;
  for (var index = 0; index < questionCount; index++) {
    final decoded = _decodeDomainName(message, offset);
    offset = decoded.nextOffset + 4;
  }
  final recordCount = answerCount + authorityCount + additionalCount;
  final records = <_DnsRecord>[];
  for (var index = 0; index < recordCount; index++) {
    final name = _decodeDomainName(message, offset);
    offset = name.nextOffset;
    final type = readUint16(message, offset);
    final ttl = readUint32(message, offset + 4);
    final length = readUint16(message, offset + 8);
    final dataStart = offset + 10;
    final dataEnd = dataStart + length;
    if (dataEnd > message.length) {
      throw const StunParseException('DNS resource record is truncated.');
    }
    records.add(
      _DnsRecord(
        name: name.name,
        type: type,
        ttl: ttl,
        message: message,
        dataOffset: dataStart,
        dataLength: length,
      ),
    );
    offset = dataEnd;
  }
  return records;
}

_SrvRecord _parseSrvRecord(_DnsRecord record) {
  if (record.dataLength < 7) {
    throw const StunParseException('SRV record is truncated.');
  }
  final priority = readUint16(record.message, record.dataOffset);
  final weight = readUint16(record.message, record.dataOffset + 2);
  final port = readUint16(record.message, record.dataOffset + 4);
  final target = _decodeDomainName(record.message, record.dataOffset + 6).name;
  return _SrvRecord(
    priority: priority,
    weight: weight,
    port: port,
    target: target,
    ttl: record.ttl,
  );
}

_NaptrRecord _parseNaptrRecord(_DnsRecord record) {
  if (record.dataLength < 7) {
    throw const StunParseException('NAPTR record is truncated.');
  }
  var offset = record.dataOffset;
  final order = readUint16(record.message, offset);
  offset += 2;
  final preference = readUint16(record.message, offset);
  offset += 2;
  final flags = _readCharacterString(record.message, offset);
  offset = flags.nextOffset;
  final service = _readCharacterString(record.message, offset);
  offset = service.nextOffset;
  final regexp = _readCharacterString(record.message, offset);
  offset = regexp.nextOffset;
  final replacement = _decodeDomainName(record.message, offset).name;
  return _NaptrRecord(
    order: order,
    preference: preference,
    flags: flags.value,
    service: service.value,
    regexp: regexp.value,
    replacement: replacement,
    ttl: record.ttl,
  );
}

_DecodedName _decodeDomainName(Uint8List message, int offset) {
  final labels = <String>[];
  var currentOffset = offset;
  var jumped = false;
  var nextOffset = offset;
  final visited = <int>{};
  while (true) {
    if (currentOffset >= message.length) {
      throw const StunParseException('DNS name exceeds message length.');
    }
    if (!visited.add(currentOffset)) {
      throw const StunParseException('DNS name compression loop detected.');
    }
    final length = message[currentOffset];
    if (length == 0) {
      if (!jumped) {
        nextOffset = currentOffset + 1;
      }
      break;
    }
    final pointerMask = length & 0xc0;
    if (pointerMask == 0xc0) {
      if (currentOffset + 1 >= message.length) {
        throw const StunParseException('DNS compression pointer is truncated.');
      }
      final pointer = ((length & 0x3f) << 8) | message[currentOffset + 1];
      if (!jumped) {
        nextOffset = currentOffset + 2;
      }
      currentOffset = pointer;
      jumped = true;
      continue;
    }
    final start = currentOffset + 1;
    final end = start + length;
    if (end > message.length) {
      throw const StunParseException('DNS label is truncated.');
    }
    labels.add(String.fromCharCodes(message.sublist(start, end)));
    currentOffset = end;
    if (!jumped) {
      nextOffset = currentOffset;
    }
  }
  return _DecodedName(labels.join('.'), nextOffset);
}

_ReadStringResult _readCharacterString(Uint8List data, int offset) {
  if (offset >= data.length) {
    throw const StunParseException('DNS character-string is truncated.');
  }
  final length = data[offset];
  final start = offset + 1;
  final end = start + length;
  if (end > data.length) {
    throw const StunParseException(
        'DNS character-string payload is truncated.');
  }
  return _ReadStringResult(
    String.fromCharCodes(data.sublist(start, end)),
    end,
  );
}

class _DnsRecord {
  const _DnsRecord({
    required this.name,
    required this.type,
    required this.ttl,
    required this.message,
    required this.dataOffset,
    required this.dataLength,
  });

  final String name;
  final int type;
  final int ttl;
  final Uint8List message;
  final int dataOffset;
  final int dataLength;
}

class _SrvRecord {
  const _SrvRecord({
    required this.priority,
    required this.weight,
    required this.port,
    required this.target,
    required this.ttl,
  });

  final int priority;
  final int weight;
  final int port;
  final String target;
  final int ttl;
}

class _NaptrRecord {
  const _NaptrRecord({
    required this.order,
    required this.preference,
    required this.flags,
    required this.service,
    required this.regexp,
    required this.replacement,
    required this.ttl,
  });

  final int order;
  final int preference;
  final String flags;
  final String service;
  final String regexp;
  final String replacement;
  final int ttl;
}

class _DecodedName {
  const _DecodedName(this.name, this.nextOffset);

  final String name;
  final int nextOffset;
}

class _ReadStringResult {
  const _ReadStringResult(this.value, this.nextOffset);

  final String value;
  final int nextOffset;
}

abstract final class _DnsRecordType {
  static const int srv = 33;
  static const int naptr = 35;
}

final List<InternetAddress> _defaultDnsServers = <InternetAddress>[
  InternetAddress('1.1.1.1'),
  InternetAddress('8.8.8.8'),
];
