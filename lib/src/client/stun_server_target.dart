import 'dart:io';

enum Transport {
  udp,
  tcp,
  tls;

  int get defaultPort => switch (this) {
        Transport.udp => 3478,
        Transport.tcp => 3478,
        Transport.tls => 5349,
      };
}

class StunServerTarget {
  const StunServerTarget({
    required this.host,
    this.port,
    this.transport = Transport.udp,
    this.originalUri,
    this.enableDnsDiscovery = true,
    this.enableDnsCache = true,
    this.dnsCacheTtl = const Duration(minutes: 1),
    this.dnsServers = const <InternetAddress>[],
  });

  factory StunServerTarget.uri(
    String uri, {
    List<InternetAddress> dnsServers = const <InternetAddress>[],
    bool enableDnsDiscovery = true,
    bool enableDnsCache = true,
    Duration dnsCacheTtl = const Duration(minutes: 1),
  }) {
    final normalized = uri.contains('://') ? uri : uri.replaceFirst(':', '://');
    final parsed = Uri.parse(normalized);
    final host = parsed.host;
    if (host.isEmpty) {
      throw ArgumentError.value(uri, 'uri', 'STUN URI must include a host.');
    }
    final scheme = parsed.scheme.toLowerCase();
    final transport = switch (scheme) {
      'stun' => _transportFromQuery(parsed.queryParameters['transport']) ??
          Transport.udp,
      'stuns' => Transport.tls,
      _ => throw ArgumentError.value(
          uri,
          'uri',
          'Unsupported STUN URI scheme.',
        ),
    };
    return StunServerTarget(
      host: host,
      port: parsed.hasPort ? parsed.port : null,
      transport: transport,
      originalUri: uri,
      enableDnsDiscovery: enableDnsDiscovery,
      enableDnsCache: enableDnsCache,
      dnsCacheTtl: dnsCacheTtl,
      dnsServers: List.unmodifiable(dnsServers),
    );
  }

  final String host;
  final int? port;
  final Transport transport;
  final String? originalUri;
  final bool enableDnsDiscovery;
  final bool enableDnsCache;
  final Duration dnsCacheTtl;
  final List<InternetAddress> dnsServers;

  int get effectivePort => port ?? transport.defaultPort;

  bool get hasExplicitPort => port != null;

  bool get isLiteralAddress => InternetAddress.tryParse(host) != null;

  StunServerTarget copyWith({
    String? host,
    int? port,
    Transport? transport,
    String? originalUri,
    bool? enableDnsDiscovery,
    bool? enableDnsCache,
    Duration? dnsCacheTtl,
    List<InternetAddress>? dnsServers,
  }) {
    return StunServerTarget(
      host: host ?? this.host,
      port: port ?? this.port,
      transport: transport ?? this.transport,
      originalUri: originalUri ?? this.originalUri,
      enableDnsDiscovery: enableDnsDiscovery ?? this.enableDnsDiscovery,
      enableDnsCache: enableDnsCache ?? this.enableDnsCache,
      dnsCacheTtl: dnsCacheTtl ?? this.dnsCacheTtl,
      dnsServers: dnsServers ?? this.dnsServers,
    );
  }

  @override
  String toString() {
    return 'StunServerTarget(host: $host, port: $effectivePort, '
        'transport: ${transport.name})';
  }
}

class StunServerEndpoint {
  const StunServerEndpoint({
    required this.host,
    required this.address,
    required this.port,
    required this.transport,
  });

  factory StunServerEndpoint.fromJson(Map<String, Object?> json) {
    final rawAddress = json['address'] as String;
    return StunServerEndpoint(
      host: json['host'] as String,
      address:
          InternetAddress.tryParse(rawAddress) ?? InternetAddress(rawAddress),
      port: json['port'] as int,
      transport: Transport.values.byName(json['transport'] as String),
    );
  }

  final String host;
  final InternetAddress address;
  final int port;
  final Transport transport;

  StunServerEndpoint copyWith({
    String? host,
    InternetAddress? address,
    int? port,
    Transport? transport,
  }) {
    return StunServerEndpoint(
      host: host ?? this.host,
      address: address ?? this.address,
      port: port ?? this.port,
      transport: transport ?? this.transport,
    );
  }

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'host': host,
      'address': address.address,
      'port': port,
      'transport': transport.name,
    };
  }

  @override
  bool operator ==(Object other) {
    return other is StunServerEndpoint &&
        other.host == host &&
        other.port == port &&
        other.transport == transport &&
        other.address.address == address.address;
  }

  @override
  int get hashCode => Object.hash(host, address.address, port, transport);

  @override
  String toString() {
    return 'StunServerEndpoint(host: $host, address: ${address.address}, '
        'port: $port, transport: ${transport.name})';
  }
}

Transport? _transportFromQuery(String? value) {
  return switch (value?.toLowerCase()) {
    null || '' => null,
    'udp' => Transport.udp,
    'tcp' => Transport.tcp,
    'tls' => Transport.tls,
    _ => throw ArgumentError.value(
        value,
        'transport',
        'Unsupported STUN transport in URI.',
      ),
  };
}
