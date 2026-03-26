import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../client/stun_backoff_strategy.dart';
import '../client/stun_discovery.dart';
import '../client/stun_server_target.dart';
import '../client/stun_transport.dart';
import '../common/binary_utils.dart';
import '../common/stun_capabilities.dart';
import '../common/exceptions.dart';
import '../common/stun_log.dart';
import '../message/stun_message.dart';

enum NatReachability {
  reachable,
  udpBlocked,
  undetermined,
}

enum NatMappingBehavior {
  endpointIndependent,
  addressDependent,
  addressAndPortDependent,
  unsupported,
  undetermined,
}

enum NatFilteringBehavior {
  endpointIndependent,
  addressDependent,
  addressAndPortDependent,
  unsupported,
  undetermined,
}

enum NatProbeStatus {
  yes,
  no,
  unsupported,
  undetermined,
}

enum NatLegacyType {
  openInternet,
  fullCone,
  restrictedCone,
  portRestrictedCone,
  symmetric,
  symmetricUdpFirewall,
  udpBlocked,
  unknown,
}

class NatBehaviorReport {
  const NatBehaviorReport({
    required this.reachability,
    required this.serverEndpoint,
    required this.localAddress,
    required this.mappedAddress,
    required this.isNatted,
    required this.mappingBehavior,
    required this.filteringBehavior,
    required this.bindingLifetimeEstimate,
    required this.hairpinning,
    required this.fragmentHandling,
    required this.algDetected,
    required this.serverCapabilities,
    required this.legacyNatType,
    required this.warnings,
  });

  factory NatBehaviorReport.fromJson(Map<String, Object?> json) {
    return NatBehaviorReport(
      reachability:
          NatReachability.values.byName(json['reachability'] as String),
      serverEndpoint: StunServerEndpoint.fromJson(
        Map<String, Object?>.from(
            json['serverEndpoint'] as Map<Object?, Object?>),
      ),
      localAddress: _transportAddressFromJson(json['localAddress']),
      mappedAddress: _transportAddressFromJson(json['mappedAddress']),
      isNatted: json['isNatted'] as bool?,
      mappingBehavior:
          NatMappingBehavior.values.byName(json['mappingBehavior'] as String),
      filteringBehavior: NatFilteringBehavior.values
          .byName(json['filteringBehavior'] as String),
      bindingLifetimeEstimate: switch (json['bindingLifetimeEstimateMs']) {
        final int milliseconds => Duration(milliseconds: milliseconds),
        _ => null,
      },
      hairpinning: NatProbeStatus.values.byName(json['hairpinning'] as String),
      fragmentHandling:
          NatProbeStatus.values.byName(json['fragmentHandling'] as String),
      algDetected: json['algDetected'] as bool?,
      serverCapabilities: StunServerCapabilities.fromJson(
        Map<String, Object?>.from(
          json['serverCapabilities'] as Map<Object?, Object?>,
        ),
      ),
      legacyNatType:
          NatLegacyType.values.byName(json['legacyNatType'] as String),
      warnings: List<String>.unmodifiable(
        (json['warnings'] as List<Object?>).cast<String>(),
      ),
    );
  }

  final NatReachability reachability;
  final StunServerEndpoint serverEndpoint;
  final StunTransportAddress? localAddress;
  final StunTransportAddress? mappedAddress;
  final bool? isNatted;
  final NatMappingBehavior mappingBehavior;
  final NatFilteringBehavior filteringBehavior;
  final Duration? bindingLifetimeEstimate;
  final NatProbeStatus hairpinning;
  final NatProbeStatus fragmentHandling;
  final bool? algDetected;
  final StunServerCapabilities serverCapabilities;
  final NatLegacyType legacyNatType;
  final List<String> warnings;

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'reachability': reachability.name,
      'serverEndpoint': serverEndpoint.toJson(),
      'localAddress': localAddress?.toJson(),
      'mappedAddress': mappedAddress?.toJson(),
      'isNatted': isNatted,
      'mappingBehavior': mappingBehavior.name,
      'filteringBehavior': filteringBehavior.name,
      'bindingLifetimeEstimateMs': bindingLifetimeEstimate?.inMilliseconds,
      'hairpinning': hairpinning.name,
      'fragmentHandling': fragmentHandling.name,
      'algDetected': algDetected,
      'serverCapabilities': serverCapabilities.toJson(),
      'legacyNatType': legacyNatType.name,
      'warnings': List<String>.from(warnings),
    };
  }

  @override
  String toString() {
    return 'NatBehaviorReport(reachability: $reachability, '
        'serverEndpoint: $serverEndpoint, localAddress: $localAddress, '
        'mappedAddress: $mappedAddress, isNatted: $isNatted, '
        'mappingBehavior: $mappingBehavior, filteringBehavior: $filteringBehavior, '
        'bindingLifetimeEstimate: $bindingLifetimeEstimate, hairpinning: $hairpinning, '
        'fragmentHandling: $fragmentHandling, algDetected: $algDetected, '
        'serverCapabilities: $serverCapabilities, legacyNatType: $legacyNatType, '
        'warnings: $warnings)';
  }
}

class NatDetector {
  NatDetector({
    required StunServerTarget target,
    this.localAddress,
    this.localPort = 0,
    this.initialRto = const Duration(milliseconds: 500),
    this.backoffStrategy = StunBackoffStrategy.linear,
    this.maxRetransmissions = 7,
    this.responseTimeoutMultiplier = 16,
    this.requestTimeout = const Duration(seconds: 3),
    this.initialBindingLifetimeProbe = const Duration(seconds: 15),
    this.maxBindingLifetimeProbe = const Duration(minutes: 2),
    this.bindingLifetimePrecision = const Duration(seconds: 1),
    this.fragmentPaddingBytes = 1400,
    this.includeFingerprint = true,
    this.software = 'dart_stun',
  }) : target = target.copyWith(transport: Transport.udp);

  factory NatDetector.fromUri(
    String uri, {
    String? localIp,
    int localPort = 0,
    Duration initialRto = const Duration(milliseconds: 200),
    StunBackoffStrategy backoffStrategy = StunBackoffStrategy.linear,
    int maxRetransmissions = 2,
    int responseTimeoutMultiplier = 2,
    Duration requestTimeout = const Duration(seconds: 1),
    Duration initialBindingLifetimeProbe = const Duration(milliseconds: 300),
    Duration maxBindingLifetimeProbe = const Duration(milliseconds: 1000),
    Duration bindingLifetimePrecision = const Duration(milliseconds: 200),
    int fragmentPaddingBytes = 1024,
    bool includeFingerprint = true,
    String? software,
    List<InternetAddress> dnsServers = const <InternetAddress>[],
    bool enableDnsDiscovery = true,
    bool enableDnsCache = true,
    Duration dnsCacheTtl = const Duration(minutes: 1),
  }) {
    return NatDetector(
      target: StunServerTarget.uri(
        uri,
        dnsServers: dnsServers,
        enableDnsDiscovery: enableDnsDiscovery,
        enableDnsCache: enableDnsCache,
        dnsCacheTtl: dnsCacheTtl,
      ).copyWith(transport: Transport.udp),
      localAddress: localIp == null ? null : InternetAddress(localIp),
      localPort: localPort,
      initialRto: initialRto,
      backoffStrategy: backoffStrategy,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
      requestTimeout: requestTimeout,
      initialBindingLifetimeProbe: initialBindingLifetimeProbe,
      maxBindingLifetimeProbe: maxBindingLifetimeProbe,
      bindingLifetimePrecision: bindingLifetimePrecision,
      fragmentPaddingBytes: fragmentPaddingBytes,
      includeFingerprint: includeFingerprint,
      software: software,
    );
  }

  final StunServerTarget target;
  final InternetAddress? localAddress;
  final int localPort;
  final Duration initialRto;
  final StunBackoffStrategy backoffStrategy;
  final int maxRetransmissions;
  final int responseTimeoutMultiplier;
  final Duration requestTimeout;
  final Duration initialBindingLifetimeProbe;
  final Duration maxBindingLifetimeProbe;
  final Duration bindingLifetimePrecision;
  final int fragmentPaddingBytes;
  final bool includeFingerprint;
  final String? software;

  Future<NatBehaviorReport> check() => detect();

  Future<NatBehaviorReport> detect() async {
    final warnings = <String>[];
    final endpoint = await _resolveUdpEndpoint();
    StunLog.log('[nat] detect-start endpoint=${summarizeEndpoint(endpoint)}');
    var capabilities = const StunServerCapabilities();
    final baselineSession = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    try {
      final baselineResponse = await _sendBindingRequest(
        session: baselineSession,
        endpoint: endpoint,
      );
      if (baselineResponse == null) {
        StunLog.log('[nat] baseline reachability=udpBlocked');
        return NatBehaviorReport(
          reachability: NatReachability.udpBlocked,
          serverEndpoint: endpoint,
          localAddress: StunTransportAddress(
            address: baselineSession.localAddress,
            port: baselineSession.localPort,
          ),
          mappedAddress: null,
          isNatted: null,
          mappingBehavior: NatMappingBehavior.undetermined,
          filteringBehavior: NatFilteringBehavior.undetermined,
          bindingLifetimeEstimate: null,
          hairpinning: NatProbeStatus.undetermined,
          fragmentHandling: NatProbeStatus.undetermined,
          algDetected: null,
          serverCapabilities: capabilities,
          legacyNatType: NatLegacyType.udpBlocked,
          warnings: const <String>['No UDP STUN response received.'],
        );
      }

      final localTransportAddress = StunTransportAddress(
        address: baselineSession.localAddress,
        port: baselineSession.localPort,
      );
      final mappedAddress = _mappedAddressFrom(baselineResponse.message);
      final otherAddress = _otherAddressFrom(baselineResponse.message);
      final responseOrigin = _responseOriginFrom(baselineResponse.message);
      capabilities = capabilities.copyWith(
        otherAddress: otherAddress == null
            ? NatCapabilitySupport.unsupported
            : NatCapabilitySupport.supported,
        responseOrigin: responseOrigin == null
            ? NatCapabilitySupport.unsupported
            : NatCapabilitySupport.supported,
      );

      final isNatted = mappedAddress == null
          ? null
          : !(await _mappedAddressLooksLocal(
              session: baselineSession,
              mappedAddress: mappedAddress,
              endpointType: endpoint.address.type,
            ));
      final algDetected = _detectAlg(baselineResponse.message);
      if (mappedAddress == null) {
        warnings
            .add('Baseline STUN response did not include a mapped address.');
      }
      if (otherAddress == null) {
        warnings.add('Server did not provide OTHER-ADDRESS/CHANGED-ADDRESS.');
      }

      final mappingBehavior = await _detectMappingBehavior(
        endpoint: endpoint,
        session: baselineSession,
        mappedAddress: mappedAddress,
        otherAddress: otherAddress,
        warnings: warnings,
      );
      StunLog.log('[nat] mapping-behavior result=${mappingBehavior.name}');

      final filteringProbe = await _detectFilteringBehavior(
        endpoint: endpoint,
        warnings: warnings,
      );
      StunLog.log(
        '[nat] filtering-behavior result=${filteringProbe.behavior.name}',
      );
      capabilities = capabilities.copyWith(
        changeRequest: filteringProbe.changeRequestSupport,
      );

      final lifetimeProbe = await _detectBindingLifetime(
        endpoint: endpoint,
        mappedAddress: mappedAddress,
        warnings: warnings,
      );
      StunLog.log(
        '[nat] binding-lifetime estimate=${lifetimeProbe.lifetimeEstimate} '
        'responsePort=${lifetimeProbe.responsePortSupport.name}',
      );
      capabilities = capabilities.copyWith(
        responsePort: lifetimeProbe.responsePortSupport,
      );

      final hairpinning = isNatted == false
          ? NatProbeStatus.unsupported
          : await _detectHairpinning(
              endpoint: endpoint,
              mappedAddress: mappedAddress,
              warnings: warnings,
            );
      StunLog.log('[nat] hairpinning result=${hairpinning.name}');

      final fragmentProbe = await _detectFragmentHandling(
        endpoint: endpoint,
        warnings: warnings,
      );
      StunLog.log(
        '[nat] fragment-handling result=${fragmentProbe.status.name} '
        'padding=${fragmentProbe.paddingSupport.name}',
      );
      capabilities = capabilities.copyWith(
        padding: fragmentProbe.paddingSupport,
      );

      final legacyNatType = _deriveLegacyNatType(
        reachability: NatReachability.reachable,
        isNatted: isNatted,
        mappingBehavior: mappingBehavior,
        filteringBehavior: filteringProbe.behavior,
      );
      StunLog.log(
        '[nat] detect-finished legacy=${legacyNatType.name} '
        'mapped=$mappedAddress local=$localTransportAddress warnings=${warnings.length}',
      );

      return NatBehaviorReport(
        reachability: NatReachability.reachable,
        serverEndpoint: endpoint,
        localAddress: localTransportAddress,
        mappedAddress: mappedAddress,
        isNatted: isNatted,
        mappingBehavior: mappingBehavior,
        filteringBehavior: filteringProbe.behavior,
        bindingLifetimeEstimate: lifetimeProbe.lifetimeEstimate,
        hairpinning: hairpinning,
        fragmentHandling: fragmentProbe.status,
        algDetected: algDetected,
        serverCapabilities: capabilities,
        legacyNatType: legacyNatType,
        warnings: List.unmodifiable(warnings),
      );
    } finally {
      await baselineSession.close();
    }
  }

  Future<StunServerEndpoint> _resolveUdpEndpoint() async {
    final endpoints =
        await resolveStunTarget(target.copyWith(transport: Transport.udp));
    if (endpoints.isEmpty) {
      throw StunDiscoveryException(
        'No UDP STUN endpoint could be resolved for ${target.host}.',
      );
    }
    return endpoints.first;
  }

  Future<StunInboundPacket?> _sendBindingRequest({
    required StunUdpBinding session,
    required StunServerEndpoint endpoint,
    List<StunAttribute> attributes = const <StunAttribute>[],
  }) {
    final request = StunMessage.bindingRequest(attributes: attributes);
    final payload = request.encode(
      includeFingerprint: includeFingerprint,
      software: software,
    );
    return session.request(
      message: request,
      payload: payload,
      endpoint: endpoint,
      initialRto: initialRto,
      backoffStrategy: backoffStrategy,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
    );
  }
}

typedef NatChecker = NatDetector;

class _FilteringProbeResult {
  const _FilteringProbeResult({
    required this.behavior,
    required this.changeRequestSupport,
  });

  final NatFilteringBehavior behavior;
  final NatCapabilitySupport changeRequestSupport;
}

class _LifetimeProbeResult {
  const _LifetimeProbeResult({
    required this.lifetimeEstimate,
    required this.responsePortSupport,
  });

  final Duration? lifetimeEstimate;
  final NatCapabilitySupport responsePortSupport;
}

class _FragmentProbeResult {
  const _FragmentProbeResult({
    required this.status,
    required this.paddingSupport,
  });

  final NatProbeStatus status;
  final NatCapabilitySupport paddingSupport;
}

extension _NatDetectorCore on NatDetector {
  Future<bool> _mappedAddressLooksLocal({
    required StunUdpBinding session,
    required StunTransportAddress mappedAddress,
    required InternetAddressType endpointType,
  }) async {
    final boundAddress = session.localAddress;
    final isAnyV4 = bytesEqual(
      boundAddress.rawAddress,
      InternetAddress.anyIPv4.rawAddress,
    );
    final isAnyV6 = bytesEqual(
      boundAddress.rawAddress,
      InternetAddress.anyIPv6.rawAddress,
    );
    if (!isAnyV4 && !isAnyV6) {
      return mappedAddress.port == session.localPort &&
          bytesEqual(mappedAddress.address.rawAddress, boundAddress.rawAddress);
    }
    try {
      final interfaces = await NetworkInterface.list(
        includeLinkLocal: true,
        includeLoopback: true,
        type: endpointType,
      );
      for (final interface in interfaces) {
        for (final address in interface.addresses) {
          if (mappedAddress.port == session.localPort &&
              bytesEqual(
                  address.rawAddress, mappedAddress.address.rawAddress)) {
            return true;
          }
        }
      }
    } on SocketException {
      return false;
    }
    return false;
  }

  Future<NatMappingBehavior> _detectMappingBehavior({
    required StunServerEndpoint endpoint,
    required StunUdpBinding session,
    required StunTransportAddress? mappedAddress,
    required StunTransportAddress? otherAddress,
    required List<String> warnings,
  }) async {
    if (mappedAddress == null) {
      return NatMappingBehavior.undetermined;
    }
    if (otherAddress == null) {
      return NatMappingBehavior.unsupported;
    }

    final alternateIpEndpoint = StunServerEndpoint(
      host: endpoint.host,
      address: otherAddress.address,
      port: endpoint.port,
      transport: Transport.udp,
    );
    final alternateIpResponse = await _sendBindingRequest(
      session: session,
      endpoint: alternateIpEndpoint,
    );
    final mapped2 = alternateIpResponse == null
        ? null
        : _mappedAddressFrom(alternateIpResponse.message);
    if (mapped2 == null) {
      warnings.add('Mapping behavior test II did not yield a mapped address.');
      return NatMappingBehavior.undetermined;
    }
    if (mapped2 == mappedAddress) {
      return NatMappingBehavior.endpointIndependent;
    }

    final alternateIpPortEndpoint = StunServerEndpoint(
      host: endpoint.host,
      address: otherAddress.address,
      port: otherAddress.port,
      transport: Transport.udp,
    );
    final alternateIpPortResponse = await _sendBindingRequest(
      session: session,
      endpoint: alternateIpPortEndpoint,
    );
    final mapped3 = alternateIpPortResponse == null
        ? null
        : _mappedAddressFrom(alternateIpPortResponse.message);
    if (mapped3 == null) {
      warnings.add('Mapping behavior test III did not yield a mapped address.');
      return NatMappingBehavior.undetermined;
    }
    if (mapped3 == mapped2) {
      return NatMappingBehavior.addressDependent;
    }
    return NatMappingBehavior.addressAndPortDependent;
  }

  Future<_FilteringProbeResult> _detectFilteringBehavior({
    required StunServerEndpoint endpoint,
    required List<String> warnings,
  }) async {
    final session = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    try {
      final baseline = await _sendBindingRequest(
        session: session,
        endpoint: endpoint,
      );
      if (baseline == null) {
        warnings.add('Filtering baseline request did not receive a response.');
        return const _FilteringProbeResult(
          behavior: NatFilteringBehavior.undetermined,
          changeRequestSupport: NatCapabilitySupport.unknown,
        );
      }
      final otherAddress = _otherAddressFrom(baseline.message);
      if (otherAddress == null) {
        return const _FilteringProbeResult(
          behavior: NatFilteringBehavior.unsupported,
          changeRequestSupport: NatCapabilitySupport.unsupported,
        );
      }

      final testTwo = await _sendBindingRequest(
        session: session,
        endpoint: endpoint,
        attributes: const <StunAttribute>[
          StunChangeRequestAttribute(changeIp: true, changePort: true),
        ],
      );
      if (_isExplicitUnsupported(testTwo?.message)) {
        return const _FilteringProbeResult(
          behavior: NatFilteringBehavior.unsupported,
          changeRequestSupport: NatCapabilitySupport.unsupported,
        );
      }
      if (testTwo != null) {
        return const _FilteringProbeResult(
          behavior: NatFilteringBehavior.endpointIndependent,
          changeRequestSupport: NatCapabilitySupport.supported,
        );
      }

      final testThree = await _sendBindingRequest(
        session: session,
        endpoint: endpoint,
        attributes: const <StunAttribute>[
          StunChangeRequestAttribute(changePort: true),
        ],
      );
      if (_isExplicitUnsupported(testThree?.message)) {
        return const _FilteringProbeResult(
          behavior: NatFilteringBehavior.unsupported,
          changeRequestSupport: NatCapabilitySupport.unsupported,
        );
      }
      if (testThree != null) {
        return const _FilteringProbeResult(
          behavior: NatFilteringBehavior.addressDependent,
          changeRequestSupport: NatCapabilitySupport.supported,
        );
      }
      return const _FilteringProbeResult(
        behavior: NatFilteringBehavior.addressAndPortDependent,
        changeRequestSupport: NatCapabilitySupport.unknown,
      );
    } finally {
      await session.close();
    }
  }

  Future<_LifetimeProbeResult> _detectBindingLifetime({
    required StunServerEndpoint endpoint,
    required StunTransportAddress? mappedAddress,
    required List<String> warnings,
  }) async {
    if (mappedAddress == null) {
      return const _LifetimeProbeResult(
        lifetimeEstimate: null,
        responsePortSupport: NatCapabilitySupport.unknown,
      );
    }
    final primary = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    final secondary = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: 0,
      addressType: endpoint.address.type,
    );
    try {
      final supportProbe = await _probeLifetimeAtDelay(
        primary: primary,
        secondary: secondary,
        endpoint: endpoint,
        responsePort: mappedAddress.port,
        delay: Duration.zero,
      );
      if (supportProbe.support == NatCapabilitySupport.unsupported) {
        warnings
            .add('Server did not honor RESPONSE-PORT during lifetime test.');
        return const _LifetimeProbeResult(
          lifetimeEstimate: null,
          responsePortSupport: NatCapabilitySupport.unsupported,
        );
      }

      var lower = Duration.zero;
      var upper = initialBindingLifetimeProbe;
      _LifetimeOutcome? firstExpired;
      while (upper <= maxBindingLifetimeProbe) {
        final probe = await _probeLifetimeAtDelay(
          primary: primary,
          secondary: secondary,
          endpoint: endpoint,
          responsePort: mappedAddress.port,
          delay: upper,
        );
        if (probe.support == NatCapabilitySupport.unsupported) {
          return const _LifetimeProbeResult(
            lifetimeEstimate: null,
            responsePortSupport: NatCapabilitySupport.unsupported,
          );
        }
        if (probe.bindingAlive == true) {
          lower = upper;
          upper = _multiplyDuration(upper, 2);
          continue;
        }
        firstExpired = probe;
        break;
      }

      if (firstExpired == null) {
        warnings.add(
          'Binding lifetime exceeded the configured maximum probe window.',
        );
        return _LifetimeProbeResult(
          lifetimeEstimate: maxBindingLifetimeProbe,
          responsePortSupport: NatCapabilitySupport.supported,
        );
      }

      while ((upper - lower) > bindingLifetimePrecision) {
        final midpoint = Duration(
          microseconds: lower.inMicroseconds +
              ((upper.inMicroseconds - lower.inMicroseconds) ~/ 2),
        );
        final probe = await _probeLifetimeAtDelay(
          primary: primary,
          secondary: secondary,
          endpoint: endpoint,
          responsePort: mappedAddress.port,
          delay: midpoint,
        );
        if (probe.bindingAlive == true) {
          lower = midpoint;
        } else {
          upper = midpoint;
        }
      }
      return _LifetimeProbeResult(
        lifetimeEstimate: lower,
        responsePortSupport: NatCapabilitySupport.supported,
      );
    } finally {
      await primary.close();
      await secondary.close();
    }
  }

  Future<NatProbeStatus> _detectHairpinning({
    required StunServerEndpoint endpoint,
    required StunTransportAddress? mappedAddress,
    required List<String> warnings,
  }) async {
    if (mappedAddress == null) {
      return NatProbeStatus.undetermined;
    }
    final receiver = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    final sender = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: 0,
      addressType: endpoint.address.type,
    );
    try {
      final baseline = await _sendBindingRequest(
        session: receiver,
        endpoint: endpoint,
      );
      if (baseline == null) {
        return NatProbeStatus.undetermined;
      }
      final request = StunMessage.bindingRequest();
      final payload = request.encode(
        includeFingerprint: includeFingerprint,
        software: software,
      );
      final receiveFuture = receiver.waitForTransaction(
        request.transactionId,
        requestTimeout,
      );
      sender.send(payload, mappedAddress.address, mappedAddress.port);
      final received = await receiveFuture;
      if (received != null) {
        return NatProbeStatus.yes;
      }
      return NatProbeStatus.no;
    } on SocketException {
      warnings.add('Hairpin probe could not send to the mapped address.');
      return NatProbeStatus.undetermined;
    } finally {
      await receiver.close();
      await sender.close();
    }
  }

  Future<_FragmentProbeResult> _detectFragmentHandling({
    required StunServerEndpoint endpoint,
    required List<String> warnings,
  }) async {
    final session = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    try {
      final padding = Uint8List(fragmentPaddingBytes);
      final response = await _sendBindingRequest(
        session: session,
        endpoint: endpoint,
        attributes: <StunAttribute>[StunPaddingAttribute(padding)],
      );
      if (response == null) {
        warnings.add('No response received for padded STUN probe.');
        return const _FragmentProbeResult(
          status: NatProbeStatus.no,
          paddingSupport: NatCapabilitySupport.unknown,
        );
      }
      if (_isExplicitUnsupported(response.message)) {
        return const _FragmentProbeResult(
          status: NatProbeStatus.unsupported,
          paddingSupport: NatCapabilitySupport.unsupported,
        );
      }
      final echoedPadding = response.message.attribute<StunPaddingAttribute>();
      return _FragmentProbeResult(
        status: NatProbeStatus.yes,
        paddingSupport: echoedPadding == null
            ? NatCapabilitySupport.unknown
            : NatCapabilitySupport.supported,
      );
    } finally {
      await session.close();
    }
  }
}

class _LifetimeOutcome {
  const _LifetimeOutcome({
    required this.bindingAlive,
    required this.support,
  });

  final bool? bindingAlive;
  final NatCapabilitySupport support;
}

extension _NatDetectorLifetime on NatDetector {
  Future<_LifetimeOutcome> _probeLifetimeAtDelay({
    required StunUdpBinding primary,
    required StunUdpBinding secondary,
    required StunServerEndpoint endpoint,
    required int responsePort,
    required Duration delay,
  }) async {
    final refresh = await _sendBindingRequest(
      session: primary,
      endpoint: endpoint,
    );
    if (refresh == null) {
      return const _LifetimeOutcome(
        bindingAlive: null,
        support: NatCapabilitySupport.unknown,
      );
    }
    if (delay > Duration.zero) {
      await Future<void>.delayed(delay);
    }

    final request = StunMessage.bindingRequest(
      attributes: <StunAttribute>[StunResponsePortAttribute(responsePort)],
    );
    final payload = request.encode(
      includeFingerprint: includeFingerprint,
      software: software,
    );
    final onPrimary = primary.waitForTransaction(
      request.transactionId,
      requestTimeout,
    );
    final onSecondary = secondary.waitForTransaction(
      request.transactionId,
      requestTimeout,
    );
    secondary.send(payload, endpoint.address, endpoint.port);
    final packets = await _awaitLifetimePackets(onPrimary, onSecondary);
    final primaryPacket = packets.primaryPacket;
    final secondaryPacket = packets.secondaryPacket;

    if (primaryPacket != null) {
      return const _LifetimeOutcome(
        bindingAlive: true,
        support: NatCapabilitySupport.supported,
      );
    }
    if (secondaryPacket != null) {
      final error = secondaryPacket.message.attribute<StunErrorCodeAttribute>();
      if (delay == Duration.zero &&
          error != null &&
          (error.code == 400 || error.code == 420)) {
        return const _LifetimeOutcome(
          bindingAlive: null,
          support: NatCapabilitySupport.unsupported,
        );
      }
      if (delay == Duration.zero) {
        return const _LifetimeOutcome(
          bindingAlive: null,
          support: NatCapabilitySupport.unsupported,
        );
      }
      return const _LifetimeOutcome(
        bindingAlive: false,
        support: NatCapabilitySupport.supported,
      );
    }
    return const _LifetimeOutcome(
      bindingAlive: false,
      support: NatCapabilitySupport.supported,
    );
  }
}

StunTransportAddress? _mappedAddressFrom(StunMessage message) {
  return message.attribute<StunXorMappedAddressAttribute>()?.value ??
      message.attribute<StunMappedAddressAttribute>()?.value;
}

StunTransportAddress? _otherAddressFrom(StunMessage message) {
  return message.attribute<StunOtherAddressAttribute>()?.value ??
      message.attribute<StunChangedAddressAttribute>()?.value;
}

StunTransportAddress? _responseOriginFrom(StunMessage message) {
  return message.attribute<StunResponseOriginAttribute>()?.value ??
      message.attribute<StunSourceAddressAttribute>()?.value;
}

bool? _detectAlg(StunMessage message) {
  final mapped = message.attribute<StunMappedAddressAttribute>()?.value;
  final xorMapped = message.attribute<StunXorMappedAddressAttribute>()?.value;
  if (mapped == null || xorMapped == null) {
    return null;
  }
  return mapped != xorMapped;
}

bool _isExplicitUnsupported(StunMessage? message) {
  final error = message?.attribute<StunErrorCodeAttribute>();
  return error != null && (error.code == 400 || error.code == 420);
}

NatLegacyType _deriveLegacyNatType({
  required NatReachability reachability,
  required bool? isNatted,
  required NatMappingBehavior mappingBehavior,
  required NatFilteringBehavior filteringBehavior,
}) {
  if (reachability == NatReachability.udpBlocked) {
    return NatLegacyType.udpBlocked;
  }
  if (isNatted == false) {
    return filteringBehavior == NatFilteringBehavior.endpointIndependent
        ? NatLegacyType.openInternet
        : NatLegacyType.symmetricUdpFirewall;
  }
  if (mappingBehavior == NatMappingBehavior.addressAndPortDependent) {
    return NatLegacyType.symmetric;
  }
  return switch (filteringBehavior) {
    NatFilteringBehavior.endpointIndependent => NatLegacyType.fullCone,
    NatFilteringBehavior.addressDependent => NatLegacyType.restrictedCone,
    NatFilteringBehavior.addressAndPortDependent =>
      NatLegacyType.portRestrictedCone,
    _ => NatLegacyType.unknown,
  };
}

Duration _multiplyDuration(Duration duration, int factor) {
  return Duration(microseconds: duration.inMicroseconds * factor);
}

class _LifetimePackets {
  const _LifetimePackets({
    required this.primaryPacket,
    required this.secondaryPacket,
  });

  final StunInboundPacket? primaryPacket;
  final StunInboundPacket? secondaryPacket;
}

Future<_LifetimePackets> _awaitLifetimePackets(
  Future<StunInboundPacket?> primaryFuture,
  Future<StunInboundPacket?> secondaryFuture,
) {
  final completer = Completer<_LifetimePackets>();
  StunInboundPacket? primaryPacket;
  StunInboundPacket? secondaryPacket;
  var finished = 0;

  void resolveIfDone() {
    if (primaryPacket != null || secondaryPacket != null) {
      if (!completer.isCompleted) {
        completer.complete(
          _LifetimePackets(
            primaryPacket: primaryPacket,
            secondaryPacket: secondaryPacket,
          ),
        );
      }
      return;
    }
    if (finished == 2 && !completer.isCompleted) {
      completer.complete(
        const _LifetimePackets(primaryPacket: null, secondaryPacket: null),
      );
    }
  }

  primaryFuture.then((value) {
    primaryPacket = value;
    finished += 1;
    resolveIfDone();
  });
  secondaryFuture.then((value) {
    secondaryPacket = value;
    finished += 1;
    resolveIfDone();
  });
  return completer.future;
}

StunTransportAddress? _transportAddressFromJson(Object? rawValue) {
  if (rawValue == null) {
    return null;
  }
  return StunTransportAddress.fromJson(
    Map<String, Object?>.from(rawValue as Map<Object?, Object?>),
  );
}
