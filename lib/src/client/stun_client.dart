import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../common/stun_capabilities.dart';
import '../common/stun_log.dart';
import '../common/exceptions.dart';
import '../message/stun_message.dart';
import 'stun_backoff_strategy.dart';
import 'stun_discovery.dart';
import 'stun_server_target.dart';
import 'stun_transport.dart';

typedef StunKeepaliveErrorHandler = void Function(
  Object error,
  StackTrace stackTrace,
);

class StunRequestResult {
  StunRequestResult({
    required this.endpoint,
    required this.response,
    required List<StunServerEndpoint> attemptedEndpoints,
    required this.redirectCount,
    required this.elapsed,
    this.alternateServerLoopDetected = false,
    this.redirectLimitReached = false,
  }) : attemptedEndpoints = List.unmodifiable(attemptedEndpoints);

  final StunServerEndpoint endpoint;
  final StunMessage response;
  final List<StunServerEndpoint> attemptedEndpoints;
  final int redirectCount;
  final Duration elapsed;
  final bool alternateServerLoopDetected;
  final bool redirectLimitReached;

  bool get isSuccess =>
      response.messageClass == StunMessageClass.successResponse;

  bool get isError => response.messageClass == StunMessageClass.errorResponse;

  StunErrorCodeAttribute? get errorResponse =>
      response.attribute<StunErrorCodeAttribute>();

  int? get errorCode => errorResponse?.code;

  String? get reasonPhrase => errorResponse?.reasonPhrase;

  StunTransportAddress? get alternateServer =>
      response.attribute<StunAlternateServerAttribute>()?.value;

  bool get isAlternateServerRedirect =>
      errorCode == 300 && alternateServer != null;

  StunRequestResult copyWith({
    StunServerEndpoint? endpoint,
    StunMessage? response,
    List<StunServerEndpoint>? attemptedEndpoints,
    int? redirectCount,
    Duration? elapsed,
    bool? alternateServerLoopDetected,
    bool? redirectLimitReached,
  }) {
    return StunRequestResult(
      endpoint: endpoint ?? this.endpoint,
      response: response ?? this.response,
      attemptedEndpoints: attemptedEndpoints ?? this.attemptedEndpoints,
      redirectCount: redirectCount ?? this.redirectCount,
      elapsed: elapsed ?? this.elapsed,
      alternateServerLoopDetected:
          alternateServerLoopDetected ?? this.alternateServerLoopDetected,
      redirectLimitReached: redirectLimitReached ?? this.redirectLimitReached,
    );
  }

  @override
  String toString() {
    return 'StunRequestResult(endpoint: $endpoint, '
        'class: ${response.messageClass.name}, errorCode: $errorCode, '
        'redirectCount: $redirectCount, attempts: ${attemptedEndpoints.length}, '
        'elapsed: $elapsed, redirectLimitReached: $redirectLimitReached, '
        'alternateServerLoopDetected: $alternateServerLoopDetected)';
  }
}

class StunCapabilityProbeResult {
  StunCapabilityProbeResult({
    required this.endpoint,
    required this.capabilities,
    required this.baselineResult,
    required this.mappedAddress,
    required this.otherAddress,
    required this.responseOrigin,
    required List<String> warnings,
  }) : warnings = List.unmodifiable(warnings);

  final StunServerEndpoint endpoint;
  final StunServerCapabilities capabilities;
  final StunRequestResult baselineResult;
  final StunTransportAddress? mappedAddress;
  final StunTransportAddress? otherAddress;
  final StunTransportAddress? responseOrigin;
  final List<String> warnings;

  @override
  String toString() {
    return 'StunCapabilityProbeResult(endpoint: $endpoint, '
        'capabilities: $capabilities, mappedAddress: $mappedAddress, '
        'otherAddress: $otherAddress, responseOrigin: $responseOrigin, '
        'warnings: $warnings)';
  }
}

class StunKeepaliveHandle {
  StunKeepaliveHandle._(this._stop, this.done);

  final void Function() _stop;
  final Future<void> done;
  bool _stopped = false;

  bool get isStopped => _stopped;

  void stop() {
    if (_stopped) {
      return;
    }
    _stopped = true;
    _stop();
  }
}

class StunSession {
  StunSession._({
    required this.client,
    required StunUdpBinding binding,
    required List<StunServerEndpoint> endpoints,
  })  : _binding = binding,
        _endpoints = List.unmodifiable(endpoints);

  final StunClient client;
  final StunUdpBinding _binding;
  final List<StunServerEndpoint> _endpoints;
  final Set<StunKeepaliveHandle> _keepalives = <StunKeepaliveHandle>{};
  bool _closed = false;

  InternetAddress get localAddress => _binding.localAddress;

  int get localPort => _binding.localPort;

  List<StunServerEndpoint> get endpoints => _endpoints;

  Future<StunRequestResult> sendForResult(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) async {
    _ensureOpen();
    final candidates = endpoint == null
        ? client._candidateEndpoints(_endpoints)
        : <StunServerEndpoint>[endpoint];
    final compatible =
        candidates.where(_supportsEndpoint).toList(growable: false);
    if (compatible.isEmpty) {
      throw const StunUnsupportedException(
        'This STUN session can only send UDP requests to endpoints that match '
        'the session address family.',
      );
    }
    final effectiveTimeout = timeout ?? client.requestTimeout;
    final failedEndpoints = <StunServerEndpoint>[];
    Object? lastError;
    StackTrace? lastStackTrace;
    for (var index = 0; index < compatible.length; index++) {
      final candidate = compatible[index];
      try {
        final result = await client._sendThroughEndpointChain(
          message: message,
          endpoint: candidate,
          timeout: effectiveTimeout,
          binding: _binding,
        );
        return result.copyWith(
          attemptedEndpoints: <StunServerEndpoint>[
            ...failedEndpoints,
            ...result.attemptedEndpoints,
          ],
        );
      } catch (error, stackTrace) {
        failedEndpoints.add(candidate);
        lastError = error;
        lastStackTrace = stackTrace;
        StunLog.log(
          '[stun] endpoint-failed endpoint=${summarizeEndpoint(candidate)} '
          'error=$error',
          category: 'stun',
          action: 'endpoint-failed',
          fields: <String, Object?>{
            'endpoint': summarizeEndpoint(candidate),
            'error': '$error',
          },
        );
        if (endpoint != null || !client.enableEndpointFallback) {
          break;
        }
      }
    }
    if (lastError != null && lastStackTrace != null) {
      Error.throwWithStackTrace(lastError, lastStackTrace);
    }
    throw const StunTimeoutException('Timed out waiting for a STUN response.');
  }

  Future<StunMessage> sendAndAwait(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) async {
    final result = await sendForResult(
      message,
      endpoint: endpoint,
      timeout: timeout,
    );
    return result.response;
  }

  StunKeepaliveHandle startKeepalive({
    Duration interval = const Duration(seconds: 15),
    List<StunAttribute> attributes = const <StunAttribute>[],
    Duration? timeout,
    void Function(StunRequestResult result)? onResponse,
    void Function(
      StunTransportAddress? previous,
      StunTransportAddress? current,
    )? onMappedAddressChanged,
    StunKeepaliveErrorHandler? onError,
  }) {
    _ensureOpen();
    final stopSignal = Completer<void>();
    final doneSignal = Completer<void>();
    final handle = StunKeepaliveHandle._(
      () {
        if (!stopSignal.isCompleted) {
          stopSignal.complete();
        }
      },
      doneSignal.future,
    );
    _keepalives.add(handle);
    unawaited(
      () async {
        StunTransportAddress? lastMappedAddress;
        try {
          while (!stopSignal.isCompleted) {
            final result = await sendForResult(
              client.createBindingRequest(attributes: attributes),
              timeout: timeout,
            );
            onResponse?.call(result);
            final mappedAddress = _mappedAddressFrom(result.response);
            if (mappedAddress != lastMappedAddress) {
              final previous = lastMappedAddress;
              lastMappedAddress = mappedAddress;
              if (previous != null || mappedAddress != null) {
                onMappedAddressChanged?.call(previous, mappedAddress);
              }
            }
            await Future.any<void>(<Future<void>>[
              Future<void>.delayed(interval),
              stopSignal.future,
            ]);
          }
        } catch (error, stackTrace) {
          onError?.call(error, stackTrace);
        } finally {
          _keepalives.remove(handle);
          if (!doneSignal.isCompleted) {
            doneSignal.complete();
          }
        }
      }(),
    );
    return handle;
  }

  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    final handles = _keepalives.toList(growable: false);
    for (final handle in handles) {
      handle.stop();
    }
    if (handles.isNotEmpty) {
      await Future.wait(handles.map((handle) => handle.done));
    }
    await _binding.close();
  }

  void _ensureOpen() {
    if (_closed) {
      throw const StunUnsupportedException('STUN session is already closed.');
    }
  }

  bool _supportsEndpoint(StunServerEndpoint endpoint) {
    return endpoint.transport == Transport.udp &&
        endpoint.address.type == localAddress.type;
  }
}

class StunClient {
  StunClient({
    required this.target,
    this.localAddress,
    this.addressType,
    this.localPort = 0,
    this.stunProtocol = StunProtocol.rfc5389,
    this.credentials,
    this.software,
    this.includeFingerprint = true,
    this.initialRto = const Duration(milliseconds: 500),
    this.backoffStrategy = StunBackoffStrategy.linear,
    this.maxRetransmissions = 7,
    this.responseTimeoutMultiplier = 16,
    this.requestTimeout = const Duration(seconds: 5),
    this.followAlternateServer = true,
    this.maxAlternateServerRedirects = 2,
    this.enableEndpointFallback = true,
    this.onBadCertificate,
  }) : assert(
          addressType == null ||
              localAddress == null ||
              localAddress.type == addressType,
          'localAddress must match addressType when both are provided.',
        );

  factory StunClient.create({
    required Transport transport,
    required String serverHost,
    int? serverPort,
    String? localIp,
    InternetAddressType? addressType,
    int localPort = 0,
    StunProtocol stunProtocol = StunProtocol.rfc5389,
    StunCredentials? credentials,
    String? software,
    bool includeFingerprint = true,
    Duration initialRto = const Duration(milliseconds: 500),
    StunBackoffStrategy backoffStrategy = StunBackoffStrategy.linear,
    int maxRetransmissions = 7,
    int responseTimeoutMultiplier = 16,
    Duration requestTimeout = const Duration(seconds: 5),
    bool followAlternateServer = true,
    int maxAlternateServerRedirects = 2,
    bool enableEndpointFallback = true,
    bool Function(X509Certificate certificate)? onBadCertificate,
    List<InternetAddress> dnsServers = const <InternetAddress>[],
    bool enableDnsDiscovery = true,
    bool enableDnsCache = true,
    Duration dnsCacheTtl = const Duration(minutes: 1),
  }) {
    return StunClient(
      target: StunServerTarget(
        host: serverHost,
        port: serverPort,
        transport: transport,
        enableDnsDiscovery: enableDnsDiscovery,
        enableDnsCache: enableDnsCache,
        dnsCacheTtl: dnsCacheTtl,
        dnsServers: dnsServers,
      ),
      localAddress: localIp == null ? null : InternetAddress(localIp),
      addressType: addressType,
      localPort: localPort,
      stunProtocol: stunProtocol,
      credentials: credentials,
      software: software,
      includeFingerprint: includeFingerprint,
      initialRto: initialRto,
      backoffStrategy: backoffStrategy,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
      requestTimeout: requestTimeout,
      followAlternateServer: followAlternateServer,
      maxAlternateServerRedirects: maxAlternateServerRedirects,
      enableEndpointFallback: enableEndpointFallback,
      onBadCertificate: onBadCertificate,
    );
  }

  factory StunClient.fromUri(
    String uri, {
    String? localIp,
    InternetAddressType? addressType,
    int localPort = 0,
    StunProtocol stunProtocol = StunProtocol.rfc5389,
    StunCredentials? credentials,
    String? software,
    bool includeFingerprint = true,
    Duration initialRto = const Duration(milliseconds: 500),
    StunBackoffStrategy backoffStrategy = StunBackoffStrategy.linear,
    int maxRetransmissions = 7,
    int responseTimeoutMultiplier = 16,
    Duration requestTimeout = const Duration(seconds: 5),
    bool followAlternateServer = true,
    int maxAlternateServerRedirects = 2,
    bool enableEndpointFallback = true,
    bool Function(X509Certificate certificate)? onBadCertificate,
    List<InternetAddress> dnsServers = const <InternetAddress>[],
    bool enableDnsDiscovery = true,
    bool enableDnsCache = true,
    Duration dnsCacheTtl = const Duration(minutes: 1),
  }) {
    return StunClient(
      target: StunServerTarget.uri(
        uri,
        dnsServers: dnsServers,
        enableDnsDiscovery: enableDnsDiscovery,
        enableDnsCache: enableDnsCache,
        dnsCacheTtl: dnsCacheTtl,
      ),
      localAddress: localIp == null ? null : InternetAddress(localIp),
      addressType: addressType,
      localPort: localPort,
      stunProtocol: stunProtocol,
      credentials: credentials,
      software: software,
      includeFingerprint: includeFingerprint,
      initialRto: initialRto,
      backoffStrategy: backoffStrategy,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
      requestTimeout: requestTimeout,
      followAlternateServer: followAlternateServer,
      maxAlternateServerRedirects: maxAlternateServerRedirects,
      enableEndpointFallback: enableEndpointFallback,
      onBadCertificate: onBadCertificate,
    );
  }

  final StunServerTarget target;
  final InternetAddress? localAddress;
  final InternetAddressType? addressType;
  final int localPort;
  final StunProtocol stunProtocol;
  final StunCredentials? credentials;
  final String? software;
  final bool includeFingerprint;
  final Duration initialRto;
  final StunBackoffStrategy backoffStrategy;
  final int maxRetransmissions;
  final int responseTimeoutMultiplier;
  final Duration requestTimeout;
  final bool followAlternateServer;
  final int maxAlternateServerRedirects;
  final bool enableEndpointFallback;
  final bool Function(X509Certificate certificate)? onBadCertificate;

  StunMessage createBindingStunMessage({
    List<StunAttribute> attributes = const <StunAttribute>[],
  }) {
    return StunMessage.bindingRequest(
      legacy: stunProtocol == StunProtocol.rfc3489,
      attributes: attributes,
    );
  }

  StunMessage createBindingRequest({
    List<StunAttribute> attributes = const <StunAttribute>[],
  }) {
    return createBindingStunMessage(attributes: attributes);
  }

  Uint8List encodeMessage(StunMessage message) {
    final encoded = message.encode(
      credentials: credentials,
      includeFingerprint: includeFingerprint,
      software: software,
    );
    StunLog.log(
      '[stun] encode bytes=${encoded.length} ${summarizeStunMessage(message)}',
    );
    return encoded;
  }

  StunMessage parseMessage(
    Uint8List bytes, {
    bool validateFingerprint = false,
  }) {
    final decoded = StunMessage.decode(
      bytes,
      validateFingerprint: validateFingerprint,
    );
    StunLog.log(
      '[stun] parsed bytes=${bytes.length} ${summarizeStunMessage(decoded)}',
    );
    return decoded;
  }

  Future<List<StunServerEndpoint>> resolveEndpoints() {
    return resolveStunTarget(
      target,
      addressType: addressType ?? localAddress?.type,
    );
  }

  Future<StunServerEndpoint> resolveEndpoint() async {
    final endpoints = await resolveEndpoints();
    if (endpoints.isEmpty) {
      throw StunDiscoveryException(
        'No STUN endpoints could be resolved for ${target.host}.',
      );
    }
    return endpoints.first;
  }

  Future<StunRequestResult> sendForResult(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) async {
    final resolvedEndpoints = endpoint == null
        ? await resolveEndpoints()
        : <StunServerEndpoint>[endpoint];
    if (resolvedEndpoints.isEmpty) {
      throw StunDiscoveryException(
        'No STUN endpoints could be resolved for ${target.host}.',
      );
    }
    final effectiveTimeout = timeout ?? requestTimeout;
    final failedEndpoints = <StunServerEndpoint>[];
    final candidates = _candidateEndpoints(resolvedEndpoints);
    Object? lastError;
    StackTrace? lastStackTrace;
    for (var index = 0; index < candidates.length; index++) {
      final candidate = candidates[index];
      try {
        final result = await _sendThroughEndpointChain(
          message: message,
          endpoint: candidate,
          timeout: effectiveTimeout,
        );
        return result.copyWith(
          attemptedEndpoints: <StunServerEndpoint>[
            ...failedEndpoints,
            ...result.attemptedEndpoints,
          ],
        );
      } catch (error, stackTrace) {
        failedEndpoints.add(candidate);
        lastError = error;
        lastStackTrace = stackTrace;
        StunLog.log(
          '[stun] endpoint-failed endpoint=${summarizeEndpoint(candidate)} '
          'error=$error',
          category: 'stun',
          action: 'endpoint-failed',
          fields: <String, Object?>{
            'endpoint': summarizeEndpoint(candidate),
            'error': '$error',
          },
        );
        if (endpoint != null || !enableEndpointFallback) {
          break;
        }
      }
    }
    if (lastError != null && lastStackTrace != null) {
      Error.throwWithStackTrace(lastError, lastStackTrace);
    }
    throw const StunTimeoutException('Timed out waiting for a STUN response.');
  }

  Future<StunMessage> sendAndAwait(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) async {
    final result = await sendForResult(
      message,
      endpoint: endpoint,
      timeout: timeout,
    );
    return result.response;
  }

  Future<StunMessage> send(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) {
    return sendAndAwait(message, endpoint: endpoint, timeout: timeout);
  }

  Future<StunSession> openSession({
    StunServerEndpoint? endpoint,
  }) async {
    final resolvedEndpoints = endpoint == null
        ? await resolveEndpoints()
        : <StunServerEndpoint>[endpoint];
    final candidates = _candidateEndpoints(resolvedEndpoints)
        .where((candidate) => candidate.transport == Transport.udp)
        .where(_supportsConfiguredAddressType)
        .toList(growable: false);
    if (candidates.isEmpty) {
      throw const StunUnsupportedException(
        'Reusable STUN sessions currently support UDP only.',
      );
    }
    final primary = candidates.first;
    final binding = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: primary.address.type,
    );
    final compatibleEndpoints = candidates
        .where((candidate) => candidate.address.type == primary.address.type)
        .toList(growable: false);
    return StunSession._(
      client: this,
      binding: binding,
      endpoints: compatibleEndpoints,
    );
  }

  bool _supportsConfiguredAddressType(StunServerEndpoint endpoint) {
    final effectiveAddressType = addressType ?? localAddress?.type;
    return effectiveAddressType == null ||
        endpoint.address.type == effectiveAddressType;
  }

  Future<StunCapabilityProbeResult> probeServerCapabilities({
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) async {
    final warnings = <String>[];
    final effectiveTimeout = timeout ?? requestTimeout;
    final baselineResult = await sendForResult(
      createBindingRequest(),
      endpoint: endpoint,
      timeout: effectiveTimeout,
    );
    final baselineResponse = baselineResult.response;
    var capabilities = StunServerCapabilities(
      otherAddress: _otherAddressFrom(baselineResponse) == null
          ? NatCapabilitySupport.unsupported
          : NatCapabilitySupport.supported,
      responseOrigin: _responseOriginFrom(baselineResponse) == null
          ? NatCapabilitySupport.unsupported
          : NatCapabilitySupport.supported,
    );
    if (!baselineResult.isSuccess) {
      warnings.add(
        'Baseline capability probe returned ${baselineResult.errorCode ?? "error"} '
                '${baselineResult.reasonPhrase ?? ""}'
            .trim(),
      );
    }
    if (baselineResult.endpoint.transport != Transport.udp) {
      return StunCapabilityProbeResult(
        endpoint: baselineResult.endpoint,
        capabilities: capabilities,
        baselineResult: baselineResult,
        mappedAddress: _mappedAddressFrom(baselineResponse),
        otherAddress: _otherAddressFrom(baselineResponse),
        responseOrigin: _responseOriginFrom(baselineResponse),
        warnings: warnings,
      );
    }

    final session = await openSession(endpoint: baselineResult.endpoint);
    try {
      final changeRequestResult = await session.sendForResult(
        createBindingRequest(
          attributes: const <StunAttribute>[
            StunChangeRequestAttribute(changeIp: true, changePort: true),
          ],
        ),
        endpoint: baselineResult.endpoint,
        timeout: effectiveTimeout,
      );
      capabilities = capabilities.copyWith(
        changeRequest: _explicitSupportFromResult(changeRequestResult),
      );

      final paddingResult = await session.sendForResult(
        createBindingRequest(
          attributes: <StunAttribute>[
            StunPaddingAttribute(Uint8List.fromList(<int>[1, 2, 3, 4])),
          ],
        ),
        endpoint: baselineResult.endpoint,
        timeout: effectiveTimeout,
      );
      capabilities = capabilities.copyWith(
        padding: _paddingSupportFromResult(paddingResult),
      );

      capabilities = capabilities.copyWith(
        responsePort: await _probeResponsePortSupport(
          session: session,
          endpoint: baselineResult.endpoint,
          timeout: effectiveTimeout,
        ),
      );
    } on StunException catch (error) {
      warnings.add('Capability extension probe failed: $error');
    } finally {
      await session.close();
    }

    return StunCapabilityProbeResult(
      endpoint: baselineResult.endpoint,
      capabilities: capabilities,
      baselineResult: baselineResult,
      mappedAddress: _mappedAddressFrom(baselineResponse),
      otherAddress: _otherAddressFrom(baselineResponse),
      responseOrigin: _responseOriginFrom(baselineResponse),
      warnings: warnings,
    );
  }

  List<StunServerEndpoint> _candidateEndpoints(
    List<StunServerEndpoint> endpoints,
  ) {
    if (!enableEndpointFallback || endpoints.length <= 1) {
      return <StunServerEndpoint>[endpoints.first];
    }
    return endpoints;
  }

  Future<StunRequestResult> _sendThroughEndpointChain({
    required StunMessage message,
    required StunServerEndpoint endpoint,
    required Duration timeout,
    StunUdpBinding? binding,
  }) async {
    final stopwatch = Stopwatch()..start();
    final attemptedEndpoints = <StunServerEndpoint>[];
    final visitedEndpoints = <String>{};
    var redirectCount = 0;
    var redirectLimitReached = false;
    var alternateServerLoopDetected = false;
    var currentEndpoint = endpoint;
    late StunMessage response;
    while (true) {
      attemptedEndpoints.add(currentEndpoint);
      visitedEndpoints.add(_endpointKey(currentEndpoint));
      response = await _sendOnce(
        message: message,
        endpoint: currentEndpoint,
        timeout: timeout,
        binding: binding,
      );
      if (!followAlternateServer) {
        break;
      }
      final alternateServer = _alternateServerEndpoint(
        currentEndpoint,
        response,
      );
      if (alternateServer == null) {
        break;
      }
      if (binding != null &&
          !_bindingSupportsEndpoint(binding, alternateServer)) {
        StunLog.log(
          '[stun] redirect-skipped endpoint=${summarizeEndpoint(alternateServer)} '
          'reason=session-address-family-mismatch',
          category: 'stun',
          action: 'redirect-skipped',
          fields: <String, Object?>{
            'endpoint': summarizeEndpoint(alternateServer),
            'reason': 'session-address-family-mismatch',
          },
        );
        break;
      }
      if (redirectCount >= maxAlternateServerRedirects) {
        redirectLimitReached = true;
        break;
      }
      final redirectKey = _endpointKey(alternateServer);
      if (visitedEndpoints.contains(redirectKey)) {
        alternateServerLoopDetected = true;
        break;
      }
      redirectCount += 1;
      StunLog.log(
        '[stun] redirect-follow from=${summarizeEndpoint(currentEndpoint)} '
        'to=${summarizeEndpoint(alternateServer)} '
        'count=$redirectCount',
        category: 'stun',
        action: 'redirect-follow',
        fields: <String, Object?>{
          'from': summarizeEndpoint(currentEndpoint),
          'to': summarizeEndpoint(alternateServer),
          'count': redirectCount,
        },
      );
      currentEndpoint = alternateServer;
    }
    stopwatch.stop();
    return StunRequestResult(
      endpoint: currentEndpoint,
      response: response,
      attemptedEndpoints: attemptedEndpoints,
      redirectCount: redirectCount,
      elapsed: stopwatch.elapsed,
      alternateServerLoopDetected: alternateServerLoopDetected,
      redirectLimitReached: redirectLimitReached,
    );
  }

  Future<StunMessage> _sendOnce({
    required StunMessage message,
    required StunServerEndpoint endpoint,
    required Duration timeout,
    StunUdpBinding? binding,
  }) async {
    final payload = encodeMessage(message);
    StunLog.log(
      '[stun] request transport=${endpoint.transport.name} '
      'timeoutMs=${timeout.inMilliseconds} '
      'endpoint=${summarizeEndpoint(endpoint)} '
      '${summarizeStunMessage(message)}',
      category: 'stun',
      action: 'request',
      fields: <String, Object?>{
        'transport': endpoint.transport.name,
        'timeoutMs': timeout.inMilliseconds,
        'endpoint': summarizeEndpoint(endpoint),
        'transactionId': _transactionIdOf(message),
      },
    );
    switch (endpoint.transport) {
      case Transport.udp:
        return _sendOverUdp(
          message: message,
          endpoint: endpoint,
          payload: payload,
          binding: binding,
        );
      case Transport.tcp:
        return _sendOverTcp(
          endpoint: endpoint,
          payload: payload,
          timeout: timeout,
          secure: false,
        );
      case Transport.tls:
        return _sendOverTcp(
          endpoint: endpoint,
          payload: payload,
          timeout: timeout,
          secure: true,
        );
    }
  }

  Future<StunMessage> _sendOverUdp({
    required StunMessage message,
    required StunServerEndpoint endpoint,
    required Uint8List payload,
    StunUdpBinding? binding,
  }) async {
    if (binding != null) {
      return _sendOverUdpBinding(
        binding: binding,
        message: message,
        endpoint: endpoint,
        payload: payload,
      );
    }
    final localBinding = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    try {
      return await _sendOverUdpBinding(
        binding: localBinding,
        message: message,
        endpoint: endpoint,
        payload: payload,
      );
    } finally {
      await localBinding.close();
    }
  }

  Future<StunMessage> _sendOverUdpBinding({
    required StunUdpBinding binding,
    required StunMessage message,
    required StunServerEndpoint endpoint,
    required Uint8List payload,
  }) async {
    final response = await binding.request(
      message: message,
      payload: payload,
      endpoint: endpoint,
      initialRto: initialRto,
      backoffStrategy: backoffStrategy,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
    );
    if (response == null) {
      throw StunTimeoutException(
        'Timed out waiting for STUN response from $endpoint.',
      );
    }
    StunLog.log(
      '[stun] response endpoint=${summarizeEndpoint(endpoint)} '
      'remote=${response.remoteAddress.address}:${response.remotePort} '
      '${summarizeStunMessage(response.message)}',
      category: 'stun',
      action: 'response',
      fields: <String, Object?>{
        'endpoint': summarizeEndpoint(endpoint),
        'remote': '${response.remoteAddress.address}:${response.remotePort}',
        'transactionId': _transactionIdOf(response.message),
        'class': response.message.messageClass.name,
      },
    );
    return response.message;
  }

  Future<StunMessage> _sendOverTcp({
    required StunServerEndpoint endpoint,
    required Uint8List payload,
    required Duration timeout,
    required bool secure,
  }) async {
    if (secure) {
      final socket = await SecureSocket.connect(
        endpoint.address,
        endpoint.port,
        timeout: timeout,
        onBadCertificate: onBadCertificate,
      );
      try {
        StunLog.log(
          '[stun] tcp-send secure=true bytes=${payload.length} '
          'endpoint=${summarizeEndpoint(endpoint)}',
        );
        socket.add(payload);
        await socket.flush();
        final response = await readSingleStunMessageFromStream(
          socket,
          timeout: timeout,
        );
        StunLog.log(
          '[stun] tcp-response secure=true endpoint=${summarizeEndpoint(endpoint)} '
          '${summarizeStunMessage(response)}',
        );
        return response;
      } finally {
        await socket.close();
      }
    }

    final socket = await Socket.connect(
      endpoint.address,
      endpoint.port,
      sourceAddress: localAddress,
      sourcePort: localPort,
      timeout: timeout,
    );
    try {
      StunLog.log(
        '[stun] tcp-send secure=false bytes=${payload.length} '
        'endpoint=${summarizeEndpoint(endpoint)}',
      );
      socket.add(payload);
      await socket.flush();
      final response = await readSingleStunMessageFromStream(
        socket,
        timeout: timeout,
      );
      StunLog.log(
        '[stun] tcp-response secure=false endpoint=${summarizeEndpoint(endpoint)} '
        '${summarizeStunMessage(response)}',
      );
      return response;
    } finally {
      await socket.close();
    }
  }

  Future<NatCapabilitySupport> _probeResponsePortSupport({
    required StunSession session,
    required StunServerEndpoint endpoint,
    required Duration timeout,
  }) async {
    final secondary = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: 0,
      addressType: endpoint.address.type,
    );
    try {
      final request = StunMessage.bindingRequest(
        attributes: <StunAttribute>[
          StunResponsePortAttribute(session.localPort),
        ],
      );
      final payload = encodeMessage(request);
      final onPrimary = session._binding.waitForTransaction(
        request.transactionId,
        timeout,
      );
      final onSecondary = secondary.waitForTransaction(
        request.transactionId,
        timeout,
      );
      secondary.send(payload, endpoint.address, endpoint.port);
      final packets = await _awaitProbePackets(onPrimary, onSecondary);
      if (packets.primaryPacket != null) {
        return NatCapabilitySupport.supported;
      }
      final secondaryError =
          packets.secondaryPacket?.message.attribute<StunErrorCodeAttribute>();
      if (packets.secondaryPacket == null) {
        return NatCapabilitySupport.unsupported;
      }
      if (secondaryError != null &&
          (secondaryError.code == 400 || secondaryError.code == 420)) {
        return NatCapabilitySupport.unsupported;
      }
      return NatCapabilitySupport.unsupported;
    } finally {
      await secondary.close();
    }
  }
}

class _ProbePackets {
  const _ProbePackets({
    required this.primaryPacket,
    required this.secondaryPacket,
  });

  final StunInboundPacket? primaryPacket;
  final StunInboundPacket? secondaryPacket;
}

Future<_ProbePackets> _awaitProbePackets(
  Future<StunInboundPacket?> primaryFuture,
  Future<StunInboundPacket?> secondaryFuture,
) {
  final completer = Completer<_ProbePackets>();
  StunInboundPacket? primaryPacket;
  StunInboundPacket? secondaryPacket;
  var finished = 0;

  void resolveIfDone() {
    if (primaryPacket != null || secondaryPacket != null) {
      if (!completer.isCompleted) {
        completer.complete(
          _ProbePackets(
            primaryPacket: primaryPacket,
            secondaryPacket: secondaryPacket,
          ),
        );
      }
      return;
    }
    if (finished == 2 && !completer.isCompleted) {
      completer.complete(
        const _ProbePackets(primaryPacket: null, secondaryPacket: null),
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

NatCapabilitySupport _explicitSupportFromResult(StunRequestResult result) {
  if (_isExplicitUnsupported(result.response)) {
    return NatCapabilitySupport.unsupported;
  }
  return result.isSuccess || result.isError
      ? NatCapabilitySupport.supported
      : NatCapabilitySupport.unknown;
}

NatCapabilitySupport _paddingSupportFromResult(StunRequestResult result) {
  if (_isExplicitUnsupported(result.response)) {
    return NatCapabilitySupport.unsupported;
  }
  if (result.response.messageClass == StunMessageClass.successResponse) {
    return NatCapabilitySupport.supported;
  }
  return NatCapabilitySupport.unknown;
}

bool _isExplicitUnsupported(StunMessage message) {
  final error = message.attribute<StunErrorCodeAttribute>();
  return error != null && (error.code == 400 || error.code == 420);
}

StunServerEndpoint? _alternateServerEndpoint(
  StunServerEndpoint currentEndpoint,
  StunMessage response,
) {
  final error = response.attribute<StunErrorCodeAttribute>();
  final alternateServer = response.attribute<StunAlternateServerAttribute>();
  if (response.messageClass != StunMessageClass.errorResponse ||
      error?.code != 300 ||
      alternateServer == null) {
    return null;
  }
  return StunServerEndpoint(
    host: alternateServer.value.address.address,
    address: alternateServer.value.address,
    port: alternateServer.value.port,
    transport: currentEndpoint.transport,
  );
}

bool _bindingSupportsEndpoint(
  StunUdpBinding binding,
  StunServerEndpoint endpoint,
) {
  return endpoint.transport == Transport.udp &&
      endpoint.address.type == binding.localAddress.type;
}

String _endpointKey(StunServerEndpoint endpoint) {
  return '${endpoint.transport.name}|${endpoint.address.address}|${endpoint.port}';
}

String _transactionIdOf(StunMessage message) => message.transactionId
    .map((value) => value.toRadixString(16).padLeft(2, '0'))
    .join();
