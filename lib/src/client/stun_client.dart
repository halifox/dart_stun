import 'dart:io';
import 'dart:typed_data';

import '../common/exceptions.dart';
import '../message/stun_message.dart';
import 'stun_discovery.dart';
import 'stun_server_target.dart';
import 'stun_transport.dart';

class StunClient {
  StunClient({
    required this.target,
    this.localAddress,
    this.localPort = 0,
    this.stunProtocol = StunProtocol.rfc5389,
    this.credentials,
    this.software,
    this.includeFingerprint = true,
    this.initialRto = const Duration(milliseconds: 500),
    this.maxRetransmissions = 7,
    this.responseTimeoutMultiplier = 16,
    this.requestTimeout = const Duration(seconds: 5),
    this.onBadCertificate,
  });

  factory StunClient.create({
    required Transport transport,
    required String serverHost,
    int? serverPort,
    String? localIp,
    int localPort = 0,
    StunProtocol stunProtocol = StunProtocol.rfc5389,
    StunCredentials? credentials,
    String? software,
    bool includeFingerprint = true,
    Duration initialRto = const Duration(milliseconds: 500),
    int maxRetransmissions = 7,
    int responseTimeoutMultiplier = 16,
    Duration requestTimeout = const Duration(seconds: 5),
    bool Function(X509Certificate certificate)? onBadCertificate,
    List<InternetAddress> dnsServers = const <InternetAddress>[],
  }) {
    return StunClient(
      target: StunServerTarget(
        host: serverHost,
        port: serverPort,
        transport: transport,
        dnsServers: dnsServers,
      ),
      localAddress: localIp == null ? null : InternetAddress(localIp),
      localPort: localPort,
      stunProtocol: stunProtocol,
      credentials: credentials,
      software: software,
      includeFingerprint: includeFingerprint,
      initialRto: initialRto,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
      requestTimeout: requestTimeout,
      onBadCertificate: onBadCertificate,
    );
  }

  factory StunClient.fromUri(
    String uri, {
    String? localIp,
    int localPort = 0,
    StunProtocol stunProtocol = StunProtocol.rfc5389,
    StunCredentials? credentials,
    String? software,
    bool includeFingerprint = true,
    Duration initialRto = const Duration(milliseconds: 500),
    int maxRetransmissions = 7,
    int responseTimeoutMultiplier = 16,
    Duration requestTimeout = const Duration(seconds: 5),
    bool Function(X509Certificate certificate)? onBadCertificate,
    List<InternetAddress> dnsServers = const <InternetAddress>[],
  }) {
    return StunClient(
      target: StunServerTarget.uri(uri, dnsServers: dnsServers),
      localAddress: localIp == null ? null : InternetAddress(localIp),
      localPort: localPort,
      stunProtocol: stunProtocol,
      credentials: credentials,
      software: software,
      includeFingerprint: includeFingerprint,
      initialRto: initialRto,
      maxRetransmissions: maxRetransmissions,
      responseTimeoutMultiplier: responseTimeoutMultiplier,
      requestTimeout: requestTimeout,
      onBadCertificate: onBadCertificate,
    );
  }

  final StunServerTarget target;
  final InternetAddress? localAddress;
  final int localPort;
  final StunProtocol stunProtocol;
  final StunCredentials? credentials;
  final String? software;
  final bool includeFingerprint;
  final Duration initialRto;
  final int maxRetransmissions;
  final int responseTimeoutMultiplier;
  final Duration requestTimeout;
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
    return message.encode(
      credentials: credentials,
      includeFingerprint: includeFingerprint,
      software: software,
    );
  }

  StunMessage parseMessage(
    Uint8List bytes, {
    bool validateFingerprint = false,
  }) {
    return StunMessage.decode(
      bytes,
      validateFingerprint: validateFingerprint,
    );
  }

  Future<List<StunServerEndpoint>> resolveEndpoints() {
    return resolveStunTarget(target);
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

  Future<StunMessage> sendAndAwait(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) async {
    final resolved = endpoint ?? await resolveEndpoint();
    final payload = encodeMessage(message);
    final effectiveTimeout = timeout ?? requestTimeout;
    switch (resolved.transport) {
      case Transport.udp:
        return _sendOverUdp(
          message: message,
          endpoint: resolved,
          payload: payload,
          timeout: effectiveTimeout,
        );
      case Transport.tcp:
        return _sendOverTcp(
          endpoint: resolved,
          payload: payload,
          timeout: effectiveTimeout,
          secure: false,
        );
      case Transport.tls:
        return _sendOverTcp(
          endpoint: resolved,
          payload: payload,
          timeout: effectiveTimeout,
          secure: true,
        );
    }
  }

  Future<StunMessage> send(
    StunMessage message, {
    StunServerEndpoint? endpoint,
    Duration? timeout,
  }) {
    return sendAndAwait(message, endpoint: endpoint, timeout: timeout);
  }

  Future<StunMessage> _sendOverUdp({
    required StunMessage message,
    required StunServerEndpoint endpoint,
    required Uint8List payload,
    required Duration timeout,
  }) async {
    final binding = await StunUdpBinding.bind(
      localAddress: localAddress,
      localPort: localPort,
      addressType: endpoint.address.type,
    );
    try {
      final response = await binding.request(
        message: message,
        payload: payload,
        endpoint: endpoint,
        initialRto: initialRto,
        maxRetransmissions: maxRetransmissions,
        responseTimeoutMultiplier: responseTimeoutMultiplier,
      );
      if (response == null) {
        throw StunTimeoutException(
          'Timed out waiting for STUN response from $endpoint.',
        );
      }
      return response.message;
    } finally {
      await binding.close();
    }
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
        socket.add(payload);
        await socket.flush();
        return await readSingleStunMessageFromStream(
          socket,
          timeout: timeout,
        );
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
      socket.add(payload);
      await socket.flush();
      return await readSingleStunMessageFromStream(
        socket,
        timeout: timeout,
      );
    } finally {
      await socket.close();
    }
  }
}
