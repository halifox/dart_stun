import 'dart:async';
import 'dart:io';

import 'package:stun/stun.dart';
import 'package:stun/src/common/exceptions.dart';

import 'public_providers.dart';

enum PublicResultStatus {
  pass,
  unsupported,
  networkUnstable,
  protocolFailure,
}

class PublicStageResult {
  const PublicStageResult._({
    required this.status,
    required this.summary,
  });

  const PublicStageResult.pass(String summary)
      : this._(
          status: PublicResultStatus.pass,
          summary: summary,
        );

  const PublicStageResult.unsupported(String summary)
      : this._(
          status: PublicResultStatus.unsupported,
          summary: summary,
        );

  const PublicStageResult.networkUnstable(String summary)
      : this._(
          status: PublicResultStatus.networkUnstable,
          summary: summary,
        );

  const PublicStageResult.protocolFailure(String summary)
      : this._(
          status: PublicResultStatus.protocolFailure,
          summary: summary,
        );

  final PublicResultStatus status;
  final String summary;

  bool get failed => status == PublicResultStatus.protocolFailure;

  String get statusLabel => switch (status) {
        PublicResultStatus.pass => 'PASS',
        PublicResultStatus.unsupported => 'UNSUPPORTED',
        PublicResultStatus.networkUnstable => 'NETWORK-UNSTABLE',
        PublicResultStatus.protocolFailure => 'PROTOCOL-FAILURE',
      };
}

class PublicStageCollector {
  PublicStageCollector(this.stageName);

  final String stageName;
  final Map<String, PublicStageResult> _results = <String, PublicStageResult>{};

  void record(PublicProvider provider, PublicStageResult result) {
    _results[provider.id] = result;
  }

  int get totalCount => _results.length;

  int count(PublicResultStatus status) {
    return _results.values.where((result) => result.status == status).length;
  }

  int get passedCount => count(PublicResultStatus.pass);

  List<String> idsFor(PublicResultStatus status) {
    return _results.entries
        .where((entry) => entry.value.status == status)
        .map((entry) => entry.key)
        .toList(growable: false);
  }

  void writeSummary() {
    stdout.writeln(
      '[SUMMARY][$stageName] total=$totalCount '
      'pass=${count(PublicResultStatus.pass)} '
      'unsupported=${count(PublicResultStatus.unsupported)} '
      'network_unstable=${count(PublicResultStatus.networkUnstable)} '
      'protocol_failure=${count(PublicResultStatus.protocolFailure)}',
    );
    stdout.writeln(
      '[SUMMARY][$stageName] pass=${_join(idsFor(PublicResultStatus.pass))}',
    );
    stdout.writeln(
      '[SUMMARY][$stageName] unsupported='
      '${_join(idsFor(PublicResultStatus.unsupported))}',
    );
    stdout.writeln(
      '[SUMMARY][$stageName] network_unstable='
      '${_join(idsFor(PublicResultStatus.networkUnstable))}',
    );
    stdout.writeln(
      '[SUMMARY][$stageName] protocol_failure='
      '${_join(idsFor(PublicResultStatus.protocolFailure))}',
    );

    for (final entry in _results.entries) {
      if (entry.value.status == PublicResultStatus.pass) {
        continue;
      }
      stdout.writeln(
        '[SUMMARY][$stageName] ${entry.key}='
        '${entry.value.statusLabel} ${entry.value.summary}',
      );
    }
  }
}

StunTransportAddress? mappedAddressFrom(StunMessage message) {
  return message.attribute<StunXorMappedAddressAttribute>()?.value ??
      message.attribute<StunMappedAddressAttribute>()?.value;
}

PublicStageResult classifyBaselineResponse(StunMessage response) {
  if (response.messageClass == StunMessageClass.errorResponse) {
    return PublicStageResult.unsupported(
      describeNonSuccessResponse(response),
    );
  }

  if (response.messageClass != StunMessageClass.successResponse) {
    return PublicStageResult.protocolFailure(
      describeNonSuccessResponse(response),
    );
  }

  final mapped = mappedAddressFrom(response);
  if (mapped == null) {
    return const PublicStageResult.protocolFailure(
      'success response did not include a mapped address',
    );
  }

  return PublicStageResult.pass('mapped=$mapped');
}

PublicStageResult classifyPublicError(Object error) {
  if (error is StunTimeoutException ||
      error is TimeoutException ||
      error is SocketException ||
      error is TlsException ||
      error is HandshakeException ||
      error is StunDiscoveryException) {
    return PublicStageResult.networkUnstable(describeError(error));
  }
  if (error is StunUnsupportedException) {
    return PublicStageResult.unsupported(describeError(error));
  }
  if (error is StunParseException ||
      error is StunProtocolException ||
      error is FormatException ||
      error is ArgumentError) {
    return PublicStageResult.protocolFailure(describeError(error));
  }
  if (error is StunException) {
    return PublicStageResult.protocolFailure(describeError(error));
  }
  return PublicStageResult.protocolFailure(describeError(error));
}

PublicStageResult classifyNatReport(NatBehaviorReport report) {
  if (report.reachability != NatReachability.reachable) {
    return PublicStageResult.networkUnstable(
      'reachability=${report.reachability.name}',
    );
  }

  if (report.mappedAddress == null) {
    return const PublicStageResult.unsupported(
      'reachable NAT report did not include a mapped address',
    );
  }

  final unsupported = <String>[
    if (report.serverCapabilities.otherAddress ==
        NatCapabilitySupport.unsupported)
      'other-address',
    if (report.serverCapabilities.changeRequest ==
        NatCapabilitySupport.unsupported)
      'change-request',
    if (report.serverCapabilities.responsePort ==
        NatCapabilitySupport.unsupported)
      'response-port',
    if (report.serverCapabilities.padding == NatCapabilitySupport.unsupported)
      'padding',
    if (report.mappingBehavior == NatMappingBehavior.unsupported) 'mapping',
    if (report.filteringBehavior == NatFilteringBehavior.unsupported)
      'filtering',
  ];
  if (unsupported.isNotEmpty) {
    return PublicStageResult.unsupported(
      'unsupported=${unsupported.join(",")}',
    );
  }

  if (report.mappingBehavior == NatMappingBehavior.undetermined ||
      report.filteringBehavior == NatFilteringBehavior.undetermined) {
    return PublicStageResult.networkUnstable(
      'mapping=${report.mappingBehavior.name} '
      'filtering=${report.filteringBehavior.name}',
    );
  }

  return PublicStageResult.pass(
    'legacy=${report.legacyNatType.name} '
    'mapping=${report.mappingBehavior.name} '
    'filtering=${report.filteringBehavior.name}',
  );
}

PublicStageResult classifyRfc3489Report(NatBehaviorReport report) {
  if (report.reachability != NatReachability.reachable) {
    return PublicStageResult.networkUnstable(
      'legacy=${report.legacyNatType.name} '
      'reachability=${report.reachability.name}',
    );
  }

  if (report.legacyNatType == NatLegacyType.unknown) {
    return const PublicStageResult.unsupported(
      'legacy NAT type could not be derived',
    );
  }

  return PublicStageResult.pass(
    'legacy=${report.legacyNatType.name} '
    'natted=${report.isNatted ?? "-"} '
    'mapped=${report.mappedAddress ?? "-"}',
  );
}

PublicStageResult classifyRfc5780Report(NatBehaviorReport report) {
  if (report.reachability != NatReachability.reachable) {
    return PublicStageResult.networkUnstable(
      'reachability=${report.reachability.name}',
    );
  }

  if (report.mappedAddress == null) {
    return const PublicStageResult.unsupported(
      'RFC5780-style report did not include a mapped address',
    );
  }

  final unsupported = <String>[
    if (report.serverCapabilities.otherAddress ==
        NatCapabilitySupport.unsupported)
      'other-address',
    if (report.serverCapabilities.changeRequest ==
        NatCapabilitySupport.unsupported)
      'change-request',
    if (report.serverCapabilities.responsePort ==
        NatCapabilitySupport.unsupported)
      'response-port',
    if (report.serverCapabilities.padding == NatCapabilitySupport.unsupported)
      'padding',
    if (report.mappingBehavior == NatMappingBehavior.unsupported) 'mapping',
    if (report.filteringBehavior == NatFilteringBehavior.unsupported)
      'filtering',
  ];
  if (unsupported.isNotEmpty) {
    return PublicStageResult.unsupported(
      'unsupported=${unsupported.join(",")}',
    );
  }

  if (report.mappingBehavior == NatMappingBehavior.undetermined ||
      report.filteringBehavior == NatFilteringBehavior.undetermined) {
    return PublicStageResult.networkUnstable(
      'mapping=${report.mappingBehavior.name} '
      'filtering=${report.filteringBehavior.name}',
    );
  }

  return PublicStageResult.pass(
    'mapping=${report.mappingBehavior.name} '
    'filtering=${report.filteringBehavior.name} '
    'lifetime=${formatDuration(report.bindingLifetimeEstimate)} '
    'hairpin=${report.hairpinning.name} '
    'fragment=${report.fragmentHandling.name}',
  );
}

String describeError(Object error) {
  if (error is SocketException) {
    return 'socket-error ${compact(error.message)}';
  }
  if (error is HandshakeException) {
    return 'handshake-error ${compact(error.message)}';
  }
  if (error is TlsException) {
    return 'tls-error ${compact(error.message)}';
  }
  if (error is StunException) {
    return compact(error.message);
  }
  return '${error.runtimeType}: ${compact(error.toString())}';
}

String describeNonSuccessResponse(StunMessage response) {
  final error = response.attribute<StunErrorCodeAttribute>();
  if (error == null) {
    return 'unexpected message class ${response.messageClass.name}';
  }
  final reason = compact(error.reasonPhrase);
  if (reason.isEmpty) {
    return 'stun-error ${error.code}';
  }
  return 'stun-error ${error.code} $reason';
}

void writeProviderStart({
  required String stage,
  required PublicProvider provider,
}) {
  stdout.writeln(
    '[$stage][PROVIDER] ${provider.id} '
    'uri=${provider.uri} '
    'endpoint=${provider.endpointKey}',
  );
  stdout.writeln('[$stage][NOTES] ${provider.id} ${provider.notes}');
}

void writeResolvedEndpoint({
  required String stage,
  required PublicProvider provider,
  required StunServerEndpoint endpoint,
}) {
  stdout.writeln('[$stage][RESOLVED] ${provider.id} $endpoint');
}

void writeStageResult({
  required String stage,
  required PublicProvider provider,
  required PublicStageResult result,
  String? detail,
}) {
  final suffix = detail == null || detail.isEmpty ? '' : ' detail=$detail';
  stdout.writeln(
    '[$stage][${result.statusLabel}] ${provider.id} ${result.summary}$suffix',
  );
}

void writeNatReport({
  required PublicProvider provider,
  required NatBehaviorReport report,
}) {
  stdout.writeln(
    '[NAT][REPORT] ${provider.id} '
    'endpoint=${report.serverEndpoint} '
    'reachability=${report.reachability.name} '
    'local=${report.localAddress ?? "-"} '
    'mapped=${report.mappedAddress ?? "-"} '
    'natted=${report.isNatted ?? "-"} '
    'mapping=${report.mappingBehavior.name} '
    'filtering=${report.filteringBehavior.name} '
    'lifetime=${formatDuration(report.bindingLifetimeEstimate)} '
    'hairpin=${report.hairpinning.name} '
    'fragment=${report.fragmentHandling.name} '
    'alg=${report.algDetected ?? "-"} '
    'legacy=${report.legacyNatType.name}',
  );
  stdout.writeln(
    '[NAT][CAPS] ${provider.id} '
    'otherAddress=${report.serverCapabilities.otherAddress.name} '
    'responseOrigin=${report.serverCapabilities.responseOrigin.name} '
    'changeRequest=${report.serverCapabilities.changeRequest.name} '
    'responsePort=${report.serverCapabilities.responsePort.name} '
    'padding=${report.serverCapabilities.padding.name}',
  );
  stdout.writeln(
    '[NAT][WARNINGS] ${provider.id} '
    '${report.warnings.isEmpty ? "-" : report.warnings.join(" | ")}',
  );
}

void writeRfc3489Report({
  required PublicProvider provider,
  required NatBehaviorReport report,
}) {
  stdout.writeln(
    '[RFC3489][REPORT] ${provider.id} '
    'reachability=${report.reachability.name} '
    'local=${report.localAddress ?? "-"} '
    'mapped=${report.mappedAddress ?? "-"} '
    'natted=${report.isNatted ?? "-"} '
    'legacy=${report.legacyNatType.name}',
  );
  stdout.writeln(
    '[RFC3489][WARNINGS] ${provider.id} '
    '${report.warnings.isEmpty ? "-" : report.warnings.join(" | ")}',
  );
}

void writeRfc5780Report({
  required PublicProvider provider,
  required NatBehaviorReport report,
}) {
  stdout.writeln(
    '[RFC5780][REPORT] ${provider.id} '
    'reachability=${report.reachability.name} '
    'mapped=${report.mappedAddress ?? "-"} '
    'mapping=${report.mappingBehavior.name} '
    'filtering=${report.filteringBehavior.name} '
    'lifetime=${formatDuration(report.bindingLifetimeEstimate)} '
    'hairpin=${report.hairpinning.name} '
    'fragment=${report.fragmentHandling.name} '
    'alg=${report.algDetected ?? "-"}',
  );
  stdout.writeln(
    '[RFC5780][CAPS] ${provider.id} '
    'otherAddress=${report.serverCapabilities.otherAddress.name} '
    'responseOrigin=${report.serverCapabilities.responseOrigin.name} '
    'changeRequest=${report.serverCapabilities.changeRequest.name} '
    'responsePort=${report.serverCapabilities.responsePort.name} '
    'padding=${report.serverCapabilities.padding.name}',
  );
  stdout.writeln(
    '[RFC5780][WARNINGS] ${provider.id} '
    '${report.warnings.isEmpty ? "-" : report.warnings.join(" | ")}',
  );
}

String compact(String value) {
  return value.replaceAll(RegExp(r'\s+'), ' ').trim();
}

String formatDuration(Duration? value) {
  if (value == null) {
    return '-';
  }
  return '${value.inMilliseconds}ms';
}

String _join(List<String> values) {
  if (values.isEmpty) {
    return '-';
  }
  return values.join(',');
}
