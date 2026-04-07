@Tags(['network', 'nat'])

import 'package:stun/stun.dart';
import 'package:test/test.dart';

import 'support/public_providers.dart';
import 'support/public_test_support.dart';

void main() {
  final providers = natProviders();
  final summary = PublicStageCollector('nat');
  final rfc3489Summary = PublicStageCollector('rfc3489');
  final rfc5780Summary = PublicStageCollector('rfc5780');
  final addressType = selectedPublicAddressType();
  final familyLabel = selectedPublicIpVersionLabel();

  tearDownAll(() {
    summary.writeSummary();
    rfc3489Summary.writeSummary();
    rfc5780Summary.writeSummary();
  });

  group('public NAT detector sweep [$familyLabel]', () {
    test('NAT provider catalog is not empty', () {
      expect(providers, isNotEmpty);
    });

    for (final provider in providers) {
      test('NatDetector.check against ${provider.id}', () async {
        writeProviderStart(stage: 'NAT', provider: provider);

        final detector = NatDetector.fromUri(
          provider.uri,
          addressType: addressType,
          requestTimeout: const Duration(seconds: 1),
          initialRto: const Duration(milliseconds: 200),
          maxRetransmissions: 2,
          responseTimeoutMultiplier: 2,
          initialBindingLifetimeProbe: const Duration(milliseconds: 300),
          maxBindingLifetimeProbe: const Duration(seconds: 1),
          bindingLifetimePrecision: const Duration(milliseconds: 200),
          fragmentPaddingBytes: 1024,
          software: 'dart_stun-public-nat',
        );

        late final PublicStageResult result;
        late final PublicStageResult rfc3489Result;
        late final PublicStageResult rfc5780Result;
        try {
          final report = await detector.check();
          writeNatReport(provider: provider, report: report);
          writeRfc3489Report(provider: provider, report: report);
          writeRfc5780Report(provider: provider, report: report);

          rfc3489Result = classifyRfc3489Report(report);
          rfc5780Result = classifyRfc5780Report(report);
          result = classifyNatReport(report);

          writeStageResult(
            stage: 'RFC3489',
            provider: provider,
            result: rfc3489Result,
          );
          writeStageResult(
            stage: 'RFC5780',
            provider: provider,
            result: rfc5780Result,
          );
          writeStageResult(
            stage: 'NAT',
            provider: provider,
            result: result,
          );
        } catch (error) {
          rfc3489Result = classifyPublicError(error);
          rfc5780Result = classifyPublicError(error);
          result = classifyPublicError(error);
          writeStageResult(
            stage: 'RFC3489',
            provider: provider,
            result: rfc3489Result,
          );
          writeStageResult(
            stage: 'RFC5780',
            provider: provider,
            result: rfc5780Result,
          );
          writeStageResult(
            stage: 'NAT',
            provider: provider,
            result: result,
          );
        }

        summary.record(provider, result);
        rfc3489Summary.record(provider, rfc3489Result);
        rfc5780Summary.record(provider, rfc5780Result);
        if (result.failed || rfc3489Result.failed || rfc5780Result.failed) {
          final reasons = <String>[
            if (rfc3489Result.failed) 'RFC3489=${rfc3489Result.summary}',
            if (rfc5780Result.failed) 'RFC5780=${rfc5780Result.summary}',
            if (result.failed) 'NAT=${result.summary}',
          ];
          fail('[${provider.id}] ${reasons.join('; ')}');
        }
      });
    }
  });
}
