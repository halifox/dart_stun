@Tags(['network'])

import 'package:stun/stun.dart';
import 'package:test/test.dart';

import 'support/public_providers.dart';
import 'support/public_test_support.dart';

void main() {
  final summary = PublicStageCollector('baseline');

  tearDownAll(summary.writeSummary);

  group('public STUN baseline sweep', () {
    test('provider catalog is not empty', () {
      expect(publicProviders, isNotEmpty);
    });

    for (final provider in publicProviders) {
      test('binding request against ${provider.id}', () async {
        writeProviderStart(stage: 'BASELINE', provider: provider);

        final client = StunClient.fromUri(
          provider.uri,
          requestTimeout: const Duration(seconds: 3),
          initialRto: const Duration(milliseconds: 300),
          maxRetransmissions: 2,
          responseTimeoutMultiplier: 4,
          software: 'dart_stun-public-baseline',
        );

        StunServerEndpoint? endpoint;
        late final PublicStageResult result;
        try {
          endpoint = await client.resolveEndpoint();
          writeResolvedEndpoint(
            stage: 'BASELINE',
            provider: provider,
            endpoint: endpoint,
          );

          final response = await client.sendAndAwait(
            client.createBindingRequest(),
            endpoint: endpoint,
          );
          result = classifyBaselineResponse(response);
          writeStageResult(
            stage: 'BASELINE',
            provider: provider,
            result: result,
            detail:
                'class=${response.messageClass.name} mapped=${mappedAddressFrom(response) ?? "-"}',
          );
        } catch (error) {
          result = classifyPublicError(error);
          writeStageResult(
            stage: 'BASELINE',
            provider: provider,
            result: result,
            detail: endpoint == null ? 'endpoint=-' : 'endpoint=$endpoint',
          );
        }

        summary.record(provider, result);
        if (result.failed) {
          fail('[${provider.id}] ${result.summary}');
        }
      });
    }

    test('at least one public provider returned a mapped address', () {
      expect(
        summary.passedCount,
        greaterThan(0),
        reason:
            'No public provider completed a baseline binding request. See the BASELINE summary lines after the run.',
      );
    });
  });
}
