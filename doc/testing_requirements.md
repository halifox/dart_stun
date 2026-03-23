# dart_stun Testing Requirements

This repository now treats public interoperability as the default test path.
Running `dart test -r expanded` executes:

- deterministic message model checks
- a public STUN baseline sweep across multiple vendors and transports
- a public `NatDetector` sweep across the UDP subset of that provider list

No environment variables are required.

## Test Layout

Primary files:

- `test/stun_message_test.dart`
- `test/public_stun_client_test.dart`
- `test/public_nat_detector_test.dart`
- `test/support/public_providers.dart`
- `test/support/public_test_support.dart`

The public provider matrix is embedded directly in
`test/support/public_providers.dart` so the default command has no external
configuration step.

## Default Run

Recommended command:

```powershell
dart test -r expanded
```

Why `-r expanded` matters:

- each provider prints its URI, resolved endpoint, and stage outcome
- baseline tests print mapped-address results
- NAT tests print reachability, mapped/local address, mapping behavior,
  filtering behavior, lifetime estimate, hairpinning, fragment handling,
  ALG detection, capability support, and warnings
- each stage finishes with a `[SUMMARY]` block

## Result Classification

The public suites classify outcomes into four buckets.

`PASS`

- baseline Binding request succeeded and returned a mapped address
- or NAT probing produced a concrete, internally consistent report

`UNSUPPORTED`

- the provider was reachable but did not expose the capabilities required for a
  deeper NAT interpretation, such as `OTHER-ADDRESS`, `CHANGE-REQUEST`,
  `RESPONSE-PORT`, or `PADDING`

`NETWORK-UNSTABLE`

- timeout
- DNS resolution failure
- socket failure
- TLS handshake failure
- other environment-sensitive public network problems

`PROTOCOL-FAILURE`

- malformed or contradictory STUN behavior
- success response without a mapped address
- parse or protocol exception caused by the library or by an unusable STUN
  response

Only `PROTOCOL-FAILURE` is treated as a hard test failure for individual
provider cases.

The baseline suite also requires at least one provider to return a mapped
address. If every public target is unreachable, the final baseline guard test
fails and the summary output explains the environment condition.

## Coverage Goals

### Message Model

- binding request encode/decode
- fingerprint validation
- message integrity validation
- address, padding, and response-port attribute round-trips
- unknown attribute preservation
- malformed message rejection

### Public Client Sweep

- UDP interoperability against multiple vendors
- TCP interoperability against public best-effort targets
- TLS/STUNS best-effort interoperability
- endpoint resolution and detailed failure reporting

### Public NAT Sweep

- real-world `NatDetector.check()` execution on the UDP provider set
- explicit logging of `NatBehaviorReport`
- separation of unsupported server capabilities from actual client failures

## Maintenance Rules

- keep provider entries explicit, including host, port, and transport
- prefer endpoints that are publicly documented and do not require credentials
- when a provider becomes consistently dead, update or remove its entry rather
  than hiding the failure behind an environment variable
- keep NAT classification conservative; public STUN services often implement
  only baseline Binding behavior
