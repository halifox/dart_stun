class StunServerCapabilities {
  const StunServerCapabilities({
    this.otherAddress = NatCapabilitySupport.unknown,
    this.responseOrigin = NatCapabilitySupport.unknown,
    this.changeRequest = NatCapabilitySupport.unknown,
    this.responsePort = NatCapabilitySupport.unknown,
    this.padding = NatCapabilitySupport.unknown,
  });

  factory StunServerCapabilities.fromJson(Map<String, Object?> json) {
    return StunServerCapabilities(
      otherAddress: _supportFromJson(json['otherAddress']),
      responseOrigin: _supportFromJson(json['responseOrigin']),
      changeRequest: _supportFromJson(json['changeRequest']),
      responsePort: _supportFromJson(json['responsePort']),
      padding: _supportFromJson(json['padding']),
    );
  }

  final NatCapabilitySupport otherAddress;
  final NatCapabilitySupport responseOrigin;
  final NatCapabilitySupport changeRequest;
  final NatCapabilitySupport responsePort;
  final NatCapabilitySupport padding;

  StunServerCapabilities copyWith({
    NatCapabilitySupport? otherAddress,
    NatCapabilitySupport? responseOrigin,
    NatCapabilitySupport? changeRequest,
    NatCapabilitySupport? responsePort,
    NatCapabilitySupport? padding,
  }) {
    return StunServerCapabilities(
      otherAddress: otherAddress ?? this.otherAddress,
      responseOrigin: responseOrigin ?? this.responseOrigin,
      changeRequest: changeRequest ?? this.changeRequest,
      responsePort: responsePort ?? this.responsePort,
      padding: padding ?? this.padding,
    );
  }

  Map<String, Object?> toJson() {
    return <String, Object?>{
      'otherAddress': otherAddress.name,
      'responseOrigin': responseOrigin.name,
      'changeRequest': changeRequest.name,
      'responsePort': responsePort.name,
      'padding': padding.name,
    };
  }

  @override
  bool operator ==(Object other) {
    return other is StunServerCapabilities &&
        otherAddress == other.otherAddress &&
        responseOrigin == other.responseOrigin &&
        changeRequest == other.changeRequest &&
        responsePort == other.responsePort &&
        padding == other.padding;
  }

  @override
  int get hashCode => Object.hash(
        otherAddress,
        responseOrigin,
        changeRequest,
        responsePort,
        padding,
      );

  @override
  String toString() {
    return 'StunServerCapabilities(otherAddress: $otherAddress, '
        'responseOrigin: $responseOrigin, changeRequest: $changeRequest, '
        'responsePort: $responsePort, padding: $padding)';
  }
}

enum NatCapabilitySupport {
  supported,
  unsupported,
  unknown,
}

NatCapabilitySupport _supportFromJson(Object? rawValue) {
  if (rawValue is! String) {
    throw ArgumentError.value(
      rawValue,
      'rawValue',
      'Expected support value to be a string.',
    );
  }
  return NatCapabilitySupport.values.byName(rawValue);
}
