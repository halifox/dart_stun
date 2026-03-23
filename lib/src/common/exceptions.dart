class StunException implements Exception {
  const StunException(this.message);

  final String message;

  @override
  String toString() => 'StunException: $message';
}

class StunParseException extends StunException {
  const StunParseException(super.message);
}

class StunProtocolException extends StunException {
  const StunProtocolException(super.message);
}

class StunTimeoutException extends StunException {
  const StunTimeoutException(super.message);
}

class StunDiscoveryException extends StunException {
  const StunDiscoveryException(super.message);
}

class StunUnsupportedException extends StunException {
  const StunUnsupportedException(super.message);
}
