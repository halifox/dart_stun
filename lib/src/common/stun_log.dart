import '../client/stun_server_target.dart';
import '../message/stun_message.dart';
import 'binary_utils.dart';

enum StunLogLevel {
  debug,
  info,
  warning,
  error,
}

typedef StunLogger = void Function(StunLogEvent event);

class StunLogEvent {
  StunLogEvent({
    required this.category,
    required this.action,
    this.level = StunLogLevel.debug,
    this.message,
    Map<String, Object?> fields = const <String, Object?>{},
    DateTime? timestamp,
  })  : fields = Map.unmodifiable(fields),
        timestamp = timestamp ?? DateTime.now().toUtc();

  final String category;
  final String action;
  final StunLogLevel level;
  final String? message;
  final Map<String, Object?> fields;
  final DateTime timestamp;

  String format() {
    if (message case final message?) {
      return message;
    }
    final buffer = StringBuffer('[$category] $action');
    if (fields.isNotEmpty) {
      for (final entry in fields.entries) {
        buffer.write(' ${entry.key}=${entry.value}');
      }
    }
    return buffer.toString();
  }

  @override
  String toString() => format();
}

abstract final class StunLog {
  static StunLogger? _logger;

  static bool get enabled => _logger != null;

  static set enabled(bool value) {
    _logger = value ? _defaultLogger : null;
  }

  static StunLogger? get logger => _logger;

  static set logger(StunLogger? value) {
    _logger = value;
  }

  static void emit(StunLogEvent event) {
    final activeLogger = _logger;
    if (activeLogger == null) {
      return;
    }
    activeLogger(event);
  }

  static void log(
    String message, {
    String category = 'stun',
    String action = 'message',
    StunLogLevel level = StunLogLevel.debug,
    Map<String, Object?> fields = const <String, Object?>{},
  }) {
    emit(
      StunLogEvent(
        category: category,
        action: action,
        level: level,
        message: message,
        fields: fields,
      ),
    );
  }

  static void _defaultLogger(StunLogEvent event) {
    print(event.format());
  }
}

String summarizeStunMessage(StunMessage message) {
  return 'method=${message.method.name} class=${message.messageClass.name} '
      'tx=${hexEncode(message.transactionId)} attrs=${message.attributes}';
}

String summarizeEndpoint(StunServerEndpoint endpoint) {
  return '${endpoint.transport.name}://${endpoint.address.address}:${endpoint.port}'
      ' host=${endpoint.host}';
}
