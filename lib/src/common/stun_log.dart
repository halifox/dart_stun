import '../client/stun_server_target.dart';
import '../common/binary_utils.dart';
import '../message/stun_message.dart';

abstract final class StunLog {
  static bool enabled = false;

  static void log(String message) {
    if (!enabled) {
      return;
    }
    print(message);
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
