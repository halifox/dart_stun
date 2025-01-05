import 'dart:async';

import 'package:stun/stun.dart';
import 'package:test/test.dart';

void main() {
  test("description", () async {
    StunClient stunClient = StunClient.create(
      transport: Transport.udp,
      serverHost: "stun.hot-chilli.net",
      serverPort: 3478,
      localIp: "0.0.0.0",
      localPort: 54320,
      stunProtocol: StunProtocol.MIX,
    );
    await stunClient.connect();
    StunMessage stunMessage = stunClient.createBindingStunMessage();
    var completer = Completer();
    stunClient.addOnMessageListener((StunMessage stunMessage) {
      print(stunMessage);
      completer.complete();
    });
    stunClient.send(stunMessage);
    await completer.future;
  });
}
