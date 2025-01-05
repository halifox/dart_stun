import 'package:stun/stun.dart';
import 'package:test/test.dart';

void main() {
  test("udp", () async {
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
    StunMessage data = await stunClient.sendAndAwait(stunMessage);
    print(data);
  });

  test("tcp", () async {
    StunClient stunClient = StunClient.create(
      transport: Transport.tcp,
      serverHost: "stun.hot-chilli.net",
      serverPort: 3478,
      localIp: "0.0.0.0",
      localPort: 54320,
      stunProtocol: StunProtocol.MIX,
    );
    await stunClient.connect();
    StunMessage stunMessage = stunClient.createBindingStunMessage();
    StunMessage data = await stunClient.sendAndAwait(stunMessage);
    print(data);
  });

  test("tls", () async {
    StunClient stunClient = StunClient.create(
      transport: Transport.tls,
      serverHost: "stun.hot-chilli.net",
      serverPort: 3478,
      localIp: "0.0.0.0",
      localPort: 54320,
      stunProtocol: StunProtocol.MIX,
    );
    await stunClient.connect();
    StunMessage stunMessage = stunClient.createBindingStunMessage();
    StunMessage data = await stunClient.sendAndAwait(stunMessage);
    print(data);
  });
}
