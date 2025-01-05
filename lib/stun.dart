import 'package:stun/stun_client.dart';
import 'package:stun/stun_message.dart';

main() async {
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
  stunClient.send(stunMessage);
}
