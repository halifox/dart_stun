import 'package:stun/stun_client.dart';
import 'package:stun/stun_message.dart';

main() async {
  StunClient stunClient = StunClient(stunProtocol: StunProtocol.MIX);
  stunClient.udp();
  // stunClient.tcp();
  // stunClient.tls();
}
