import 'package:stun/stun_client.dart';

main() async {
  StunClient stunClient = StunClient();
  // stunClient.udp();
  // stunClient.tcp();
  stunClient.tls();
}
