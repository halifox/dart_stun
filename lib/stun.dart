import 'package:stun/stun_client.dart';

main() async {
  var stunClient = StunClient();
  stunClient.udp();
  stunClient.tcp();
}
