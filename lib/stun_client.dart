import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:stun/stun_message.dart';

enum Transport {
  tcp,
  udp,
  tls,
}

class StunClient {
  Transport transport;
  String serverHost;
  int serverPort;
  String localIp;
  int localPort;

  int Ti = 395000;

  int rto = 500; // 初始 RTO ms
  int rc = 7; // 最大重传次数
  int calculateSendIntervals(int rto, int rc) {
    return rto * 1 << rc;
  }

  StunClient({
    this.transport = Transport.udp,
    this.serverHost = "stun.hot-chilli.net",
    this.serverPort = 3478,
    this.localIp = "0.0.0.0",
    this.localPort = 54320,
  });

  StunMessage createBindingStunMessage() {
    StunMessage stunMessage = StunMessage(
      StunMessage.HEAD,
      StunMessage.TYPE_BINDING | StunMessage.CLASS_REQUEST,
      0,
      StunMessage.MAGIC_COOKIE,
      //todo: the transaction ID MUST be uniformly and randomly chosen from the interval 0 .. 2**96-1
      Random.secure().nextInt(2 << 32 - 1),
      [],
    );
    return stunMessage;
  }

  udp() async {
    RawDatagramSocket socket = await RawDatagramSocket.bind(InternetAddress(localIp), localPort);
    socket.timeout(Duration(seconds: 3));
    socket.listen((RawSocketEvent socketEvent) {
      if (socketEvent != RawSocketEvent.read) return;
      Datagram? incomingDatagram = socket.receive();
      if (incomingDatagram == null) return;
      Uint8List data = incomingDatagram.data;
      StunMessage stunMessage = StunMessage.form(data);
      print(stunMessage.toString());
    }, onDone: () {
      socket.close();
    }, onError: (error) {
      socket.close();
    });

    List<InternetAddress> addresses = await InternetAddress.lookup(serverHost).timeout(const Duration(seconds: 3));
    if (addresses.isEmpty) throw Exception("Failed to resolve host: $serverHost");

    for (InternetAddress address in addresses) {
      StunMessage stunMessage = createBindingStunMessage();
      socket.send(stunMessage.toUInt8List(), address, serverPort);
    }
  }

  tcp() async {
    Socket socket = await Socket.connect(serverHost, serverPort);
    socket.timeout(Duration(milliseconds: Ti));
    socket.listen((Uint8List data) {
      StunMessage stunMessage = StunMessage.form(data);
      print(stunMessage.toString());
      socket.destroy();
    }, onDone: () {
      socket.destroy();
    }, onError: (error) {
      socket.destroy();
    });
    StunMessage stunMessage = createBindingStunMessage();
    socket.add(stunMessage.toUInt8List());
  }

  tls() async {
    Socket socket = await SecureSocket.connect(serverHost, serverPort);
    socket.timeout(Duration(milliseconds: Ti));
    socket.listen((Uint8List data) {
      StunMessage stunMessage = StunMessage.form(data);
      print(stunMessage.toString());
      socket.destroy();
    }, onDone: () {
      socket.destroy();
    }, onError: (error) {
      socket.destroy();
    });
    StunMessage stunMessage = createBindingStunMessage();
    socket.add(stunMessage.toUInt8List());
  }
}
