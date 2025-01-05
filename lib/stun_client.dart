import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:stun/stun_message.dart';

enum Transport {
  udp,
  tcp,
  tls,
}

abstract class StunClient {
  Transport transport;
  String serverHost;
  int serverPort;
  String localIp;
  int localPort;
  StunProtocol stunProtocol;

  StunClient(this.transport, this.serverHost, this.serverPort, this.localIp, this.localPort, this.stunProtocol);

  int Ti = 395000;

  int rto = 500; // 初始 RTO ms
  int rc = 7; // 最大重传次数
  int calculateSendIntervals(int rto, int rc) {
    return rto * 1 << rc;
  }

  static StunClient create({
    Transport transport = Transport.udp,
    String serverHost = "stun.hot-chilli.net",
    int serverPort = 3478,
    String localIp = "0.0.0.0",
    int localPort = 54320,
    StunProtocol stunProtocol = StunProtocol.MIX,
  }) {
    return switch (transport) {
      Transport.udp => StunClientUdp(transport, serverHost, serverPort, localIp, localPort, stunProtocol),
      Transport.tcp => StunClientTcp(transport, serverHost, serverPort, localIp, localPort, stunProtocol),
      Transport.tls => StunClientTls(transport, serverHost, serverPort, localIp, localPort, stunProtocol),
    };
  }

  StunMessage createBindingStunMessage() {
    StunMessage stunMessage = StunMessage(
      StunMessage.HEAD,
      StunMessage.METHOD_BINDING | StunMessage.CLASS_REQUEST,
      0,
      StunMessage.MAGIC_COOKIE,
      //todo: the transaction ID MUST be uniformly and randomly chosen from the interval 0 .. 2**96-1
      Random.secure().nextInt(2 << 32 - 1),
      [],
      stunProtocol,
    );
    return stunMessage;
  }

  connect();

  send(StunMessage stunMessage);
}

class StunClientUdp extends StunClient {
  RawDatagramSocket? socket;

  List<InternetAddress> addresses = [];

  StunClientUdp(super.transport, super.serverHost, super.serverPort, super.localIp, super.localPort, super.stunProtocol);

  connect() async {
    socket = await RawDatagramSocket.bind(InternetAddress(localIp), localPort);
    socket?.timeout(Duration(milliseconds: Ti));
    socket?.listen((RawSocketEvent socketEvent) {
      if (socketEvent != RawSocketEvent.read) return;
      Datagram? incomingDatagram = socket?.receive();
      if (incomingDatagram == null) return;
      Uint8List data = incomingDatagram.data;
      StunMessage stunMessage = StunMessage.form(data, stunProtocol);
      print(stunMessage.toString());
    }, onDone: () {
      socket?.close();
    }, onError: (error) {
      socket?.close();
    });
    addresses = await InternetAddress.lookup(serverHost).timeout(const Duration(seconds: 3));
    if (addresses.isEmpty) throw Exception("Failed to resolve host: $serverHost");
  }

  send(StunMessage stunMessage) {
    if (addresses.isEmpty) throw Exception("Failed to resolve host: $serverHost");
    InternetAddress address = addresses[0];
    socket?.send(stunMessage.toUInt8List(), address, serverPort);
  }
}

class StunClientTcp extends StunClient {
  Socket? socket;

  StunClientTcp(super.transport, super.serverHost, super.serverPort, super.localIp, super.localPort, super.stunProtocol);

  connect() async {
    socket = await Socket.connect(serverHost, serverPort);
    socket?.timeout(Duration(milliseconds: Ti));
    socket?.listen((Uint8List data) {
      StunMessage stunMessage = StunMessage.form(data, stunProtocol);
      print(stunMessage.toString());
      socket?.destroy();
    }, onDone: () {
      socket?.destroy();
    }, onError: (error) {
      socket?.destroy();
    });
  }

  send(StunMessage stunMessage) {
    socket?.add(stunMessage.toUInt8List());
  }
}

class StunClientTls extends StunClient {
  Socket? socket;

  StunClientTls(super.transport, super.serverHost, super.serverPort, super.localIp, super.localPort, super.stunProtocol);

  connect() async {
    socket = await SecureSocket.connect(serverHost, serverPort);
    socket?.timeout(Duration(milliseconds: Ti));
    socket?.listen((Uint8List data) {
      StunMessage stunMessage = StunMessage.form(data, stunProtocol);
      print(stunMessage.toString());
      socket?.destroy();
    }, onDone: () {
      socket?.destroy();
    }, onError: (error) {
      socket?.destroy();
    });
  }

  send(StunMessage stunMessage) {
    socket?.add(stunMessage.toUInt8List());
  }
}
