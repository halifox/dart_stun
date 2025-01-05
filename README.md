# dart_stun

[中文文档](README-CN.md)

## 📖 Introduction

`dart_stun` is a Dart library designed for fast processing of the STUN (Session Traversal Utilities for NAT) protocol. It supports RFC 3489, RFC 5389, and RFC 5780 standards and is compatible with UDP, TCP, and TLS. It helps developers quickly send and receive STUN messages.

---

## ✨ Features

- **Supported Standards**: RFC 3489, RFC 5389, RFC 5780.
- **Multiple Transport Protocols**: Including UDP, TCP, and TLS.
- **Easy to Use**: Quickly build and parse STUN messages.

---

## 📥 Installation

Add the dependency in your `pubspec.yaml` file:

```yaml
dependencies:
  stun:
    git:
      url: https://github.com/halifox/dart_stun
      ref: 1.0.0
```

---

## 🛠️ Usage

The following code demonstrates how to use the `StunClient` class to communicate with a STUN server. The STUN (Session Traversal Utilities for NAT) protocol is widely used to help devices behind NAT (Network Address Translation) establish direct UDP or TCP connections.

1. **Create a STUN client**:
    ```dart
    StunClient stunClient = StunClient.create(
      transport: Transport.udp,  // Select transport protocol: UDP, TCP, TLS, etc.
      serverHost: "stun.hot-chilli.net",  // Hostname or IP address of the STUN server
      serverPort: 3478,  // STUN server port (standard is 3478)
      localIp: "0.0.0.0",  // Local IP address, usually set to "0.0.0.0" for automatic selection
      localPort: 54320,  // Local port to be used for the client connection
      stunProtocol: StunProtocol.RFC5780,  // Choose STUN protocol version, RFC5780 is commonly used
    );
    ```

   - `Transport.udp`: Specifies the transport protocol. `Transport.udp` uses UDP, while `Transport.tcp` and `Transport.tls` are other options.
   - `serverHost: "stun.hot-chilli.net"`: Set the STUN server's hostname.
   - `serverPort: 3478`: Configures the port used to communicate with the STUN server. 3478 is the standard STUN port.
   - `localIp: "0.0.0.0"`: Automatically select the local IP address, typically set to "0.0.0.0".
   - `localPort: 54320`: The local port used by the client for the connection.
   - `stunProtocol: StunProtocol.RFC5780`: Specifies the STUN protocol version. Options include `RFC5780`, `RFC3489`, `RFC5389`, or mixed protocols like `MIX`.

2. **Connect to the STUN server**:
    ```dart
    await stunClient.connect();
    ```
   Calling `stunClient.connect()` will attempt to establish a connection to the STUN server.

3. **Create a Binding Request Message**:
    ```dart
    StunMessage stunMessage = stunClient.createBindingStunMessage();
    ```
   By calling `createBindingStunMessage`, the client generates a Binding Request message. This message is used to request the public IP and port mapping from the STUN server.

4. **Send the request and await the response**:
    ```dart
    StunMessage data = await stunClient.sendAndAwait(stunMessage);
    ```
   Use the `sendAndAwait` method to send the Binding Request message and wait for the server's response. The returned data is a `StunMessage` object containing the STUN server's response.

---

## Roadmap

---

## 🤝 Contributing

We welcome any form of community contribution!  
Please read the [Contributing Guide](CONTRIBUTING.md) to learn how to submit issues, request features, or contribute code.

---

## 📜 License

This project is licensed under the [LGPL-3.0 License](LICENSE).

---

## 🙏 Acknowledgements

- [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)
- [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)

## 📢 Legal Notice

This open-source project is for learning and educational purposes only. Due to potential patent or copyright issues, please ensure you fully understand relevant laws and regulations before use. **Do not use this tool for commercial purposes or distribute it without authorization.**

All code and related content of this project are for personal technical learning and reference only. Any legal responsibility arising from its use will be borne by the user.

Thank you for your understanding and support.