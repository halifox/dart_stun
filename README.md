# dart_stun

[中文文档](README-CN.md)

## 📖 Introduction

`dart_stun` is a Dart library designed for fast handling of the STUN (Session Traversal Utilities for NAT) protocol. It supports RFC 3489, RFC 5389, and RFC 5780 standards, as well as UDP, TCP, and TLS transport protocols, enabling developers to quickly send and receive STUN messages.

---

## ✨ Features

- **Standards Supported**: RFC 3489, RFC 5389, RFC 5780.  
- **Multiple Transport Protocols**: Supports UDP, TCP, and TLS.  
- **Simple and Easy to Use**: Quickly constructs and parses STUN messages.

---

## 📥 Installation

Add the dependency in your `pubspec.yaml` file:

```yaml
dependencies:
  stun:
    git:
      url: https://github.com/halifox/dart_stun
      ref: 2.0.2
```

---

## 🛠️ Usage

### Create a STUN Client

Use `StunClient.create` to create a client instance.

```dart
StunClient client = StunClient.create(
  transport: Transport.udp,          // Transport protocol: udp, tcp, or tls
  serverHost: "stun.hot-chilli.net", // STUN server address
  serverPort: 3478,                  // STUN server port
  localIp: "0.0.0.0",               // Local IP address
  localPort: 54320,                 // Local port
  stunProtocol: StunProtocol.RFC5780 // STUN protocol version
);
```

### Create a Binding Request

Generate a binding request message using `createBindingStunMessage`.

```dart
StunMessage bindingRequest = client.createBindingStunMessage();
```

### Create a Change Request

Generate a change request message using `createChangeStunMessage`.

```dart
StunMessage changeRequest = client.createChangeStunMessage(
  flagChangeIp: true,   // Request to change IP
  flagChangePort: true  // Request to change port
);
```

### Send Request and Await Response

Send a STUN message and wait for a response with `sendAndAwait`.

```dart
try {
  StunMessage response = await client.sendAndAwait(bindingRequest, isAutoClose: true);
  // Handle response
} catch (e) {
  print("Request timed out or encountered an error: $e");
}
```

### Send STUN Message Directly

Send a STUN message directly using `send`.

```dart
await client.send(bindingRequest);
```

### Message Listener

Add or remove message listeners to handle incoming STUN messages.

**Add Message Listener**

```dart
client.addOnMessageListener((StunMessage message) {
  print("Received message: \$message");
});
```

**Remove Message Listener**

```dart
client.removeOnMessageListener(listener);
```

### Timeout Handling

- `sendAndAwait` has a default timeout of 6 seconds.
- If exceeded, a `TimeoutException` is thrown.

### Notes

- Ensure the STUN server address is resolved before sending messages.
- If `isAutoClose` is set to `true`, the connection will close automatically after receiving a response.
- Transaction IDs must be randomly generated for uniqueness.

### Error Handling

- If the STUN server cannot be resolved, `send` will throw an exception.
- A timeout will result in a `TimeoutException`.

---

## 🛠️ NatChecker Usage (RFC 5780)

### Create an Instance

Use the `NatChecker` constructor with optional parameters:

- `serverHost`: STUN server hostname (default: `"stun.hot-chilli.net"`).
- `serverPort`: STUN server port (default: `3478`).
- `localIp`: Local listening IP address (default: `"0.0.0.0"`).
- `localPort`: Local listening port (default: `54320`).

Example:

```dart
import 'package:stun/src/nat_checker_rfc_5780.dart' as rfc5780;

void main() async {
   rfc5780.NatChecker checker = rfc5780.NatChecker(
    serverHost: "stun.l.google.com",
    serverPort: 19302,
    localIp: "0.0.0.0",
    localPort: 12345,
  );

  final (mappingBehavior, filteringBehavior) = await checker.check();

  print('NAT Mapping Behavior: $mappingBehavior');
  print('NAT Filtering Behavior: $filteringBehavior');
}
```

### Detect NAT Behavior

Call `check` to return the NAT mapping and filtering behaviors:

- `NatMappingBehavior`: Indicates how NAT maps external ports.
- `NatFilteringBehavior`: Indicates how NAT filters external traffic.

Example Output:

```text
NAT Mapping Behavior: AddressDependentMapping
NAT Filtering Behavior: AddressAndPortDependentFiltering
```

---

## 🤝 Contributing

We welcome all forms of community contributions!  
Please read the [Contributing Guide](CONTRIBUTING.md) to learn how to submit issues, request features, or contribute code.

---

## 📜 License

This project is licensed under the [LGPL-3.0 License](LICENSE).

---

## 🙏 Acknowledgements

- [P2P Technology Explained (Part 1): NAT in Depth](http://www.52im.net/thread-50-1-1.html)
- [P2P Technology Explained (Part 2): NAT Traversal Methods](http://www.52im.net/thread-542-1-1.html)
- [P2P Technology Explained (Part 3): Advanced NAT Traversal](http://www.52im.net/thread-2872-1-1.html)
- [Netmanias Comparison of RFC 3489 and STUN (RFC 5389/5780)](https://netmanias.com/en/post/techdocs/6065/nat-network-protocol/stun-rfc-3489-vs-stun-rfc-5389-5780)
- [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)
- [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)
- [RFC 3489 (Chinese)](https://rfc2cn.com/rfc3489.html)
- [RFC 5389 (Chinese)](https://rfc2cn.com/rfc5389.html)
- [RFC 5780 (Chinese)](https://rfc2cn.com/rfc5780.html)

---

## 📢 Legal Disclaimer

This open-source project is for educational and research purposes only.  
Due to possible patent or copyright implications, ensure you understand relevant laws before use.  
**Do not use this tool for commercial purposes or distribute it in any form without authorization.**

All code and related content are for personal learning and reference. Any legal liability arising from use is solely the user's responsibility.

Thank you for your understanding and support.