# dart_stun

## 📖 简介

`dart_stun` 是一个用于快速处理 STUN（Session Traversal Utilities for NAT）协议的 Dart 库，支持 RFC 3489、RFC 5389、RFC 5780 标准，支持 UDP、TCP 和 TLS，帮助开发者快速收发 STUN 报文。

---

## ✨ 功能

- **支持标准**：RFC 3489、RFC 5389、RFC 5780。
- **支持多种传输协议**：包括 UDP、TCP 和 TLS。
- **简单易用**：快速构建和解析 STUN 消息。

---

## 🛠️ 使用方法

这段代码演示了如何使用 `StunClient` 类与 STUN 服务器进行通信。STUN（Session Traversal Utilities for NAT）协议被广泛用于帮助 NAT（网络地址转换）后的设备建立直接的 UDP 或 TCP 连接。

1. **创建 STUN 客户端**:
    ```dart
    StunClient stunClient = StunClient.create(
      transport: Transport.udp,  // 选择传输协议：UDP, TCP, TLS等
      serverHost: "stun.hot-chilli.net",  // STUN 服务器的主机名或IP地址
      serverPort: 3478,  // STUN 服务器的端口（标准STUN端口是3478）
      localIp: "0.0.0.0",  // 本地IP地址，通常可以设置为"0.0.0.0"，表示自动选择
      localPort: 54320,  // 本地端口，客户端连接时会使用该端口
      stunProtocol: StunProtocol.RFC5780,  // 选择STUN协议的版本，RFC5780是最常用的一个
    );
    ```

    - `Transport.udp`：指定传输协议，`Transport.udp` 表示使用 UDP 协议，`Transport.tcp` 和 `Transport.tls` 也可以作为选择。
    - `serverHost: "stun.hot-chilli.net"`：设置 STUN 服务器的主机地址。
    - `serverPort: 3478`：配置与 STUN 服务器通信的端口，3478 是 STUN 协议的标准端口。
    - `localIp: "0.0.0.0"`：自动选择本地 IP 地址，通常设置为 "0.0.0.0"。
    - `localPort: 54320`：本地端口，供客户端用于连接。
    - `stunProtocol: StunProtocol.RFC5780`：指定使用的 STUN 协议版本。可以选择 `RFC5780`、`RFC3489`、`RFC5389` 或混合协议 `MIX`。

2. **连接到 STUN 服务器**:
    ```dart
    await stunClient.connect();
    ```
   通过调用 `stunClient.connect()` 方法，客户端会尝试与 STUN 服务器建立连接。

3. **创建绑定请求消息**:
    ```dart
    StunMessage stunMessage = stunClient.createBindingStunMessage();
    ```
   通过调用 `createBindingStunMessage`，客户端会生成一个绑定请求消息（Binding Request）。该消息用于向 STUN 服务器请求获取公网 IP 和端口映射。

4. **发送请求并等待响应**:
    ```dart
    StunMessage data = await stunClient.sendAndAwait(stunMessage);
    ```
   使用 `sendAndAwait` 方法发送绑定请求消息并等待服务器响应。返回的数据是一个 `StunMessage` 对象，包含了 STUN 服务器的响应信息。

---

## 路线图

---

## 🤝 贡献

我们欢迎任何形式的社区贡献！  
请阅读 [贡献指南](CONTRIBUTING.md)，了解如何提交 Issue、请求功能或贡献代码。

---

## 📜 许可证

本项目遵循 [LGPL-3.0 License](LICENSE)。

---

## 🙏 致谢

- [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)
- [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)

## 📢 法律声明

本开源项目仅供学习和交流用途。由于可能涉及专利或版权相关内容，请在使用前确保已充分理解相关法律法规。未经授权，**请勿将本工具用于商业用途或进行任何形式的传播**。

本项目的所有代码和相关内容仅供个人技术学习与参考，任何使用产生的法律责任由使用者自行承担。

感谢您的理解与支持。