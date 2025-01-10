# dart_stun

## 📖 简介

`dart_stun` 是一个用于快速处理 STUN（Session Traversal Utilities for NAT）协议的 Dart 库，支持 RFC 3489、RFC 5389、RFC 5780 标准，支持 UDP、TCP 和 TLS，帮助开发者快速收发 STUN 报文。

---

## ✨ 功能

- **支持标准**：RFC 3489、RFC 5389、RFC 5780。
- **支持多种传输协议**：包括 UDP、TCP 和 TLS。
- **简单易用**：快速构建和解析 STUN 消息。

---

## 📥 安装

在 `pubspec.yaml` 文件中添加依赖：

```yaml
dependencies:
  stun:
    git:
      url: https://github.com/halifox/dart_stun
      ref: 1.0.0
```

---

## 🛠️ 使用方法

### 创建 STUN 客户端
使用 `StunClient.create` 方法创建客户端实例。

```dart
StunClient client = StunClient.create(
  transport: Transport.udp,          // 传输协议：udp、tcp 或 tls
  serverHost: "stun.hot-chilli.net", // STUN 服务器地址
  serverPort: 3478,                  // STUN 服务器端口
  localIp: "0.0.0.0",               // 本地 IP 地址
  localPort: 54320,                 // 本地端口
  stunProtocol: StunProtocol.RFC5780 // 使用的 STUN 协议版本
);
```

### 创建绑定请求（Binding Request）
使用 `createBindingStunMessage` 方法生成绑定请求消息。

```dart
StunMessage bindingRequest = client.createBindingStunMessage();
```

### 创建地址变更请求（Change Request）
使用 `createChangeStunMessage` 方法生成地址变更请求消息。

```dart
StunMessage changeRequest = client.createChangeStunMessage(
  flagChangeIp: true,   // 是否请求变更 IP
  flagChangePort: true  // 是否请求变更端口
);
```

### 发送请求并等待响应
使用 `sendAndAwait` 方法发送 STUN 消息并等待响应。

```dart
try {
  StunMessage response = await client.sendAndAwait(bindingRequest, isAutoClose: true);
  // 处理响应
} catch (e) {
  print("请求超时或发生错误: $e");
}
```

### 直接发送 STUN 消息
使用 `send` 方法直接发送 STUN 消息。

```dart
await client.send(bindingRequest);
```

### 消息监听
通过添加和移除消息监听器，可以处理收到的 STUN 消息。

### 添加消息监听器
使用 `addOnMessageListener` 方法注册消息监听器。

```dart
client.addOnMessageListener((StunMessage message) {
  print("收到消息: \$message");
});
```

### 移除消息监听器
使用 `removeOnMessageListener` 方法移除已注册的监听器。

```dart
client.removeOnMessageListener(listener);
```

### 超时处理
`sendAndAwait` 方法默认超时时间为 6 秒，超时将抛出 `TimeoutException`。

### 注意事项
- 发送消息前需确保 STUN 服务器地址已成功解析。
- `isAutoClose` 参数设为 `true` 时，响应后将自动断开连接。
- 事务 ID（Transaction ID）需随机生成，确保唯一性。

### 错误处理
- 如果 STUN 服务器无法解析，`send` 方法将抛出异常。
- 响应超时时会抛出 `TimeoutException`。

---

## 示例

```dart
void main() async {
  StunClient client = StunClient.create();
  StunMessage request = client.createBindingStunMessage();

  client.addOnMessageListener((StunMessage message) {
    print("收到监听消息: \$message");
  });

  try {
    StunMessage response = await client.sendAndAwait(request);
    print("收到响应: \$response");
  } catch (e) {
    print("发生错误: \$e");
  }
}
```



---

## 🤝 贡献

我们欢迎任何形式的社区贡献！  
请阅读 [贡献指南](CONTRIBUTING.md)，了解如何提交 Issue、请求功能或贡献代码。

---

## 📜 许可证

本项目遵循 [LGPL-3.0 License](LICENSE)。

---

## 🙏 致谢

- [P2P技术详解(一)：NAT详解——详细原理、P2P简介](http://www.52im.net/thread-50-1-1.html)
- [P2P技术详解(二)：P2P中的NAT穿越(打洞)方案详解](http://www.52im.net/thread-542-1-1.html)
- [P2P技术详解(三)：P2P中的NAT穿越(打洞)方案详解(进阶分析篇)](http://www.52im.net/thread-2872-1-1.html)
- [Netmanias 对于 RFC 3489 与 STUN (RFC 5389/5780) 的对比解读](https://netmanias.com/en/post/techdocs/6065/nat-network-protocol/stun-rfc-3489-vs-stun-rfc-5389-5780)
- [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)
- [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)
- [RFC 3489 中文](https://rfc2cn.com/rfc3489.html)
- [RFC 5389 中文](https://rfc2cn.com/rfc5389.html)
- [RFC 5780 中文](https://rfc2cn.com/rfc5780.html)


## 📢 法律声明

本开源项目仅供学习和交流用途。由于可能涉及专利或版权相关内容，请在使用前确保已充分理解相关法律法规。未经授权，**请勿将本工具用于商业用途或进行任何形式的传播**。

本项目的所有代码和相关内容仅供个人技术学习与参考，任何使用产生的法律责任由使用者自行承担。

感谢您的理解与支持。