# stun

纯 Dart 实现的 STUN SDK，提供以下三类能力：

- 发送 STUN Binding Request 并获取公网映射地址
- 构造、编码、解码、校验 STUN 消息和属性
- 基于 RFC 3489 / RFC 5389 / RFC 5780 进行 NAT 行为探测

本库适合以下场景：

- Dart / Flutter 应用中获取 NAT 后的外网地址和端口
- 自己实现或调试 STUN 协议交互
- 对网络环境做 NAT 行为分析
- 对接 UDP / TCP / TLS(STUNS) 形式的 STUN 服务

> 注意：公共 STUN 服务通常只保证基础 Binding 功能，不一定支持完整 RFC 5780 能力。因此 NAT 探测结果会受服务端能力和网络环境影响，部分字段可能为 `unsupported` 或 `undetermined`。

## 功能特性

- 纯 Dart 实现，不依赖平台原生插件
- 支持 `UDP`、`TCP`、`TLS(STUNS)` 三种传输方式
- 支持 `stun:` / `stuns:` URI 形式的目标描述
- 支持 DNS NAPTR / SRV 发现与普通 A/AAAA 解析
- 支持 STUN 消息编码、解码、`FINGERPRINT` 校验
- 支持短期凭证和长期凭证的 `MESSAGE-INTEGRITY`
- 支持常见地址类属性与未知属性保留
- 提供 `NatDetector` 输出结构化 NAT 行为报告

## 安装

在 `pubspec.yaml` 中添加依赖：

```yaml
dependencies:
  stun:
    git:
      url: https://github.com/halifox/dart_stun
      ref: ^3.0.0
```

然后执行：

```bash
dart pub get
```

Flutter 项目同样可以直接使用。

## 导入

```dart
import 'package:stun/stun.dart';
```

公开入口位于 [`lib/stun.dart`](./lib/stun.dart)，默认导出以下核心能力：

- `StunClient`
- `StunServerTarget`
- `StunMessage`
- `NatDetector`

此外，`Transport`、`StunCredentials`、`NatBehaviorReport` 以及 NAT 相关枚举也都可以直接通过 `package:stun/stun.dart` 使用。

## 快速开始

### 1. 发送一次基础 Binding Request

这是最常见的用法。适用于“我只想知道当前 socket 在公网侧映射成了什么地址和端口”。

```dart
import 'package:stun/stun.dart';

Future<void> main() async {
  final client = StunClient.fromUri(
    'stun:stun.l.google.com:19302?transport=udp',
    requestTimeout: const Duration(seconds: 3),
    software: 'my-app',
  );

  final request = client.createBindingRequest();
  final response = await client.sendAndAwait(request);

  final mapped =
      response.attribute<StunXorMappedAddressAttribute>()?.value ??
      response.attribute<StunMappedAddressAttribute>()?.value;

  print('response class: ${response.messageClass}');
  print('mapped address: $mapped');
}
```

如果只需要公网映射地址，优先使用这种方式。它比 NAT 全量探测更快，也更符合大多数业务场景。

### 2. 先解析目标，再复用已解析端点

如果你想单独控制 DNS 发现、记录解析结果，或者在多次请求中复用同一个端点，可以拆成两步：

```dart
import 'package:stun/stun.dart';

Future<void> main() async {
  final client = StunClient.fromUri(
    'stun:global.stun.twilio.com:3478?transport=udp',
  );

  final endpoint = await client.resolveEndpoint();
  print('resolved endpoint: $endpoint');

  final response = await client.sendAndAwait(
    client.createBindingRequest(),
    endpoint: endpoint,
  );

  print('response: $response');
}
```

### 3. 直接做 NAT 行为探测

如果你不是只想拿到映射地址，而是要分析 NAT 类型、过滤行为、绑定生命周期等，可以使用 `NatDetector`：

```dart
import 'package:stun/stun.dart';

Future<void> main() async {
  final detector = NatDetector.fromUri(
    'stun:stun.cloudflare.com:3478?transport=udp',
    requestTimeout: const Duration(seconds: 1),
    initialRto: const Duration(milliseconds: 200),
    maxRetransmissions: 2,
    responseTimeoutMultiplier: 2,
    software: 'my-app-nat-probe',
  );

  final report = await detector.check();

  print('reachability: ${report.reachability}');
  print('local address: ${report.localAddress}');
  print('mapped address: ${report.mappedAddress}');
  print('is natted: ${report.isNatted}');
  print('mapping behavior: ${report.mappingBehavior}');
  print('filtering behavior: ${report.filteringBehavior}');
  print('legacy nat type: ${report.legacyNatType}');
  print('warnings: ${report.warnings}');
}
```

`NatDetector` 只走 UDP。即使你通过 `stun:` URI 传入 TCP 参数，内部也会按 UDP 进行 NAT 探测，因为 RFC 5780 这类探测本质上依赖 UDP 行为。

## 核心概念

### STUN 是什么

STUN 的核心用途是：客户端向 STUN 服务器发送请求，服务器把“它看到的来源地址和端口”返回给客户端。客户端由此可以知道自己在 NAT 或防火墙外侧暴露成什么地址。

最基础的场景是：

1. 客户端发送 Binding Request
2. STUN 服务器收到后返回 Binding Success Response
3. 响应里包含 `XOR-MAPPED-ADDRESS` 或 `MAPPED-ADDRESS`
4. 客户端据此得到公网映射地址

### 本库的三个层次

- `StunClient`
  负责“发请求、收响应”
- `StunMessage`
  负责“组织消息、编码、解码、校验属性”
- `NatDetector`
  负责“在多个 STUN 探针基础上生成 NAT 行为报告”

## URI 与目标服务器

### 支持的 URI 形式

本库支持以下形式：

```text
stun:example.com
stun:example.com:3478
stun:example.com:3478?transport=udp
stun:example.com:3478?transport=tcp
stuns:example.com
stuns:example.com:5349
```

规则如下：

- `stun:` 默认为 `UDP`
- `stuns:` 固定表示 `TLS`
- 若不显式指定端口：
  - `UDP` 默认端口为 `3478`
  - `TCP` 默认端口为 `3478`
  - `TLS` 默认端口为 `5349`

### 使用 `StunServerTarget`

如果你不想用 URI，也可以显式构造目标：

```dart
import 'dart:io';
import 'package:stun/stun.dart';

Future<void> main() async {
  final client = StunClient(
    target: StunServerTarget(
      host: 'stun.telnyx.com',
      port: 3478,
      transport: Transport.udp,
      dnsServers: const [
        InternetAddress('1.1.1.1'),
        InternetAddress('8.8.8.8'),
      ],
    ),
    software: 'my-app',
  );

  final response = await client.sendAndAwait(
    client.createBindingRequest(),
  );

  print(response);
}
```

### DNS 发现行为

当你使用 URI 形式创建目标，并且：

- 没有显式指定端口
- `enableDnsDiscovery` 为 `true`

库会先尝试：

- NAPTR 发现
- SRV 发现
- 最后回退到普通 `A/AAAA` 解析

默认 DNS 服务器为：

- `1.1.1.1`
- `8.8.8.8`

也可以通过 `dnsServers` 传入自定义 DNS：

```dart
import 'dart:io';
import 'package:stun/stun.dart';

final client = StunClient.fromUri(
  'stun:example.com',
  dnsServers: const [
    InternetAddress('223.5.5.5'),
    InternetAddress('1.1.1.1'),
  ],
);
```

如果你的部署环境无法直接访问这些公共 DNS，建议显式传入企业内网可用的 DNS 服务器，或者直接写死端口，避免依赖 DNS 服务发现。

## `StunClient` 使用说明

[`StunClient`](./lib/src/client/stun_client.dart) 是最主要的入口，负责发送请求和接收响应。

### 创建方式

有三种常用方式：

```dart
// 1) 直接传 target
final client1 = StunClient(
  target: StunServerTarget(
    host: 'stun.telnyx.com',
    transport: Transport.udp,
  ),
);

// 2) 通过参数工厂创建
final client2 = StunClient.create(
  transport: Transport.tcp,
  serverHost: 'global.stun.twilio.com',
  serverPort: 3478,
);

// 3) 通过 URI 创建
final client3 = StunClient.fromUri(
  'stuns:global.stun.twilio.com:5349',
);
```

### 常用参数

- `target`
  目标 STUN 服务器描述
- `localAddress`
  指定本地绑定地址，适合多网卡环境或需要固定出口 IP 的场景
- `localPort`
  指定本地端口，默认为 `0`，表示系统自动分配
- `stunProtocol`
  选择消息风格，可选 `rfc3489`、`rfc5389`、`rfc5780`
- `credentials`
  发送带 `MESSAGE-INTEGRITY` 的消息时使用
- `software`
  自动追加 `SOFTWARE` 属性
- `includeFingerprint`
  是否自动追加 `FINGERPRINT`
- `initialRto`
  UDP 初始重传超时
- `maxRetransmissions`
  UDP 最大重传次数
- `responseTimeoutMultiplier`
  UDP 等待总时长的倍率控制
- `requestTimeout`
  TCP / TLS 连接和等待响应的超时
- `onBadCertificate`
  仅 TLS 使用，用于自定义证书校验策略

### 最常用的方法

#### `createBindingRequest()`

生成一个标准 Binding Request：

```dart
final request = client.createBindingRequest();
```

也可以附加额外属性：

```dart
final request = client.createBindingRequest(
  attributes: const [
    StunChangeRequestAttribute(changeIp: true, changePort: true),
  ],
);
```

#### `sendAndAwait()`

发送一个 `StunMessage` 并等待响应：

```dart
final response = await client.sendAndAwait(request);
```

你也可以覆盖单次超时：

```dart
final response = await client.sendAndAwait(
  request,
  timeout: const Duration(seconds: 2),
);
```

#### `resolveEndpoints()` / `resolveEndpoint()`

用于单独做目标发现：

```dart
final endpoints = await client.resolveEndpoints();
final endpoint = await client.resolveEndpoint();
```

#### `encodeMessage()` / `parseMessage()`

如果你想让 `StunClient` 只做“编码和解析辅助”，也可以这样用：

```dart
final bytes = client.encodeMessage(client.createBindingRequest());
final decoded = client.parseMessage(bytes, validateFingerprint: true);
```

## `StunMessage` 使用说明

[`StunMessage`](./lib/src/message/stun_message.dart) 负责 STUN 消息模型本身，适合以下场景：

- 需要自己拼装属性
- 需要手动编解码
- 需要做消息校验
- 需要调试服务端返回内容

### 构造 Binding Request

```dart
import 'package:stun/stun.dart';

final message = StunMessage.bindingRequest(
  attributes: const [
    StunSoftwareAttribute('dart_stun-demo'),
    StunChangeRequestAttribute(changeIp: true, changePort: true),
  ],
);
```

### 手动编码

```dart
final encoded = message.encode(
  includeFingerprint: true,
  software: 'my-app',
);
```

这里有两个常见点：

- `software` 参数会在没有显式 `StunSoftwareAttribute` 时自动补上
- `includeFingerprint: true` 会在消息末尾自动追加 `FINGERPRINT`

### 手动解码

```dart
final decoded = StunMessage.decode(
  encoded,
  validateFingerprint: true,
);
```

如果消息里带有 `FINGERPRINT` 且校验失败，会抛出 `StunProtocolException`。

### 读取属性

```dart
final software = decoded.attribute<StunSoftwareAttribute>()?.description;
final mapped = decoded.attribute<StunXorMappedAddressAttribute>()?.value;
final allUnknown = decoded.attributesOf<StunUnknownAttribute>();
```

### 常用属性类型

本库已经内置以下常见属性：

- `StunMappedAddressAttribute`
- `StunXorMappedAddressAttribute`
- `StunResponseOriginAttribute`
- `StunOtherAddressAttribute`
- `StunChangeRequestAttribute`
- `StunResponsePortAttribute`
- `StunPaddingAttribute`
- `StunSoftwareAttribute`
- `StunFingerprintAttribute`
- `StunMessageIntegrityAttribute`
- `StunUsernameAttribute`
- `StunRealmAttribute`
- `StunNonceAttribute`
- `StunErrorCodeAttribute`
- `StunUnknownAttribute`

### 未知属性保留

如果收到 SDK 不认识的属性，解码后会以 `StunUnknownAttribute` 保留，而不是直接丢弃。这对协议调试和兼容扩展实现很有用。

```dart
final unknown = decoded.attribute<StunUnknownAttribute>();
if (unknown != null) {
  print('type=0x${unknown.type.toRadixString(16)}');
  print('length=${unknown.value.length}');
}
```

## 消息认证与指纹

### `FINGERPRINT`

`FINGERPRINT` 用于快速检测消息完整性和协议正确性，常见于 RFC 5389 风格消息。

编码时：

```dart
final bytes = message.encode(includeFingerprint: true);
```

解码时校验：

```dart
final decoded = StunMessage.decode(bytes, validateFingerprint: true);
```

### `MESSAGE-INTEGRITY`

如果你的服务端要求认证，可以使用 `StunCredentials`。

#### 短期凭证

```dart
const credentials = StunCredentials.shortTerm(
  username: 'demo',
  password: 'secret',
);

final client = StunClient.fromUri(
  'stun:example.com:3478?transport=udp',
  credentials: credentials,
);

final bytes = client.encodeMessage(
  client.createBindingRequest(
    attributes: const [
      StunUsernameAttribute('demo'),
    ],
  ),
);
```

#### 长期凭证

```dart
const credentials = StunCredentials.longTerm(
  username: 'demo',
  password: 'secret',
  realm: 'example.org',
  nonce: 'server-nonce',
);
```

当 `credentials` 被传入 `encode()` 或 `StunClient` 后：

- 若缺少 `USERNAME`，会自动补齐
- 长期凭证下若缺少 `REALM` / `NONCE`，会自动补齐
- 若缺少 `MESSAGE-INTEGRITY`，会自动追加

### 校验消息完整性

```dart
final decoded = StunMessage.decode(encoded, validateFingerprint: true);
final ok = decoded.validateMessageIntegrity(credentials);
print('integrity ok: $ok');
```

## 传输方式

### UDP

默认使用 UDP，适合标准 STUN 场景，也是 NAT 探测的唯一支持方式。

```dart
final client = StunClient.fromUri(
  'stun:stun.telnyx.com:3478?transport=udp',
);
```

### TCP

适合服务端支持 TCP STUN 的情况：

```dart
final client = StunClient.fromUri(
  'stun:global.stun.twilio.com:3478?transport=tcp',
);
```

### TLS / STUNS

适合需要加密传输的环境：

```dart
final client = StunClient.fromUri(
  'stuns:global.stun.twilio.com:5349',
  requestTimeout: const Duration(seconds: 5),
);
```

如果是测试环境、自签名证书或特殊 CA 体系，可以自定义证书处理：

```dart
final client = StunClient.fromUri(
  'stuns:example.com:5349',
  onBadCertificate: (certificate) {
    return true;
  },
);
```

生产环境不建议无条件返回 `true`。

## NAT 探测说明

[`NatDetector`](./lib/src/nat/nat_detector.dart) 会在基础 Binding 之上，尽可能探测更多 NAT 行为并返回 [`NatBehaviorReport`](./lib/src/nat/nat_detector.dart)。

### 创建与执行

```dart
import 'package:stun/stun.dart';

Future<void> main() async {
  final detector = NatDetector.fromUri(
    'stun:stun.cloudflare.com:3478?transport=udp',
    requestTimeout: const Duration(seconds: 1),
    initialBindingLifetimeProbe: const Duration(milliseconds: 300),
    maxBindingLifetimeProbe: const Duration(seconds: 1),
    bindingLifetimePrecision: const Duration(milliseconds: 200),
    fragmentPaddingBytes: 1024,
  );

  final report = await detector.detect();
  print(report);
}
```

`check()` 与 `detect()` 等价：

```dart
final report1 = await detector.check();
final report2 = await detector.detect();
```

兼容性说明：

- `NatChecker` 是 `NatDetector` 的类型别名
- 新代码建议直接使用 `NatDetector`

### `NatBehaviorReport` 字段说明

#### `reachability`

- `reachable`
  至少完成了基础 UDP STUN 交互
- `udpBlocked`
  未收到任何 UDP STUN 响应
- `undetermined`
  无法明确判断

#### `localAddress`

本地绑定的 socket 地址。多网卡或绑定 `0.0.0.0` 时，这个值可用于帮助解释探测结果。

#### `mappedAddress`

STUN 服务端看到的来源地址，即公网映射地址。通常这是业务最关心的字段。

#### `isNatted`

- `true`
  本地地址和映射地址不一致，基本可判断存在 NAT
- `false`
  映射地址看起来就是本地地址
- `null`
  无法判断，例如没有拿到映射地址

#### `mappingBehavior`

表示 NAT 对目标地址变化时，公网映射是否改变：

- `endpointIndependent`
- `addressDependent`
- `addressAndPortDependent`
- `unsupported`
- `undetermined`

#### `filteringBehavior`

表示 NAT 对入站来源限制的严格程度：

- `endpointIndependent`
- `addressDependent`
- `addressAndPortDependent`
- `unsupported`
- `undetermined`

#### `bindingLifetimeEstimate`

NAT 映射大致能保持多久。该结果依赖：

- 服务端是否支持 `RESPONSE-PORT`
- 当前网络是否稳定
- 你配置的探测窗口

如果公共服务端不支持相关能力，这里可能是 `null`。

#### `hairpinning`

判断当前 NAT 是否支持发往自身映射地址的回环探测：

- `yes`
- `no`
- `unsupported`
- `undetermined`

#### `fragmentHandling`

使用带 `PADDING` 的请求探测对较大 UDP 包的处理情况：

- `yes`
- `no`
- `unsupported`
- `undetermined`

#### `algDetected`

当响应同时包含 `MAPPED-ADDRESS` 与 `XOR-MAPPED-ADDRESS` 时，SDK 会比较两者是否一致。若不一致，可能说明链路上存在 ALG 或某种地址改写行为。

#### `serverCapabilities`

用于描述服务端是否支持以下探测能力：

- `otherAddress`
- `responseOrigin`
- `changeRequest`
- `responsePort`
- `padding`

每项状态可能为：

- `supported`
- `unsupported`
- `unknown`

#### `legacyNatType`

这是将现代探测结果回映到传统 NAT 分类模型后的简化结论，可取值包括：

- `openInternet`
- `fullCone`
- `restrictedCone`
- `portRestrictedCone`
- `symmetric`
- `symmetricUdpFirewall`
- `udpBlocked`
- `unknown`

#### `warnings`

探测过程中所有“不足以导致失败，但会影响解释”的信息都会进入 `warnings`。生产环境建议将这些信息写入日志。

### NAT 探测参数建议

如果你是线上实时探测，建议先从保守参数开始：

```dart
final detector = NatDetector.fromUri(
  'stun:stun.cloudflare.com:3478?transport=udp',
  requestTimeout: const Duration(seconds: 1),
  initialRto: const Duration(milliseconds: 200),
  maxRetransmissions: 2,
  responseTimeoutMultiplier: 2,
  initialBindingLifetimeProbe: const Duration(milliseconds: 300),
  maxBindingLifetimeProbe: const Duration(seconds: 1),
  bindingLifetimePrecision: const Duration(milliseconds: 200),
  fragmentPaddingBytes: 1024,
);
```

如果你追求更准确的生命周期探测，可以放大：

- `requestTimeout`
- `initialBindingLifetimeProbe`
- `maxBindingLifetimeProbe`
- `bindingLifetimePrecision`

代价是整体耗时会上升。

## 典型使用场景

### 场景 1：只获取公网地址

```dart
Future<StunTransportAddress?> queryMappedAddress() async {
  final client = StunClient.fromUri(
    'stun:stun.l.google.com:19302?transport=udp',
  );

  final response = await client.sendAndAwait(
    client.createBindingRequest(),
  );

  return response.attribute<StunXorMappedAddressAttribute>()?.value ??
      response.attribute<StunMappedAddressAttribute>()?.value;
}
```

### 场景 2：构造自定义属性请求

```dart
import 'dart:typed_data';
import 'package:stun/stun.dart';

Future<void> main() async {
  final client = StunClient.fromUri(
    'stun:stun.telnyx.com:3478?transport=udp',
  );

  final message = StunMessage.bindingRequest(
    attributes: [
      const StunResponsePortAttribute(40000),
      StunPaddingAttribute(Uint8List(256)),
    ],
  );

  final response = await client.sendAndAwait(message);
  print(response);
}
```

### 场景 3：先拿映射地址，再按需做 NAT 探测

```dart
Future<void> inspectNetwork() async {
  final client = StunClient.fromUri(
    'stun:stun.telnyx.com:3478?transport=udp',
  );

  final bindingResponse = await client.sendAndAwait(
    client.createBindingRequest(),
  );
  final mapped = bindingResponse.attribute<StunXorMappedAddressAttribute>()?.value;

  print('mapped: $mapped');

  final detector = NatDetector.fromUri(
    'stun:stun.telnyx.com:3478?transport=udp',
  );
  final report = await detector.check();

  print('nat type: ${report.legacyNatType}');
}
```

## 异常与错误处理

常见异常类型定义在 [`lib/src/common/exceptions.dart`](./lib/src/common/exceptions.dart)：

- `StunException`
  所有 STUN 相关异常的基类
- `StunParseException`
  解码失败、消息截断、字段格式不正确
- `StunProtocolException`
  协议行为不合法，例如指纹校验失败
- `StunTimeoutException`
  请求超时
- `StunDiscoveryException`
  目标发现失败，例如没有可用端点
- `StunUnsupportedException`
  某项功能不被支持

建议这样处理：

```dart
try {
  final client = StunClient.fromUri(
    'stun:stun.l.google.com:19302?transport=udp',
  );

  final response = await client.sendAndAwait(
    client.createBindingRequest(),
  );

  print(response);
} on StunTimeoutException catch (e) {
  print('timeout: $e');
} on StunDiscoveryException catch (e) {
  print('discovery failed: $e');
} on StunProtocolException catch (e) {
  print('protocol error: $e');
} on StunParseException catch (e) {
  print('parse error: $e');
} catch (e) {
  print('unexpected error: $e');
}
```

## 参数选择建议

### 如果你只做基础公网地址查询

建议：

- 使用 `StunClient`
- `requestTimeout` 设为 `2s ~ 5s`
- UDP 下保留适中的 `initialRto` 和重传次数
- 优先选择稳定的公共服务端或自建服务端

### 如果你做 NAT 分类

建议：

- 使用 `NatDetector`
- 优先使用你自己可控、明确支持 RFC 5780 的服务端
- 不要把公共 STUN 服务的 `unsupported` 直接解释成“客户端有问题”
- 对 `warnings` 做日志留存

### 如果你需要认证

建议：

- 明确使用短期还是长期凭证
- 对长期凭证传入完整 `username / password / realm / nonce`
- 在服务端要求认证时再开启 `MESSAGE-INTEGRITY`

## 已知限制

- `NatDetector` 仅支持 UDP
- 公共 STUN 服务往往只支持基础 Binding，不一定支持：
  - `OTHER-ADDRESS`
  - `CHANGE-REQUEST`
  - `RESPONSE-PORT`
  - `PADDING`
- NAT 行为探测结果强依赖当前网络环境
- TLS 成功与否依赖服务端是否真正开放 STUNS 和证书链是否可被客户端接受
- 如果网络出口经过代理、实验网、云桌面或安全设备，映射结果可能并不是“真实公网地址”

## 测试

仓库当前默认测试路径包括：

- 消息模型测试
- 公共 STUN 基线互操作测试
- 公共 NAT 探测测试

推荐执行：

```bash
dart test -r expanded
```

测试结果会将公共互操作结果分为以下几类：

- `PASS`
- `UNSUPPORTED`
- `NETWORK-UNSTABLE`
- `PROTOCOL-FAILURE`

详细说明见 [`doc/testing_requirements.md`](./doc/testing_requirements.md)。

如果你在 CI 或受限网络环境中运行，请注意：

- 公共 UDP 测试可能受到出口网络影响
- DNS 解析、TLS 握手和公网可达性都可能导致波动
- 要做稳定回归，建议维护一组你自己可控的 STUN 目标

## 参考代码

如果你想看最接近真实使用场景的代码，建议优先阅读：

- [`test/stun_message_test.dart`](./test/stun_message_test.dart)
- [`test/public_stun_client_test.dart`](./test/public_stun_client_test.dart)
- [`test/public_nat_detector_test.dart`](./test/public_nat_detector_test.dart)

这些测试基本覆盖了 SDK 的公开使用方式。

## 参考协议

- RFC 3489
- RFC 5389
- RFC 5780

仓库中也附带了协议文本，便于交叉查阅：

- [`rfc3489.txt`](./rfc3489.txt)
- [`rfc5389.txt`](./rfc5389.txt)
- [`rfc5780.txt`](./rfc5780.txt)

## 适用建议

- 如果你只需要获取外网映射地址，用 `StunClient`
- 如果你需要自己拼 STUN 消息、调试属性或做协议互通，用 `StunMessage`
- 如果你要分析 NAT 类型和行为，用 `NatDetector`

对于生产业务，推荐优先使用你自己可控的 STUN 服务端，而不是完全依赖公共服务端。
