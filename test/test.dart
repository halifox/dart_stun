import 'package:stun/stun.dart';

void main() async {
  StunLog.enabled = true;
  const serverUri = 'stun:stun.hot-chilli.net?transport=udp';
  final detector = NatDetector.fromUri(
    serverUri,
  );
  final report = await detector.check();
  print(
    '''
[服务器信息 (Server)]
服务器地址 (Server Endpoint): ${report.serverEndpoint}
本地地址 (Local Address): ${report.localAddress}
映射地址 (Mapped Address): ${report.mappedAddress}

[网络结果 (Network)]
可达性 (Reachability): ${report.reachability}
是否经过 NAT (Is Natted): ${report.isNatted}
映射行为 (Mapping Behavior): ${report.mappingBehavior}
过滤行为 (Filtering Behavior): ${report.filteringBehavior}
传统 NAT 类型 (Legacy NAT Type): ${report.legacyNatType}

[探测能力 (Probe)]
绑定存活时间 (Binding Lifetime Estimate): ${report.bindingLifetimeEstimate}
回环支持 (Hairpinning): ${report.hairpinning}
分片处理 (Fragment Handling): ${report.fragmentHandling}
ALG 检测 (ALG Detected): ${report.algDetected}
服务器能力 (Server Capabilities): ${report.serverCapabilities}
警告 (Warnings): ${report.warnings}
''',
  );
}
