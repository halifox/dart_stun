import 'package:stun/stun.dart';

class PublicProvider {
  const PublicProvider({
    required this.id,
    required this.uri,
    required this.notes,
    this.natEnabled = true,
  });

  final String id;
  final String uri;
  final String notes;
  final bool natEnabled;

  StunServerTarget get target => StunServerTarget.uri(uri);

  Transport get transport => target.transport;

  String get endpointKey =>
      '${target.host}:${target.effectivePort}/${target.transport.name}';
}

const List<PublicProvider> publicProviders = <PublicProvider>[
  PublicProvider(
    id: 'google_primary',
    uri: 'stun:stun.l.google.com:19302?transport=udp',
    notes: 'Google public STUN over UDP.',
  ),
  PublicProvider(
    id: 'google_secondary',
    uri: 'stun:stun1.l.google.com:19302?transport=udp',
    notes: 'Second Google public STUN hostname over UDP.',
  ),
  PublicProvider(
    id: 'twilio_global_udp',
    uri: 'stun:global.stun.twilio.com:3478?transport=udp',
    notes: 'Twilio global public STUN over UDP.',
  ),
  PublicProvider(
    id: 'twilio_global_tcp',
    uri: 'stun:global.stun.twilio.com:3478?transport=tcp',
    notes: 'Twilio global public STUN over TCP.',
    natEnabled: false,
  ),
  PublicProvider(
    id: 'twilio_global_tls',
    uri: 'stuns:global.stun.twilio.com:5349',
    notes: 'Best-effort Twilio STUNS endpoint.',
    natEnabled: false,
  ),
  PublicProvider(
    id: 'cloudflare_primary',
    uri: 'stun:stun.cloudflare.com:3478?transport=udp',
    notes: 'Cloudflare public STUN over UDP.',
  ),
  PublicProvider(
    id: 'cloudflare_alt53',
    uri: 'stun:stun.cloudflare.com:53?transport=udp',
    notes: 'Cloudflare alternate port 53 over UDP.',
  ),
  PublicProvider(
    id: 'telnyx_primary',
    uri: 'stun:stun.telnyx.com:3478?transport=udp',
    notes: 'Telnyx public STUN over UDP.',
  ),
  PublicProvider(
    id: 'telnyx_tcp',
    uri: 'stun:stun.telnyx.com:3478?transport=tcp',
    notes: 'Telnyx public STUN over TCP.',
    natEnabled: false,
  ),
  PublicProvider(
    id: 'telnyx_tls',
    uri: 'stuns:stun.telnyx.com:5349',
    notes: 'Best-effort Telnyx STUNS endpoint.',
    natEnabled: false,
  ),
  PublicProvider(
    id: 'zoiper_udp',
    uri: 'stun:stun.zoiper.com:3478?transport=udp',
    notes: 'Zoiper public STUN over UDP.',
  ),
  PublicProvider(
    id: 'zoiper_tcp',
    uri: 'stun:stun.zoiper.com:3478?transport=tcp',
    notes: 'Zoiper public STUN over TCP.',
    natEnabled: false,
  ),
  PublicProvider(
    id: 'zadarma_primary',
    uri: 'stun:stun.zadarma.com:3478?transport=udp',
    notes: 'Zadarma public STUN over UDP.',
  ),
  PublicProvider(
    id: 'ippi_primary',
    uri: 'stun:stun.ippi.fr:3478?transport=udp',
    notes: 'ippi public STUN over UDP.',
  ),
  PublicProvider(
    id: 'sipgate_primary',
    uri: 'stun:stun.sipgate.net:10000?transport=udp',
    notes: 'sipgate public STUN over UDP.',
  ),
  PublicProvider(
    id: 'sonetel_primary',
    uri: 'stun:stun.sonetel.com:3478?transport=udp',
    notes: 'Sonetel public STUN over UDP.',
  ),
  PublicProvider(
    id: 'voipbuster_primary',
    uri: 'stun:stun.voipbuster.com:3478?transport=udp',
    notes: 'VoipBuster public STUN over UDP.',
  ),
  PublicProvider(
    id: 'voipstunt_primary',
    uri: 'stun:stun.voipstunt.com:3478?transport=udp',
    notes: 'VoipStunt public STUN over UDP.',
  ),
  PublicProvider(
    id: 'smartvoip_primary',
    uri: 'stun:stun.smartvoip.com:3478?transport=udp',
    notes: 'SmartVoip public STUN over UDP.',
  ),
];

List<PublicProvider> natProviders() {
  return publicProviders
      .where((provider) => provider.transport == Transport.udp)
      .where((provider) => provider.natEnabled)
      .toList(growable: false);
}
