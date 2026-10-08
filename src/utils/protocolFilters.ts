import { decoderCapabilities, type CapabilityLevel } from './decoders/capabilities';

export function packetProtocolNames(packet: any): string[] {
  const stack = Array.isArray(packet?.protocolStack) ? packet.protocolStack : [];
  const layers = Array.isArray(packet?.decodedLayers) ? packet.decodedLayers.map((layer: any) => layer?.name) : [];
  const names = [packet?.protocol, ...stack, ...layers].filter((name): name is string => typeof name === 'string' && name.length > 0);
  return [...new Map(names.map((name) => [name.toUpperCase(), name])).values()];
}

export function protocolCounts(packets: any[]): [string, number][] {
  const counts = new Map<string, { name: string; count: number }>();
  for (const packet of packets) {
    for (const name of packetProtocolNames(packet)) {
      const key = name.toUpperCase();
      const entry = counts.get(key) ?? { name, count: 0 };
      entry.count++;
      counts.set(key, entry);
    }
  }
  return [...counts.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)).map(({ name, count }) => [name, count]);
}

export function matchesProtocolFilter(packet: any, protocols: string[] = [], text = ''): boolean {
  const names = packetProtocolNames(packet).map((name) => name.toUpperCase());
  if (protocols.length && !protocols.some((name) => names.includes(name.toUpperCase()))) return false;
  return !text || ['number', 'time', 'source', 'destination', 'protocol', 'info'].some((key) => String(packet?.[key] ?? '').toLowerCase().includes(text.toLowerCase()));
}

const aliases: Record<string, string[]> = {
  eth: ['Ethernet'], sll: ['SLL', 'Linux SLL'], sll2: ['SLL2', 'Linux SLL2'],
  vlan: ['VLAN'], qinq: ['QinQ'], mpls: ['MPLS'], pppoe: ['PPPoE'],
  arp: ['ARP', 'RARP'], icmp: ['ICMP'], icmpv6: ['ICMPv6', 'NDP'],
  dns: ['DNS', 'mDNS', 'LLMNR'], dhcp: ['DHCP', 'BOOTP'], http: ['HTTP'],
  tls: ['TLS', 'SSL'], rtp: ['RTP', 'RTCP'], ftp: ['FTP', 'SMTP', 'POP3', 'IMAP'],
  gtpu: ['GTPv1-U', 'GTP-U'], gtpc2: ['GTPv2-C', 'GTPv2', 'GTP-C'],
  s1ap: ['S1AP', 'NGAP'], m3ua: ['M3UA', 'SCCP'],
};

export interface ProtocolChoice {
  name: string; count: number; level: CapabilityLevel | 'Unregistered'; notes: string;
}

export function protocolChoices(packets: any[]): ProtocolChoice[] {
  const observed = protocolCounts(packets);
  const choices = new Map<string, ProtocolChoice>();
  for (const capability of decoderCapabilities) {
    // A stream-analysis capability is not a protocol facet.
    if (capability.id === 'tcpstream' || capability.id === 'ipfrag') continue;
    for (const name of aliases[capability.id] ?? [capability.name]) {
      choices.set(name.toUpperCase(), { name, count: 0, level: capability.level, notes: capability.notes });
    }
  }
  for (const name of ['HTTP/2', 'gRPC', 'QUIC', 'WebSocket', 'Kafka', 'Redis', 'PostgreSQL', 'MySQL', '5G SBI', 'BGP', 'OSPF', 'IS-IS', 'IPsec', 'ESP', 'AH', 'EAP', '802.11']) {
    if (!choices.has(name.toUpperCase())) choices.set(name.toUpperCase(), { name, count: 0, level: 'Unavailable', notes: 'No dedicated dissector is implemented. Encrypted application fields cannot be decoded without supported keys.' });
  }
  for (const [name, count] of observed) {
    const existing = choices.get(name.toUpperCase());
    choices.set(name.toUpperCase(), { name, count, level: existing?.level ?? 'Unregistered', notes: existing?.notes ?? 'Observed in decoded layers; no dedicated capability entry is declared.' });
  }
  return [...choices.values()].sort((a, b) => Number(b.count > 0) - Number(a.count > 0) || a.name.localeCompare(b.name));
}