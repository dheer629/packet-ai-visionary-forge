// Trace auto-detection.
//
// Looks at the protocols that were actually decoded from the capture and
// classifies the trace into a profile (web, DNS, telecom signalling, etc.).
// Everything here is derived from real decoded packets — nothing is assumed
// when the evidence is missing.

import { linkTypeName } from './linkTypes';

export interface SuggestedFilter {
  id: string;
  label: string;
  description: string;
  /** Protocol facet values to select. */
  protocols?: string[];
  /** Free-text term applied to the search box. */
  text?: string;
}

export interface TraceProfile {
  /** Human readable trace type, e.g. "Telecom signalling (GTP/Diameter)". */
  name: string;
  /** Short explanation of the evidence behind the classification. */
  reason: string;
  /** Protocols to pre-select so the trace opens in its own format. */
  focusProtocols: string[];
  /** Distinct link layers seen in the capture. */
  linkTypes: string[];
  /** Ready-to-use filters offered to the user. */
  filters: SuggestedFilter[];
}

interface ProfileRule {
  name: string;
  /** Protocol names (upper case) that identify this trace type. */
  markers: string[];
  filters: (present: (p: string) => boolean) => SuggestedFilter[];
}

const has = (set: Set<string>, ...names: string[]) => names.some((n) => set.has(n));

const RULES: ProfileRule[] = [
  {
    name: 'Telecom packet core (GTP / PFCP)',
    markers: ['GTP', 'GTP-U', 'GTP-C', 'GTPV1', 'GTPV2', 'PFCP'],
    filters: (present) => [
      {
        id: 'gtp-user',
        label: 'GTP-U user plane',
        description: 'Only tunnelled subscriber traffic.',
        protocols: ['GTP-U', 'GTP', 'GTPv1'].filter(present),
      },
      {
        id: 'gtp-control',
        label: 'GTP-C / PFCP signalling',
        description: 'Session create, modify and delete messages.',
        protocols: ['GTP-C', 'GTPv2', 'PFCP'].filter(present),
      },
    ],
  },
  {
    name: 'Telecom signalling (Diameter / S1AP / NGAP)',
    markers: ['DIAMETER', 'S1AP', 'NGAP', 'M3UA', 'SCTP'],
    filters: (present) => [
      {
        id: 'sig-diameter',
        label: 'Diameter only',
        description: 'Authentication and policy exchanges.',
        protocols: ['Diameter'].filter(present),
      },
      {
        id: 'sig-ran',
        label: 'RAN signalling',
        description: 'S1AP / NGAP procedures between RAN and core.',
        protocols: ['S1AP', 'NGAP'].filter(present),
      },
      {
        id: 'sig-sctp',
        label: 'SCTP transport',
        description: 'The transport carrying the signalling.',
        protocols: ['SCTP'].filter(present),
      },
    ],
  },
  {
    name: 'Voice / SIP',
    markers: ['SIP', 'RTP', 'RTCP'],
    filters: (present) => [
      { id: 'voice-sip', label: 'SIP signalling', description: 'Call setup and teardown.', protocols: ['SIP'].filter(present) },
      { id: 'voice-media', label: 'RTP media', description: 'Voice or video media streams.', protocols: ['RTP', 'RTCP'].filter(present) },
    ],
  },
  {
    name: 'Web traffic (HTTP / TLS)',
    markers: ['HTTP', 'HTTPS', 'TLS', 'TLSV1', 'TLSV1.2', 'TLSV1.3', 'QUIC'],
    filters: (present) => [
      {
        id: 'web-http',
        label: 'HTTP requests',
        description: 'Plaintext web requests and responses.',
        protocols: ['HTTP'].filter(present),
      },
      {
        id: 'web-tls',
        label: 'TLS / HTTPS',
        description: 'Encrypted web sessions and handshakes.',
        protocols: ['HTTPS', 'TLS', 'TLSv1', 'TLSv1.2', 'TLSv1.3', 'QUIC'].filter(present),
      },
      { id: 'web-errors', label: 'Resets only', description: 'Connections torn down with RST.', text: 'RST' },
    ],
  },
  {
    name: 'Name resolution (DNS)',
    markers: ['DNS', 'MDNS', 'LLMNR'],
    filters: () => [
      { id: 'dns-queries', label: 'Queries only', description: 'Requests sent to resolvers.', text: 'Query' },
      { id: 'dns-answers', label: 'Responses only', description: 'Replies from resolvers.', text: 'Response' },
    ],
  },
  {
    name: 'Network services (DHCP / ARP / ICMP)',
    markers: ['DHCP', 'BOOTP', 'ARP', 'ICMP', 'ICMPV6', 'IGMP', 'NTP'],
    filters: (present) => [
      { id: 'svc-arp', label: 'ARP only', description: 'Address resolution on the local segment.', protocols: ['ARP'].filter(present) },
      { id: 'svc-icmp', label: 'ICMP only', description: 'Reachability and error reports.', protocols: ['ICMP', 'ICMPv6'].filter(present) },
      { id: 'svc-dhcp', label: 'DHCP only', description: 'Address leases and renewals.', protocols: ['DHCP', 'BOOTP'].filter(present) },
    ],
  },
];

export function detectTraceProfile(packets: any[]): TraceProfile | null {
  if (!Array.isArray(packets) || packets.length === 0) return null;

  const counts = new Map<string, number>();
  const linkSet = new Set<string>();

  for (const p of packets) {
    if (!p) continue;
    const proto = String(p.protocol || 'Unknown');
    counts.set(proto, (counts.get(proto) || 0) + 1);
    // Protocol stacks let a TCP frame still count as HTTP/TLS evidence.
    const stack: string[] = Array.isArray(p.protocolStack) ? p.protocolStack : [];
    stack.forEach((s) => {
      const name = String(s);
      if (name !== proto) counts.set(name, (counts.get(name) || 0) + 1);
    });
    if (p.linkType !== undefined && p.linkType !== null) {
      linkSet.add(p.linkTypeName || linkTypeName(Number(p.linkType)));
    }
  }

  if (counts.size === 0) return null;

  const upper = new Set(Array.from(counts.keys()).map((k) => k.toUpperCase()));
  const present = (name: string) => upper.has(name.toUpperCase());
  const ranked = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  const linkTypes = Array.from(linkSet);

  const matched = RULES.find((rule) => has(upper, ...rule.markers));

  if (matched) {
    const filters = matched.filters(present).filter((f) => (f.protocols?.length ?? 0) > 0 || f.text);
    const focus = filters[0]?.protocols?.length ? filters[0].protocols : [ranked[0][0]];
    const evidence = matched.markers.filter((m) => upper.has(m)).slice(0, 3).join(', ');
    return {
      name: matched.name,
      reason: `Detected from ${evidence} in the decoded frames${linkTypes.length ? ` over ${linkTypes.join(', ')}` : ''}.`,
      focusProtocols: focus,
      linkTypes,
      filters,
    };
  }

  // No specialised profile: fall back to the dominant protocols actually seen.
  const top = ranked.slice(0, 3).filter(([name]) => name !== 'Unknown');
  if (top.length === 0) return null;

  return {
    name: `General IP traffic (${top[0][0]} dominant)`,
    reason: `${top[0][1]} of ${packets.length} frames decoded as ${top[0][0]}${
      linkTypes.length ? ` over ${linkTypes.join(', ')}` : ''
    }.`,
    focusProtocols: [top[0][0]],
    linkTypes,
    filters: top.map(([name, count]) => ({
      id: `top-${name}`,
      label: `${name} only`,
      description: `${count} frames decoded as ${name}.`,
      protocols: [name],
    })),
  };
}
