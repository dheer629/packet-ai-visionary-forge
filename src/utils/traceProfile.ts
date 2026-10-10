// Trace auto-detection.
//
// Looks at the protocols that were actually decoded from the capture and
// classifies the trace into a profile (web, DNS, telecom signalling, etc.).
// Everything here is derived from real decoded packets — nothing is assumed
// when the evidence is missing.

import { linkTypeName } from './linkTypes';
import { packetProtocolNames, matchesProtocolFilter, protocolCounts } from './protocolFilters';

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
  filters: (match: (...names: string[]) => string[]) => SuggestedFilter[];
}

/** True when any decoded protocol name starts with one of the markers. */
const hasMarker = (names: string[], markers: string[]) =>
  markers.some((m) => names.some((n) => n.toUpperCase().startsWith(m)));

const RULES: ProfileRule[] = [
  {
    name: 'Telecom packet core (GTP / PFCP)',
    markers: ['GTP', 'PFCP'],
    filters: (match) => [
      {
        id: 'gtp-user',
        label: 'GTP-U user plane',
        description: 'Only tunnelled subscriber traffic.',
        protocols: match('GTPv1-U', 'GTP-U'),
      },
      {
        id: 'gtp-control',
        label: 'GTP-C / PFCP signalling',
        description: 'Session create, modify and delete messages.',
        protocols: match('GTPv2', 'GTPv2-C', 'GTP-C', 'PFCP'),
      },
    ],
  },
  {
    name: 'Telecom signalling (Diameter / S1AP / NGAP)',
    markers: ['DIAMETER', 'S1AP', 'NGAP', 'M3UA'],
    filters: (match) => [
      {
        id: 'sig-diameter',
        label: 'Diameter only',
        description: 'Authentication and policy exchanges.',
        protocols: match('Diameter'),
      },
      {
        id: 'sig-ran',
        label: 'RAN signalling',
        description: 'S1AP / NGAP procedures between RAN and core.',
        protocols: match('S1AP', 'NGAP'),
      },
      {
        id: 'sig-sctp',
        label: 'SCTP transport',
        description: 'The transport carrying the signalling.',
        protocols: match('SCTP', 'M3UA'),
      },
    ],
  },
  {
    name: 'Voice / SIP',
    markers: ['SIP', 'RTP', 'RTCP'],
    filters: (match) => [
      { id: 'voice-sip', label: 'SIP signalling', description: 'Call setup and teardown.', protocols: match('SIP') },
      { id: 'voice-media', label: 'RTP media', description: 'Voice or video media streams.', protocols: match('RTP', 'RTCP') },
    ],
  },
  {
    name: 'Web traffic (HTTP / TLS)',
    markers: ['HTTP', 'TLS', 'QUIC'],
    filters: (match) => [
      {
        id: 'web-http',
        label: 'HTTP requests',
        description: 'Plaintext web requests and responses.',
        protocols: match('HTTP'),
      },
      {
        id: 'web-tls',
        label: 'TLS / HTTPS',
        description: 'Encrypted web sessions and handshakes.',
        protocols: match('TLS', 'HTTPS', 'QUIC'),
      },
      { id: 'web-errors', label: 'Resets only', description: 'Connections torn down with RST.', text: 'RST' },
    ],
  },
  {
    name: 'Name resolution (DNS)',
    markers: ['DNS', 'MDNS', 'LLMNR'],
    filters: () => [
      { id: 'dns-queries', label: 'Queries only', description: 'Requests sent to resolvers.', protocols: ['DNS', 'DNS (TCP)', 'mDNS', 'LLMNR'], text: 'Query' },
      { id: 'dns-answers', label: 'Responses only', description: 'Replies from resolvers.', protocols: ['DNS', 'DNS (TCP)', 'mDNS', 'LLMNR'], text: 'Response' },
    ],
  },
  {
    name: 'Network services (DHCP / ARP / ICMP)',
    markers: ['DHCP', 'BOOTP', 'ARP', 'ICMP', 'IGMP', 'NTP'],
    filters: (match) => [
      { id: 'svc-arp', label: 'ARP only', description: 'Address resolution on the local segment.', protocols: match('ARP') },
      { id: 'svc-icmp', label: 'ICMP only', description: 'Reachability and error reports.', protocols: match('ICMP') },
      { id: 'svc-dhcp', label: 'DHCP only', description: 'Address leases and renewals.', protocols: match('DHCP', 'BOOTP') },
    ],
  },
  {
    name: 'Databases and messaging',
    markers: ['KAFKA', 'REDIS', 'POSTGRESQL', 'MYSQL', 'MQTT', 'AMQP'],
    filters: (match) => [
      { id: 'data-db', label: 'Database traffic', description: 'Observed database protocol layers.', protocols: match('Redis', 'PostgreSQL', 'MySQL') },
      { id: 'data-messaging', label: 'Messaging traffic', description: 'Observed messaging protocol layers.', protocols: match('Kafka', 'MQTT', 'AMQP') },
    ],
  },
  {
    name: 'Routing and tunnels',
    markers: ['BGP', 'OSPF', 'IS-IS', 'GRE', 'VXLAN', 'GENEVE', 'MPLS', '802.1Q', '802.1AD'],
    filters: (match) => [
      { id: 'routing-control', label: 'Routing protocols', description: 'Observed routing protocol layers.', protocols: match('BGP', 'OSPF', 'IS-IS') },
      { id: 'routing-tunnels', label: 'Tunnelled traffic', description: 'Observed encapsulation layers.', protocols: match('GRE', 'VXLAN', 'GENEVE', 'MPLS') },
      { id: 'routing-vlan', label: 'VLAN traffic', description: 'Observed VLAN-tagged frames.', protocols: match('802.1Q', '802.1ad') },
    ],
  },
];

interface Evidence {
  names: string[];
  match: (...names: string[]) => string[];
  ranked: [string, number][];
  linkTypes: string[];
  total: number;
}

/** Collects the protocol / link-layer evidence actually present in the capture. */
function collectEvidence(packets: any[]): Evidence | null {
  if (!Array.isArray(packets) || packets.length === 0) return null;

  const counts = new Map<string, number>(protocolCounts(packets));
  const linkSet = new Set<string>();

  for (const p of packets) {
    if (!p) continue;
    if (p.linkType !== undefined && p.linkType !== null) {
      linkSet.add(p.linkTypeName || linkTypeName(Number(p.linkType)));
    }
  }

  if (counts.size === 0) return null;

  const names = Array.from(counts.keys());
  return {
    names,
    match: (...wanted: string[]) =>
      names.filter((n) => wanted.some((w) => n.toUpperCase().startsWith(w.toUpperCase()))),
    ranked: Array.from(counts.entries()).sort((a, b) => b[1] - a[1]),
    linkTypes: Array.from(linkSet),
    total: packets.length,
  };
}

function buildRuleProfile(rule: ProfileRule, ev: Evidence, detected: boolean): TraceProfile {
  const filters = rule.filters(ev.match).filter((f) => (f.protocols?.length ?? 0) > 0 || f.text);
  // Prefer the first filter's protocols; otherwise focus on the protocols that
  // identify this profile and were actually decoded here.
  const markerMatches = ev.match(...rule.markers);
  const focus = filters[0]?.protocols?.length
    ? filters[0].protocols
    : markerMatches.length
      ? markerMatches
      : [ev.ranked[0][0]];

  const evidence = Array.from(new Set(rule.markers.flatMap((m) => ev.match(m)))).slice(0, 3).join(', ');
  return {
    name: rule.name,
    reason: evidence
      ? `${detected ? 'Detected' : 'Selected'} from ${evidence} in the decoded frames${
          ev.linkTypes.length ? ` over ${ev.linkTypes.join(', ')}` : ''
        }.`
      : `No ${rule.name} protocols were decoded in this capture.`,
    focusProtocols: focus,
    linkTypes: ev.linkTypes,
    filters,
  };
}

function buildGeneralProfile(ev: Evidence): TraceProfile | null {
  const top = ev.ranked.slice(0, 3).filter(([name]) => name !== 'Unknown');
  if (top.length === 0) return null;
  return {
    name: `General IP traffic (${top[0][0]} dominant)`,
    reason: `${top[0][1]} of ${ev.total} frames decoded as ${top[0][0]}${
      ev.linkTypes.length ? ` over ${ev.linkTypes.join(', ')}` : ''
    }.`,
    focusProtocols: [top[0][0]],
    linkTypes: ev.linkTypes,
    filters: top.map(([name, count]) => ({
      id: `top-${name}`,
      label: `${name} only`,
      description: `${count} frames decoded as ${name}.`,
      protocols: [name],
    })),
  };
}

export function detectTraceProfile(packets: any[]): TraceProfile | null {
  const ev = collectEvidence(packets);
  if (!ev) return null;
  // Rank by matching frames, not the registry order or repeated nested layers.
  const matched = RULES.map((rule) => ({ rule, count: packets.filter((packet) => hasMarker(packetProtocolNames(packet), rule.markers)).length }))
    .filter((entry) => entry.count > 0).sort((a, b) => b.count - a.count)[0]?.rule;
  return matched ? buildRuleProfile(matched, ev, true) : buildGeneralProfile(ev);
}

/**
 * Every view the user can switch to for this capture. Views whose protocols
 * were not decoded here are still listed but flagged as unavailable, so the
 * override never pretends data exists.
 */
export function listTraceProfiles(
  packets: any[],
): { name: string; available: boolean; profile: TraceProfile }[] {
  const ev = collectEvidence(packets);
  if (!ev) return [];
  const options = RULES.map((rule) => ({
    name: rule.name,
    available: hasMarker(ev.names, rule.markers),
    profile: buildRuleProfile(rule, ev, false),
  }));
  const general = buildGeneralProfile(ev);
  if (general) options.push({ name: general.name, available: true, profile: general });
  return options;
}

/** Rebuilds a specific view by name (used when the user overrides detection). */
export function getTraceProfileByName(packets: any[], name: string): TraceProfile | null {
  return listTraceProfiles(packets).find((o) => o.name === name)?.profile ?? null;
}

/** Suggestions across every observed family, with counts from the same filter predicate used by the table. */
export function captureFilterSuggestions(packets: any[]): (SuggestedFilter & { count: number })[] {
  const profiles = listTraceProfiles(packets).filter((entry) => entry.available);
  const candidates = profiles.flatMap((entry) => entry.profile.filters);
  for (const [name] of protocolCounts(packets)) {
    candidates.push({ id: `protocol-${name}`, label: `${name} frames`, description: `Frames containing a decoded ${name} layer.`, protocols: [name] });
  }
  const seen = new Set<string>();
  return candidates.flatMap((filter) => {
    if (filter.protocols && !filter.protocols.length) return [];
    const protocols = filter.protocols?.filter((name) => packets.some((packet) => packetProtocolNames(packet).some((value) => value.toUpperCase() === name.toUpperCase())));
    if (filter.protocols?.length && !protocols?.length) return [];
    const normalized = { ...filter, protocols };
    const count = packets.filter((packet) => matchesProtocolFilter(packet, protocols, filter.text)).length;
    const signature = `${[...(protocols ?? [])].sort().join('|')}:${filter.text ?? ''}`;
    if (!count || seen.has(signature)) return [];
    seen.add(signature);
    return [{ ...normalized, count }];
  });
}

