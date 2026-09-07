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
        protocols: match('GTPv2', 'GTP-C', 'PFCP'),
      },
    ],
  },
  {
    name: 'Telecom signalling (Diameter / S1AP / NGAP)',
    markers: ['DIAMETER', 'S1AP', 'NGAP', 'M3UA', 'SCTP'],
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
      { id: 'dns-queries', label: 'Queries only', description: 'Requests sent to resolvers.', text: 'Query' },
      { id: 'dns-answers', label: 'Responses only', description: 'Replies from resolvers.', text: 'Response' },
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
  const matched = RULES.find((rule) => hasMarker(ev.names, rule.markers));
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

