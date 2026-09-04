/**
 * Honest decoder capability registry.
 *
 * "Available"   - the protocol is dissected down to named fields.
 * "Partial"     - the protocol is identified and key header fields are read,
 *                 but the payload/body is not fully dissected.
 * "Unavailable" - recognised on the wire but not dissected.
 *
 * Nothing here is aspirational: every "Available"/"Partial" entry maps to code
 * in `deepDecoder.ts`.
 */

export type CapabilityLevel = 'Available' | 'Partial' | 'Unavailable';

export interface DecoderCapability {
  id: string;
  name: string;
  layer: 'Link' | 'Encapsulation' | 'Network' | 'Transport' | 'Application' | 'Telecom';
  level: CapabilityLevel;
  /** What is actually decoded, in plain terms. */
  notes: string;
}

export const decoderCapabilities: DecoderCapability[] = [
  // Link / capture formats
  { id: 'eth', name: 'Ethernet II', layer: 'Link', level: 'Available', notes: 'MAC addresses, EtherType, 802.3/LLC length form.' },
  { id: 'sll', name: 'Linux cooked (SLL)', layer: 'Link', level: 'Available', notes: 'Packet type, address, protocol (link type 113).' },
  { id: 'sll2', name: 'Linux cooked v2 (SLL2)', layer: 'Link', level: 'Available', notes: 'Protocol, interface index, packet type (link type 276).' },
  { id: 'rawip', name: 'Raw IP', layer: 'Link', level: 'Available', notes: 'Link types 12/101/228/229 — IP version sniffed from first nibble.' },
  { id: 'loopback', name: 'BSD/Null loopback', layer: 'Link', level: 'Available', notes: 'Link types 0/108, address family header.' },

  // Encapsulation
  { id: 'vlan', name: '802.1Q VLAN', layer: 'Encapsulation', level: 'Available', notes: 'VLAN ID, PCP, DEI; inner EtherType followed.' },
  { id: 'qinq', name: '802.1ad QinQ', layer: 'Encapsulation', level: 'Available', notes: 'Stacked VLAN tags, outer + inner IDs.' },
  { id: 'mpls', name: 'MPLS unicast/multicast', layer: 'Encapsulation', level: 'Available', notes: 'Label stack, TC, S bit, TTL; IP payload sniffed.' },
  { id: 'pppoe', name: 'PPPoE session', layer: 'Encapsulation', level: 'Partial', notes: 'Session ID and PPP protocol; IPv4/IPv6 payload followed.' },
  { id: 'gre', name: 'GRE', layer: 'Encapsulation', level: 'Available', notes: 'Flags, protocol type, optional key/sequence; inner packet decoded.' },
  { id: 'vxlan', name: 'VXLAN', layer: 'Encapsulation', level: 'Available', notes: 'VNI; inner Ethernet frame fully decoded.' },
  { id: 'geneve', name: 'GENEVE', layer: 'Encapsulation', level: 'Available', notes: 'VNI, option length; inner frame decoded.' },

  // Network
  { id: 'ipv4', name: 'IPv4', layer: 'Network', level: 'Available', notes: 'All header fields, DSCP/ECN, flags, fragmentation state, options length.' },
  { id: 'ipv6', name: 'IPv6', layer: 'Network', level: 'Available', notes: 'Header plus hop-by-hop, routing, destination and fragment extension headers.' },
  { id: 'ipfrag', name: 'IP fragmentation', layer: 'Network', level: 'Partial', notes: 'Fragments flagged with offset/MF; payload reassembly across packets is not performed.' },
  { id: 'arp', name: 'ARP / RARP', layer: 'Network', level: 'Available', notes: 'Operation, sender/target hardware and protocol addresses.' },
  { id: 'icmp', name: 'ICMPv4', layer: 'Network', level: 'Available', notes: 'Type, code, identifier, sequence, human-readable name.' },
  { id: 'icmpv6', name: 'ICMPv6 / NDP', layer: 'Network', level: 'Available', notes: 'Type, code, neighbour discovery message names.' },
  { id: 'igmp', name: 'IGMP', layer: 'Network', level: 'Available', notes: 'Type, max response time, group address.' },

  // Transport
  { id: 'tcp', name: 'TCP', layer: 'Transport', level: 'Available', notes: 'Ports, sequence/ack, all flags, window, header length, options length, payload length.' },
  { id: 'udp', name: 'UDP', layer: 'Transport', level: 'Available', notes: 'Ports, length, checksum.' },
  { id: 'sctp', name: 'SCTP', layer: 'Transport', level: 'Available', notes: 'Ports, verification tag, chunk types and lengths.' },
  { id: 'tcpstream', name: 'TCP stream reassembly', layer: 'Transport', level: 'Unavailable', notes: 'Per-packet decoding only; segments are not reassembled into streams.' },

  // Application
  { id: 'dns', name: 'DNS / mDNS / LLMNR', layer: 'Application', level: 'Available', notes: 'Transaction ID, flags, question name/type/class, answer counts.' },
  { id: 'dhcp', name: 'DHCPv4 (BOOTP)', layer: 'Application', level: 'Available', notes: 'Message type option, client/your/server addresses, transaction ID.' },
  { id: 'dhcpv6', name: 'DHCPv6', layer: 'Application', level: 'Partial', notes: 'Message type and transaction ID; options are not enumerated.' },
  { id: 'http', name: 'HTTP/1.x', layer: 'Application', level: 'Available', notes: 'Request line (method/URI/version) or status line, Host header when present.' },
  { id: 'tls', name: 'TLS / SSL', layer: 'Application', level: 'Available', notes: 'Record type, version, handshake type and SNI from ClientHello.' },
  { id: 'ntp', name: 'NTP', layer: 'Application', level: 'Available', notes: 'Leap indicator, version, mode, stratum.' },
  { id: 'snmp', name: 'SNMP', layer: 'Application', level: 'Partial', notes: 'Version and community string from the BER envelope; varbinds not walked.' },
  { id: 'sip', name: 'SIP', layer: 'Application', level: 'Available', notes: 'Request method/URI or response status, Call-ID.' },
  { id: 'sdp', name: 'SDP', layer: 'Application', level: 'Partial', notes: 'Detected inside SIP bodies; media lines summarised only.' },
  { id: 'rtp', name: 'RTP / RTCP', layer: 'Application', level: 'Partial', notes: 'Heuristic on even/odd ports: version, payload type, SSRC, sequence.' },
  { id: 'radius', name: 'RADIUS', layer: 'Application', level: 'Available', notes: 'Code, identifier, length.' },
  { id: 'mqtt', name: 'MQTT', layer: 'Application', level: 'Partial', notes: 'Control packet type and remaining length.' },
  { id: 'coap', name: 'CoAP', layer: 'Application', level: 'Partial', notes: 'Version, type, code, message ID.' },
  { id: 'modbus', name: 'Modbus/TCP', layer: 'Application', level: 'Available', notes: 'Transaction/protocol ID, unit ID, function code.' },
  { id: 'ssh', name: 'SSH', layer: 'Application', level: 'Partial', notes: 'Identification banner only; binary packet protocol is encrypted.' },
  { id: 'ftp', name: 'FTP / SMTP / POP3 / IMAP', layer: 'Application', level: 'Partial', notes: 'First command or response line of the text session.' },

  // Telecom
  { id: 'gtpu', name: 'GTPv1-U', layer: 'Telecom', level: 'Available', notes: 'Version, message type, TEID, optional seq/N-PDU; inner IP packet decoded.' },
  { id: 'gtpc2', name: 'GTPv2-C', layer: 'Telecom', level: 'Available', notes: 'Message type name, TEID, sequence number.' },
  { id: 'pfcp', name: 'PFCP', layer: 'Telecom', level: 'Available', notes: 'Version, message type name, SEID, sequence number.' },
  { id: 'diameter', name: 'Diameter', layer: 'Telecom', level: 'Partial', notes: 'Version, command code, flags, application ID; AVPs are not walked.' },
  { id: 's1ap', name: 'S1AP / NGAP', layer: 'Telecom', level: 'Unavailable', notes: 'Carried over SCTP; ASN.1 PER decoding is not implemented.' },
  { id: 'm3ua', name: 'SIGTRAN M3UA / SCCP', layer: 'Telecom', level: 'Partial', notes: 'M3UA common header (class/type) over SCTP; SCCP payload not dissected.' },
];

export const capabilitySummary = () => {
  const by = (level: CapabilityLevel) => decoderCapabilities.filter(c => c.level === level).length;
  return {
    total: decoderCapabilities.length,
    available: by('Available'),
    partial: by('Partial'),
    unavailable: by('Unavailable'),
  };
};

export const getCapability = (id: string) => decoderCapabilities.find(c => c.id === id);
