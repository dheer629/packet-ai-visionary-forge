/**
 * Byte-level packet decoder.
 *
 * Every value produced here is read from the captured bytes. When bytes are
 * missing or malformed the decoder records what it could read and stops - it
 * never invents field values.
 */

export interface DecodedLayer {
  name: string;
  /** Byte offset of this layer inside the frame (evidence for the UI). */
  offset: number;
  length?: number;
  fields: Record<string, string | number>;
}

export interface DecodeResult {
  protocol: string;
  source: string;
  destination: string;
  info: string;
  /** Ordered protocol stack, e.g. ["Ethernet","IPv4","UDP","GTPv1-U","IPv4","TCP"]. */
  stack: string[];
  layers: DecodedLayer[];
  truncated: boolean;
}

type Bytes = Uint8Array;

const u8 = (b: Bytes, o: number) => b[o];
const u16 = (b: Bytes, o: number) => (b[o] << 8) | b[o + 1];
const u24 = (b: Bytes, o: number) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];
const u32 = (b: Bytes, o: number) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
const hex = (n: number, w = 2) => `0x${n.toString(16).padStart(w, '0')}`;
const mac = (b: Bytes, o: number) =>
  Array.from(b.slice(o, o + 6)).map(x => x.toString(16).padStart(2, '0')).join(':');
const ipv4 = (b: Bytes, o: number) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

const ipv6 = (b: Bytes, o: number) => {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(u16(b, o + i).toString(16));
  // RFC 5952 zero compression
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  groups.forEach((g, i) => {
    if (g === '0') {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  });
  if (bestLen > 1) {
    return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLen).join(':')}`;
  }
  return groups.join(':');
};

const ascii = (b: Bytes, o: number, len: number) => {
  let s = '';
  for (let i = o; i < Math.min(b.length, o + len); i++) {
    const c = b[i];
    s += c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
  }
  return s;
};

class Ctx {
  layers: DecodedLayer[] = [];
  stack: string[] = [];
  source = '';
  destination = '';
  protocol = 'Unknown';
  info = '';
  truncated = false;
  depth = 0;

  push(
    name: string,
    offset: number,
    fields: Record<string, string | number>,
    length?: number,
    fieldOffsets?: FieldOffsets,
  ) {
    this.layers.push({ name, offset, length, fields, fieldOffsets });
    this.stack.push(name);
    this.protocol = name;
  }
}

const need = (b: Bytes, o: number, n: number, ctx: Ctx) => {
  if (b.length < o + n) { ctx.truncated = true; return false; }
  return true;
};

/* ------------------------------------------------------------------ */
/* Link layer                                                          */
/* ------------------------------------------------------------------ */

export const decodePacketBytes = (input: number[] | Uint8Array, linkType = 1): DecodeResult => {
  const bytes = input instanceof Uint8Array ? input : Uint8Array.from(input || []);
  const ctx = new Ctx();

  try {
    switch (linkType) {
      case 0:
      case 108: decodeLoopback(bytes, 0, ctx); break;
      case 113: decodeSll(bytes, 0, ctx); break;
      case 276: decodeSll2(bytes, 0, ctx); break;
      case 12:
      case 101:
      case 228:
      case 229: decodeIpVersionSniff(bytes, 0, ctx); break;
      default: decodeEthernet(bytes, 0, ctx); break;
    }
  } catch {
    ctx.info = ctx.info || 'Malformed packet: decoding stopped';
    ctx.truncated = true;
  }

  if (!ctx.info) ctx.info = `${ctx.protocol} packet`;
  return {
    protocol: ctx.protocol,
    source: ctx.source || 'Unknown',
    destination: ctx.destination || 'Unknown',
    info: ctx.info,
    stack: ctx.stack,
    layers: ctx.layers,
    truncated: ctx.truncated,
  };
};

function decodeEthernet(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 14, ctx)) return;
  const dst = mac(b, o), src = mac(b, o + 6);
  const type = u16(b, o + 12);
  ctx.push('Ethernet', o, { 'Destination MAC': dst, 'Source MAC': src, EtherType: hex(type, 4) }, 14);
  ctx.source = src; ctx.destination = dst;
  if (type <= 1500) {
    ctx.info = `IEEE 802.3 length ${type}`;
    return;
  }
  decodeEtherType(b, o + 14, type, ctx);
}

function decodeLoopback(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const af = u32(b, o) > 0xffff ? b[o] : u32(b, o); // host byte order tolerance
  ctx.push('Loopback', o, { 'Address family': af }, 4);
  if (af === 2) decodeIPv4(b, o + 4, ctx);
  else if (af === 24 || af === 28 || af === 30) decodeIPv6(b, o + 4, ctx);
  else decodeIpVersionSniff(b, o + 4, ctx);
}

function decodeSll(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 16, ctx)) return;
  const packetType = u16(b, o);
  const proto = u16(b, o + 14);
  const addrLen = u16(b, o + 4);
  const src = addrLen >= 6 ? mac(b, o + 6) : '';
  ctx.push('Linux cooked (SLL)', o, {
    'Packet type': sllPacketType(packetType),
    'Address type': u16(b, o + 2),
    'Address length': addrLen,
    'Source MAC': src || 'n/a',
    Protocol: hex(proto, 4),
  }, 16);
  if (src) ctx.source = src;
  decodeEtherType(b, o + 16, proto, ctx);
}

function decodeSll2(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 20, ctx)) return;
  const proto = u16(b, o);
  const ifIndex = u32(b, o + 4);
  const addrLen = u8(b, o + 9);
  ctx.push('Linux cooked v2 (SLL2)', o, {
    Protocol: hex(proto, 4),
    'Interface index': ifIndex,
    'Packet type': sllPacketType(u8(b, o + 10)),
    'Address length': addrLen,
  }, 20);
  decodeEtherType(b, o + 20, proto, ctx);
}

const sllPacketType = (t: number) =>
  ({ 0: 'Unicast to us', 1: 'Broadcast', 2: 'Multicast', 3: 'Unicast to other host', 4: 'Sent by us' } as Record<number, string>)[t]
  ?? `Type ${t}`;

function decodeIpVersionSniff(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 1, ctx)) return;
  const v = (b[o] >> 4) & 0x0f;
  if (v === 4) decodeIPv4(b, o, ctx);
  else if (v === 6) decodeIPv6(b, o, ctx);
  else { ctx.protocol = 'Unknown'; ctx.info = `Unrecognised IP version nibble ${v}`; }
}

function decodeEtherType(b: Bytes, o: number, type: number, ctx: Ctx) {
  switch (type) {
    case 0x0800: return decodeIPv4(b, o, ctx);
    case 0x86dd: return decodeIPv6(b, o, ctx);
    case 0x0806: return decodeARP(b, o, ctx, 'ARP');
    case 0x8035: return decodeARP(b, o, ctx, 'RARP');
    case 0x8100: return decodeVlan(b, o, ctx, '802.1Q VLAN');
    case 0x88a8:
    case 0x9100: return decodeVlan(b, o, ctx, '802.1ad QinQ');
    case 0x8847: return decodeMpls(b, o, ctx, 'MPLS unicast');
    case 0x8848: return decodeMpls(b, o, ctx, 'MPLS multicast');
    case 0x8863: return decodePppoe(b, o, ctx, true);
    case 0x8864: return decodePppoe(b, o, ctx, false);
    default:
      ctx.protocol = `EtherType ${hex(type, 4)}`;
      ctx.info = `Unhandled EtherType ${hex(type, 4)}`;
  }
}

/* ------------------------------------------------------------------ */
/* Encapsulation                                                       */
/* ------------------------------------------------------------------ */

function decodeVlan(b: Bytes, o: number, ctx: Ctx, name: string) {
  if (!need(b, o, 4, ctx)) return;
  const tci = u16(b, o);
  const inner = u16(b, o + 2);
  ctx.push(name, o, {
    'VLAN ID': tci & 0x0fff,
    Priority: (tci >> 13) & 0x07,
    DEI: (tci >> 12) & 0x01,
    'Inner EtherType': hex(inner, 4),
  }, 4);
  decodeEtherType(b, o + 4, inner, ctx);
}

function decodeMpls(b: Bytes, o: number, ctx: Ctx, name: string) {
  let cur = o;
  const labels: number[] = [];
  let bottom = false;
  while (!bottom && need(b, cur, 4, ctx)) {
    const w = u32(b, cur);
    labels.push((w >>> 12) & 0xfffff);
    bottom = ((w >>> 8) & 0x01) === 1;
    cur += 4;
    if (labels.length > 10) break;
  }
  ctx.push(name, o, {
    'Label stack': labels.join(' > '),
    'Stack depth': labels.length,
    TTL: b.length > cur - 1 ? b[cur - 1] : 'n/a',
  }, cur - o);
  decodeIpVersionSniff(b, cur, ctx);
}

function decodePppoe(b: Bytes, o: number, ctx: Ctx, discovery: boolean) {
  if (!need(b, o, 6, ctx)) return;
  const sessionId = u16(b, o + 2);
  const payloadLen = u16(b, o + 4);
  if (discovery) {
    ctx.push('PPPoE Discovery', o, { Code: hex(b[o + 1]), 'Session ID': sessionId, 'Payload length': payloadLen }, 6);
    ctx.info = `PPPoE Discovery code ${hex(b[o + 1])}`;
    return;
  }
  const ppp = u16(b, o + 6);
  ctx.push('PPPoE Session', o, { 'Session ID': sessionId, 'Payload length': payloadLen, 'PPP protocol': hex(ppp, 4) }, 8);
  if (ppp === 0x0021) decodeIPv4(b, o + 8, ctx);
  else if (ppp === 0x0057) decodeIPv6(b, o + 8, ctx);
  else ctx.info = `PPP protocol ${hex(ppp, 4)}`;
}

function decodeGre(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const flags = u16(b, o);
  const proto = u16(b, o + 2);
  let cur = o + 4;
  const fields: Record<string, string | number> = { Protocol: hex(proto, 4), Version: flags & 0x07 };
  if (flags & 0x8000) { fields.Checksum = hex(u16(b, cur), 4); cur += 4; }
  if (flags & 0x2000) { fields.Key = u32(b, cur); cur += 4; }
  if (flags & 0x1000) { fields['Sequence number'] = u32(b, cur); cur += 4; }
  ctx.push('GRE', o, fields, cur - o);
  if (proto === 0x0800) decodeIPv4(b, cur, ctx);
  else if (proto === 0x86dd) decodeIPv6(b, cur, ctx);
  else if (proto === 0x6558) decodeEthernet(b, cur, ctx);
  else ctx.info = `GRE payload ${hex(proto, 4)}`;
}

function decodeVxlan(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  ctx.push('VXLAN', o, { Flags: hex(b[o]), VNI: u24(b, o + 4) }, 8);
  decodeEthernet(b, o + 8, ctx);
}

function decodeGeneve(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const optLen = (b[o] & 0x3f) * 4;
  const proto = u16(b, o + 2);
  ctx.push('GENEVE', o, { Version: (b[o] >> 6) & 0x03, 'Option length': optLen, 'Protocol type': hex(proto, 4), VNI: u24(b, o + 4) }, 8 + optLen);
  decodeEtherType(b, o + 8 + optLen, proto, ctx);
}

/* ------------------------------------------------------------------ */
/* Network layer                                                       */
/* ------------------------------------------------------------------ */

function decodeIPv4(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 20, ctx)) return;
  const ihl = (b[o] & 0x0f) * 4;
  const total = u16(b, o + 2);
  const flags = (b[o + 6] >> 5) & 0x07;
  const fragOffset = ((b[o + 6] & 0x1f) << 8 | b[o + 7]) * 8;
  const proto = b[o + 9];
  const src = ipv4(b, o + 12), dst = ipv4(b, o + 16);
  const dscp = (b[o + 1] >> 2) & 0x3f;

  ctx.push('IPv4', o, {
    Version: 4,
    'Header length': ihl,
    DSCP: dscp,
    ECN: b[o + 1] & 0x03,
    'Total length': total,
    Identification: hex(u16(b, o + 4), 4),
    Flags: `${flags & 0x02 ? 'DF ' : ''}${flags & 0x01 ? 'MF' : ''}`.trim() || 'none',
    'Fragment offset': fragOffset,
    TTL: b[o + 8],
    Protocol: `${proto} (${ipProtoName(proto)})`,
    'Header checksum': hex(u16(b, o + 10), 4),
    Source: src,
    Destination: dst,
    'Options length': Math.max(0, ihl - 20),
  }, ihl);
  ctx.source = src; ctx.destination = dst;

  const isFragment = (flags & 0x01) === 1 || fragOffset > 0;
  if (isFragment && fragOffset > 0) {
    ctx.protocol = 'IPv4 fragment';
    ctx.info = `Fragmented IP protocol=${ipProtoName(proto)}, offset=${fragOffset}${flags & 0x01 ? ', more fragments' : ''} (reassembly not performed)`;
    return;
  }
  decodeIpPayload(b, o + ihl, proto, ctx);
}

function decodeIPv6(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 40, ctx)) return;
  const payloadLen = u16(b, o + 4);
  let next = b[o + 6];
  const src = ipv6(b, o + 8), dst = ipv6(b, o + 24);
  ctx.push('IPv6', o, {
    Version: 6,
    'Traffic class': ((b[o] & 0x0f) << 4) | (b[o + 1] >> 4),
    'Flow label': ((b[o + 1] & 0x0f) << 16) | u16(b, o + 2),
    'Payload length': payloadLen,
    'Next header': `${next} (${ipProtoName(next)})`,
    'Hop limit': b[o + 7],
    Source: src,
    Destination: dst,
  }, 40);
  ctx.source = src; ctx.destination = dst;

  // Extension headers
  let cur = o + 40;
  let guard = 0;
  while ([0, 43, 60, 44, 51].includes(next) && guard++ < 8 && need(b, cur, 8, ctx)) {
    const hdrNext = b[cur];
    if (next === 44) {
      const off = (u16(b, cur + 2) >> 3) * 8;
      ctx.push('IPv6 Fragment header', cur, { 'Next header': hdrNext, 'Fragment offset': off, 'M flag': b[cur + 3] & 0x01, Identification: u32(b, cur + 4) }, 8);
      cur += 8;
      next = hdrNext;
      if (off > 0) {
        ctx.protocol = 'IPv6 fragment';
        ctx.info = `IPv6 fragment offset=${off} (reassembly not performed)`;
        return;
      }
      continue;
    }
    const len = (b[cur + 1] + 1) * 8;
    const name = next === 0 ? 'IPv6 Hop-by-Hop' : next === 43 ? 'IPv6 Routing' : 'IPv6 Destination Options';
    ctx.push(name, cur, { 'Next header': `${hdrNext} (${ipProtoName(hdrNext)})`, Length: len }, len);
    cur += len;
    next = hdrNext;
  }
  decodeIpPayload(b, cur, next, ctx);
}

function decodeIpPayload(b: Bytes, o: number, proto: number, ctx: Ctx) {
  switch (proto) {
    case 1: return decodeICMP(b, o, ctx);
    case 2: return decodeIGMP(b, o, ctx);
    case 6: return decodeTCP(b, o, ctx);
    case 17: return decodeUDP(b, o, ctx);
    case 47: return decodeGre(b, o, ctx);
    case 58: return decodeICMPv6(b, o, ctx);
    case 132: return decodeSCTP(b, o, ctx);
    case 50:
      ctx.push('ESP', o, { SPI: need(b, o, 8, ctx) ? hex(u32(b, o), 8) : 'n/a' });
      ctx.info = 'Encrypted ESP payload';
      return;
    case 51:
      ctx.push('AH', o, { SPI: need(b, o, 12, ctx) ? hex(u32(b, o + 4), 8) : 'n/a' });
      ctx.info = 'IPsec Authentication Header';
      return;
    case 4: return decodeIPv4(b, o, ctx);
    case 41: return decodeIPv6(b, o, ctx);
    default:
      ctx.protocol = ipProtoName(proto);
      ctx.info = `IP protocol ${proto} (${ipProtoName(proto)}) — no dissector`;
  }
}

const ipProtoName = (p: number) =>
  ({ 1: 'ICMP', 2: 'IGMP', 4: 'IPv4', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP' } as Record<number, string>)[p]
  ?? `IP proto ${p}`;

function decodeARP(b: Bytes, o: number, ctx: Ctx, name: string) {
  if (!need(b, o, 28, ctx)) return;
  const op = u16(b, o + 6);
  const sha = mac(b, o + 8), spa = ipv4(b, o + 14);
  const tha = mac(b, o + 18), tpa = ipv4(b, o + 24);
  ctx.push(name, o, {
    'Hardware type': u16(b, o),
    'Protocol type': hex(u16(b, o + 2), 4),
    Operation: `${op} (${op === 1 ? 'request' : op === 2 ? 'reply' : 'other'})`,
    'Sender MAC': sha, 'Sender IP': spa, 'Target MAC': tha, 'Target IP': tpa,
  }, 28);
  ctx.source = spa; ctx.destination = tpa;
  ctx.info = op === 1 ? `Who has ${tpa}? Tell ${spa}` : `${spa} is at ${sha}`;
}

function decodeICMP(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const type = b[o], code = b[o + 1];
  const fields: Record<string, string | number> = { Type: `${type} (${icmpName(type)})`, Code: code, Checksum: hex(u16(b, o + 2), 4) };
  if ((type === 0 || type === 8) && need(b, o, 8, ctx)) {
    fields.Identifier = u16(b, o + 4);
    fields['Sequence number'] = u16(b, o + 6);
  }
  ctx.push('ICMP', o, fields, 8);
  ctx.info = `${icmpName(type)}${fields.Identifier !== undefined ? ` id=${fields.Identifier} seq=${fields['Sequence number']}` : ''}`;
}

const icmpName = (t: number) =>
  ({ 0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench', 5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement', 10: 'Router Solicitation', 11: 'Time Exceeded', 12: 'Parameter Problem', 13: 'Timestamp Request', 14: 'Timestamp Reply' } as Record<number, string>)[t]
  ?? `ICMP type ${t}`;

function decodeICMPv6(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const type = b[o];
  ctx.push('ICMPv6', o, { Type: `${type} (${icmpv6Name(type)})`, Code: b[o + 1], Checksum: hex(u16(b, o + 2), 4) }, 4);
  ctx.info = icmpv6Name(type);
}

const icmpv6Name = (t: number) =>
  ({ 1: 'Destination Unreachable', 2: 'Packet Too Big', 3: 'Time Exceeded', 4: 'Parameter Problem', 128: 'Echo Request', 129: 'Echo Reply', 130: 'Multicast Listener Query', 133: 'Router Solicitation', 134: 'Router Advertisement', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement', 137: 'Redirect' } as Record<number, string>)[t]
  ?? `ICMPv6 type ${t}`;

function decodeIGMP(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const type = b[o];
  const name = ({ 0x11: 'Membership Query', 0x12: 'IGMPv1 Report', 0x16: 'IGMPv2 Report', 0x17: 'Leave Group', 0x22: 'IGMPv3 Report' } as Record<number, string>)[type] ?? `IGMP type ${hex(type)}`;
  ctx.push('IGMP', o, { Type: `${hex(type)} (${name})`, 'Max response time': b[o + 1], 'Group address': ipv4(b, o + 4) }, 8);
  ctx.info = `${name} group ${ipv4(b, o + 4)}`;
}

/* ------------------------------------------------------------------ */
/* Transport                                                           */
/* ------------------------------------------------------------------ */

function decodeTCP(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 20, ctx)) return;
  const sport = u16(b, o), dport = u16(b, o + 2);
  const dataOffset = ((b[o + 12] >> 4) & 0x0f) * 4;
  const flagBits = b[o + 13];
  const flags = [
    flagBits & 0x01 && 'FIN', flagBits & 0x02 && 'SYN', flagBits & 0x04 && 'RST',
    flagBits & 0x08 && 'PSH', flagBits & 0x10 && 'ACK', flagBits & 0x20 && 'URG',
    flagBits & 0x40 && 'ECE', flagBits & 0x80 && 'CWR',
  ].filter(Boolean) as string[];
  const payloadOffset = o + dataOffset;
  const payloadLen = Math.max(0, b.length - payloadOffset);

  ctx.push('TCP', o, {
    'Source port': sport,
    'Destination port': dport,
    'Sequence number': u32(b, o + 4),
    'Acknowledgment number': u32(b, o + 8),
    'Header length': dataOffset,
    Flags: flags.join(' ') || 'none',
    'Window size': u16(b, o + 14),
    Checksum: hex(u16(b, o + 16), 4),
    'Urgent pointer': u16(b, o + 18),
    'Options length': Math.max(0, dataOffset - 20),
    'Payload length': payloadLen,
  }, dataOffset);
  ctx.source = `${ctx.source}:${sport}`;
  ctx.destination = `${ctx.destination}:${dport}`;
  ctx.info = `${sport} → ${dport} [${flags.join(', ')}] Seq=${u32(b, o + 4)} Ack=${u32(b, o + 8)} Win=${u16(b, o + 14)} Len=${payloadLen}`;

  if (payloadLen > 0) decodeTcpApp(b, payloadOffset, sport, dport, ctx);
}

function decodeUDP(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const sport = u16(b, o), dport = u16(b, o + 2), len = u16(b, o + 4);
  ctx.push('UDP', o, {
    'Source port': sport, 'Destination port': dport, Length: len, Checksum: hex(u16(b, o + 6), 4),
  }, 8);
  ctx.source = `${ctx.source}:${sport}`;
  ctx.destination = `${ctx.destination}:${dport}`;
  ctx.info = `${sport} → ${dport} Len=${Math.max(0, len - 8)}`;
  decodeUdpApp(b, o + 8, sport, dport, ctx);
}

function decodeSCTP(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 12, ctx)) return;
  const sport = u16(b, o), dport = u16(b, o + 2);
  const chunks: string[] = [];
  let cur = o + 12;
  let guard = 0;
  let firstDataOffset = -1;
  while (cur + 4 <= b.length && guard++ < 16) {
    const type = b[cur];
    const len = u16(b, cur + 2);
    if (len < 4) break;
    chunks.push(sctpChunkName(type));
    if (type === 0 && firstDataOffset < 0) firstDataOffset = cur + 16;
    cur += Math.ceil(len / 4) * 4;
  }
  ctx.push('SCTP', o, {
    'Source port': sport, 'Destination port': dport,
    'Verification tag': hex(u32(b, o + 4), 8),
    Checksum: hex(u32(b, o + 8), 8),
    Chunks: chunks.join(', ') || 'none',
  }, 12);
  ctx.source = `${ctx.source}:${sport}`;
  ctx.destination = `${ctx.destination}:${dport}`;
  ctx.info = `SCTP ${sport} → ${dport} [${chunks.join(', ')}]`;

  if (firstDataOffset > 0 && firstDataOffset < b.length) {
    // M3UA commonly rides on SCTP port 2905.
    if (sport === 2905 || dport === 2905) decodeM3ua(b, firstDataOffset, ctx);
    else if (sport === 3868 || dport === 3868) decodeDiameter(b, firstDataOffset, ctx);
  }
}

const sctpChunkName = (t: number) =>
  ({ 0: 'DATA', 1: 'INIT', 2: 'INIT ACK', 3: 'SACK', 4: 'HEARTBEAT', 5: 'HEARTBEAT ACK', 6: 'ABORT', 7: 'SHUTDOWN', 8: 'SHUTDOWN ACK', 9: 'ERROR', 10: 'COOKIE ECHO', 11: 'COOKIE ACK', 14: 'SHUTDOWN COMPLETE' } as Record<number, string>)[t]
  ?? `CHUNK ${t}`;

/* ------------------------------------------------------------------ */
/* Application - UDP                                                   */
/* ------------------------------------------------------------------ */

function decodeUdpApp(b: Bytes, o: number, sport: number, dport: number, ctx: Ctx) {
  const p = (n: number) => sport === n || dport === n;
  if (p(53)) return decodeDns(b, o, ctx, 'DNS');
  if (p(5353)) return decodeDns(b, o, ctx, 'mDNS');
  if (p(5355)) return decodeDns(b, o, ctx, 'LLMNR');
  if (p(67) || p(68)) return decodeDhcp(b, o, ctx);
  if (p(546) || p(547)) return decodeDhcpv6(b, o, ctx);
  if (p(123)) return decodeNtp(b, o, ctx);
  if (p(161) || p(162)) return decodeSnmp(b, o, ctx);
  if (p(5060)) return decodeSip(b, o, ctx, 'UDP');
  if (p(1812) || p(1813) || p(1645)) return decodeRadius(b, o, ctx);
  if (p(5683)) return decodeCoap(b, o, ctx);
  if (p(2152) || p(2123)) return decodeGtp(b, o, ctx, dport === 2123 || sport === 2123);
  if (p(8805)) return decodePfcp(b, o, ctx);
  if (p(4789)) return decodeVxlan(b, o, ctx);
  if (p(6081)) return decodeGeneve(b, o, ctx);
  if (p(3868)) return decodeDiameter(b, o, ctx);
  if (sport >= 16384 && dport >= 16384) return decodeRtp(b, o, ctx);
}

function decodeDns(b: Bytes, o: number, ctx: Ctx, name: string) {
  if (!need(b, o, 12, ctx)) return;
  const id = u16(b, o), flags = u16(b, o + 2);
  const qd = u16(b, o + 4), an = u16(b, o + 6);
  const isResponse = (flags & 0x8000) !== 0;
  let qname = '', cur = o + 12, qtype = 0;
  let guard = 0;
  while (cur < b.length && b[cur] !== 0 && guard++ < 64) {
    const len = b[cur];
    if (len > 63 || cur + len + 1 > b.length) break;
    qname += (qname ? '.' : '') + ascii(b, cur + 1, len);
    cur += len + 1;
  }
  if (cur + 5 <= b.length) qtype = u16(b, cur + 1);
  ctx.push(name, o, {
    'Transaction ID': hex(id, 4),
    Type: isResponse ? 'Response' : 'Query',
    'Response code': flags & 0x000f,
    Questions: qd, 'Answer RRs': an,
    'Authority RRs': u16(b, o + 8), 'Additional RRs': u16(b, o + 10),
    'Query name': qname || 'n/a',
    'Query type': dnsType(qtype),
  });
  ctx.info = `${isResponse ? 'Response' : 'Query'} ${hex(id, 4)} ${dnsType(qtype)} ${qname}`.trim();
}

const dnsType = (t: number) =>
  ({ 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' } as Record<number, string>)[t]
  ?? (t ? `TYPE${t}` : '');

function decodeDhcp(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 240, ctx)) return;
  let msgType = 0;
  let cur = o + 240;
  let guard = 0;
  while (cur + 2 <= b.length && b[cur] !== 255 && guard++ < 64) {
    const opt = b[cur], len = b[cur + 1];
    if (opt === 53) { msgType = b[cur + 2]; break; }
    cur += 2 + len;
  }
  const name = ({ 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' } as Record<number, string>)[msgType] ?? 'Message';
  ctx.push('DHCP', o, {
    Operation: b[o] === 1 ? 'Request' : 'Reply',
    'Message type': name,
    'Transaction ID': hex(u32(b, o + 4), 8),
    'Client IP': ipv4(b, o + 12),
    'Your IP': ipv4(b, o + 16),
    'Server IP': ipv4(b, o + 20),
    'Client MAC': mac(b, o + 28),
  });
  ctx.info = `DHCP ${name} — transaction ${hex(u32(b, o + 4), 8)}`;
}

function decodeDhcpv6(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const type = b[o];
  const name = ({ 1: 'SOLICIT', 2: 'ADVERTISE', 3: 'REQUEST', 5: 'RENEW', 7: 'REPLY', 11: 'INFORMATION-REQUEST' } as Record<number, string>)[type] ?? `Type ${type}`;
  ctx.push('DHCPv6', o, { 'Message type': name, 'Transaction ID': hex(u24(b, o + 1), 6) });
  ctx.info = `DHCPv6 ${name}`;
}

function decodeNtp(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const li = (b[o] >> 6) & 0x03, version = (b[o] >> 3) & 0x07, mode = b[o] & 0x07;
  const modeName = ({ 1: 'Symmetric active', 2: 'Symmetric passive', 3: 'Client', 4: 'Server', 5: 'Broadcast', 6: 'Control' } as Record<number, string>)[mode] ?? `Mode ${mode}`;
  ctx.push('NTP', o, { 'Leap indicator': li, Version: version, Mode: modeName, Stratum: b[o + 1], Poll: b[o + 2], Precision: b[o + 3] });
  ctx.info = `NTPv${version} ${modeName}, stratum ${b[o + 1]}`;
}

function decodeSnmp(b: Bytes, o: number, ctx: Ctx) {
  // Minimal BER walk: SEQUENCE { version INTEGER, community OCTET STRING, ... }
  if (!need(b, o, 8, ctx) || b[o] !== 0x30) { ctx.push('SNMP', o, {}); ctx.info = 'SNMP message'; return; }
  let cur = o + 2;
  if (b[o + 1] & 0x80) cur = o + 2 + (b[o + 1] & 0x7f);
  let version = -1, community = '';
  if (b[cur] === 0x02) { version = b[cur + 2]; cur += 2 + b[cur + 1]; }
  if (b[cur] === 0x04) { community = ascii(b, cur + 2, b[cur + 1]); }
  const vName = ({ 0: 'v1', 1: 'v2c', 3: 'v3' } as Record<number, string>)[version] ?? `version ${version}`;
  ctx.push('SNMP', o, { Version: vName, Community: community || 'n/a' });
  ctx.info = `SNMP ${vName}${community ? ` community=${community}` : ''}`;
}

function decodeRadius(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 20, ctx)) return;
  const code = b[o];
  const name = ({ 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 4: 'Accounting-Request', 5: 'Accounting-Response', 11: 'Access-Challenge' } as Record<number, string>)[code] ?? `Code ${code}`;
  ctx.push('RADIUS', o, { Code: name, Identifier: b[o + 1], Length: u16(b, o + 2) });
  ctx.info = `RADIUS ${name} id=${b[o + 1]}`;
}

function decodeCoap(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 4, ctx)) return;
  const type = ({ 0: 'CON', 1: 'NON', 2: 'ACK', 3: 'RST' } as Record<number, string>)[(b[o] >> 4) & 0x03] ?? '';
  const code = b[o + 1];
  ctx.push('CoAP', o, { Version: (b[o] >> 6) & 0x03, Type: type, Code: `${code >> 5}.${(code & 0x1f).toString().padStart(2, '0')}`, 'Message ID': u16(b, o + 2) });
  ctx.info = `CoAP ${type} ${code >> 5}.${(code & 0x1f).toString().padStart(2, '0')} mid=${u16(b, o + 2)}`;
}

function decodeRtp(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 12, ctx)) return;
  const version = (b[o] >> 6) & 0x03;
  if (version !== 2) return;
  const pt = b[o + 1] & 0x7f;
  if (pt >= 72 && pt <= 76) {
    ctx.push('RTCP', o, { Version: version, 'Packet type': b[o + 1], Length: u16(b, o + 2) });
    ctx.info = `RTCP type ${b[o + 1]}`;
    return;
  }
  ctx.push('RTP', o, { Version: version, 'Payload type': pt, 'Sequence number': u16(b, o + 2), Timestamp: u32(b, o + 4), SSRC: hex(u32(b, o + 8), 8), Marker: (b[o + 1] >> 7) & 1 });
  ctx.info = `RTP PT=${pt} Seq=${u16(b, o + 2)} SSRC=${hex(u32(b, o + 8), 8)}`;
}

/* ------------------------------------------------------------------ */
/* Telecom                                                             */
/* ------------------------------------------------------------------ */

function decodeGtp(b: Bytes, o: number, ctx: Ctx, control: boolean) {
  if (!need(b, o, 8, ctx)) return;
  const version = (b[o] >> 5) & 0x07;
  if (version === 2 || control) return decodeGtpv2(b, o, ctx);

  const flags = b[o];
  const msgType = b[o + 1];
  const teid = u32(b, o + 4);
  let headerLen = 8;
  if (flags & 0x07) headerLen = 12; // sequence / N-PDU / extension flags present
  const fields: Record<string, string | number> = {
    Version: version,
    'Message type': `${msgType} (${gtpuMsgName(msgType)})`,
    Length: u16(b, o + 2),
    TEID: hex(teid, 8),
  };
  if (headerLen === 12 && need(b, o, 12, ctx)) {
    fields['Sequence number'] = u16(b, o + 8);
    fields['N-PDU number'] = b[o + 10];
    fields['Next extension header'] = hex(b[o + 11]);
  }
  ctx.push('GTPv1-U', o, fields, headerLen);
  ctx.info = `${gtpuMsgName(msgType)} TEID=${hex(teid, 8)}`;
  if (msgType === 255) decodeIpVersionSniff(b, o + headerLen, ctx);
}

const gtpuMsgName = (t: number) =>
  ({ 1: 'Echo Request', 2: 'Echo Response', 26: 'Error Indication', 31: 'Supported Extension Headers', 254: 'End Marker', 255: 'G-PDU' } as Record<number, string>)[t]
  ?? `GTP-U message ${t}`;

function decodeGtpv2(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const flags = b[o];
  const msgType = b[o + 1];
  const teidPresent = (flags & 0x08) !== 0;
  const fields: Record<string, string | number> = {
    Version: (flags >> 5) & 0x07,
    'Message type': `${msgType} (${gtpv2MsgName(msgType)})`,
    'Message length': u16(b, o + 2),
  };
  let cur = o + 4;
  if (teidPresent && need(b, cur, 4, ctx)) { fields.TEID = hex(u32(b, cur), 8); cur += 4; }
  if (need(b, cur, 3, ctx)) fields['Sequence number'] = u24(b, cur);
  ctx.push('GTPv2-C', o, fields, teidPresent ? 12 : 8);
  ctx.info = `${gtpv2MsgName(msgType)}${fields.TEID ? ` TEID=${fields.TEID}` : ''}`;
}

const gtpv2MsgName = (t: number) =>
  ({ 1: 'Echo Request', 2: 'Echo Response', 32: 'Create Session Request', 33: 'Create Session Response', 34: 'Modify Bearer Request', 35: 'Modify Bearer Response', 36: 'Delete Session Request', 37: 'Delete Session Response', 95: 'Create Bearer Request', 96: 'Create Bearer Response', 170: 'Release Access Bearers Request', 171: 'Release Access Bearers Response' } as Record<number, string>)[t]
  ?? `GTPv2 message ${t}`;

function decodePfcp(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const flags = b[o];
  const msgType = b[o + 1];
  const seidPresent = (flags & 0x01) !== 0;
  const fields: Record<string, string | number> = {
    Version: (flags >> 5) & 0x07,
    'Message type': `${msgType} (${pfcpMsgName(msgType)})`,
    'Message length': u16(b, o + 2),
  };
  let cur = o + 4;
  if (seidPresent && need(b, cur, 8, ctx)) {
    fields.SEID = `${hex(u32(b, cur), 8)}${u32(b, cur + 4).toString(16).padStart(8, '0')}`;
    cur += 8;
  }
  if (need(b, cur, 3, ctx)) fields['Sequence number'] = u24(b, cur);
  ctx.push('PFCP', o, fields);
  ctx.info = `${pfcpMsgName(msgType)}${fields.SEID ? ` SEID=${fields.SEID}` : ''}`;
}

const pfcpMsgName = (t: number) =>
  ({ 1: 'Heartbeat Request', 2: 'Heartbeat Response', 5: 'Association Setup Request', 6: 'Association Setup Response', 50: 'Session Establishment Request', 51: 'Session Establishment Response', 52: 'Session Modification Request', 53: 'Session Modification Response', 54: 'Session Deletion Request', 55: 'Session Deletion Response', 56: 'Session Report Request', 57: 'Session Report Response' } as Record<number, string>)[t]
  ?? `PFCP message ${t}`;

function decodeDiameter(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 20, ctx)) return;
  const flags = b[o + 4];
  const cmd = u24(b, o + 5);
  ctx.push('Diameter', o, {
    Version: b[o],
    'Message length': u24(b, o + 1),
    Flags: `${flags & 0x80 ? 'Request' : 'Answer'}${flags & 0x40 ? ', Proxiable' : ''}`,
    'Command code': cmd,
    'Application ID': u32(b, o + 8),
    'Hop-by-hop ID': hex(u32(b, o + 12), 8),
    'End-to-end ID': hex(u32(b, o + 16), 8),
  });
  ctx.info = `Diameter ${flags & 0x80 ? 'Request' : 'Answer'} cmd=${cmd} app=${u32(b, o + 8)}`;
}

function decodeM3ua(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const cls = b[o + 2], type = b[o + 3];
  ctx.push('M3UA', o, { Version: b[o], 'Message class': cls, 'Message type': type, Length: u32(b, o + 4) });
  ctx.info = `M3UA class=${cls} type=${type} (SCCP payload not dissected)`;
}

/* ------------------------------------------------------------------ */
/* Application - TCP                                                   */
/* ------------------------------------------------------------------ */

function decodeTcpApp(b: Bytes, o: number, sport: number, dport: number, ctx: Ctx) {
  const p = (n: number) => sport === n || dport === n;
  if (p(443) || p(8443) || p(993) || p(995) || b[o] === 0x16 && b[o + 1] === 0x03) return decodeTls(b, o, ctx);
  if (p(80) || p(8080) || p(8000)) return decodeHttp(b, o, ctx);
  if (p(53)) return decodeDns(b, o + 2, ctx, 'DNS (TCP)');
  if (p(22)) return decodeBanner(b, o, ctx, 'SSH');
  if (p(21)) return decodeBanner(b, o, ctx, 'FTP');
  if (p(25) || p(587)) return decodeBanner(b, o, ctx, 'SMTP');
  if (p(110)) return decodeBanner(b, o, ctx, 'POP3');
  if (p(143)) return decodeBanner(b, o, ctx, 'IMAP');
  if (p(5060)) return decodeSip(b, o, ctx, 'TCP');
  if (p(1883)) return decodeMqtt(b, o, ctx);
  if (p(502)) return decodeModbus(b, o, ctx);
  if (p(3868)) return decodeDiameter(b, o, ctx);
  // Fall back to sniffing an HTTP request line in unknown ports.
  const head = ascii(b, o, 8);
  if (/^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|HTTP\/)/.test(head)) return decodeHttp(b, o, ctx);
}

function decodeTls(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 5, ctx)) return;
  const type = b[o];
  const version = u16(b, o + 1);
  const recLen = u16(b, o + 3);
  const versionName = ({ 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3', 0x0300: 'SSL 3.0' } as Record<number, string>)[version] ?? hex(version, 4);
  const typeName = ({ 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data' } as Record<number, string>)[type] ?? `Record type ${type}`;
  const fields: Record<string, string | number> = { 'Content type': typeName, Version: versionName, 'Record length': recLen };

  if (type === 22 && need(b, o + 5, 4, ctx)) {
    const hs = b[o + 5];
    const hsName = ({ 1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 12: 'Server Key Exchange', 14: 'Server Hello Done', 16: 'Client Key Exchange' } as Record<number, string>)[hs] ?? `Handshake ${hs}`;
    fields['Handshake type'] = hsName;
    if (hs === 1) {
      const sni = extractSni(b, o);
      if (sni) fields['Server name (SNI)'] = sni;
    }
    ctx.push('TLS', o, fields);
    ctx.info = `${versionName} ${hsName}${fields['Server name (SNI)'] ? ` — ${fields['Server name (SNI)']}` : ''}`;
    return;
  }
  ctx.push('TLS', o, fields);
  ctx.info = `${versionName} ${typeName}, ${recLen} bytes`;
}

function extractSni(b: Bytes, recordStart: number): string {
  try {
    let cur = recordStart + 5 + 4 + 2 + 32; // handshake hdr + version + random
    const sessionIdLen = b[cur]; cur += 1 + sessionIdLen;
    const cipherLen = u16(b, cur); cur += 2 + cipherLen;
    const compLen = b[cur]; cur += 1 + compLen;
    if (cur + 2 > b.length) return '';
    const extTotal = u16(b, cur); cur += 2;
    const end = Math.min(b.length, cur + extTotal);
    while (cur + 4 <= end) {
      const extType = u16(b, cur);
      const extLen = u16(b, cur + 2);
      if (extType === 0 && cur + 9 <= b.length) {
        const nameLen = u16(b, cur + 7);
        return ascii(b, cur + 9, nameLen);
      }
      cur += 4 + extLen;
    }
  } catch { /* fall through */ }
  return '';
}

function decodeHttp(b: Bytes, o: number, ctx: Ctx) {
  const text = ascii(b, o, Math.min(1024, b.length - o));
  const [firstLine] = text.split('\r\n');
  const hostMatch = text.match(/\r\nHost:\s*([^\r\n]+)/i);
  const fields: Record<string, string | number> = {};
  const req = firstLine.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)/);
  const res = firstLine.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/);
  if (req) {
    fields.Method = req[1]; fields.URI = req[2]; fields.Version = req[3];
    if (hostMatch) fields.Host = hostMatch[1];
    ctx.push('HTTP', o, fields);
    ctx.info = `${req[1]} ${req[2]} ${req[3]}${hostMatch ? ` (Host: ${hostMatch[1]})` : ''}`;
  } else if (res) {
    fields.Version = res[1]; fields['Status code'] = res[2]; fields.Reason = res[3];
    ctx.push('HTTP', o, fields);
    ctx.info = `${res[1]} ${res[2]} ${res[3]}`;
  } else {
    ctx.push('HTTP', o, { Note: 'Continuation or non-initial segment' });
    ctx.info = 'HTTP continuation data';
  }
}

function decodeSip(b: Bytes, o: number, ctx: Ctx, transport: string) {
  const text = ascii(b, o, Math.min(2048, b.length - o));
  const [firstLine] = text.split('\r\n');
  const callId = text.match(/\r\nCall-ID:\s*([^\r\n]+)/i)?.[1];
  const hasSdp = /application\/sdp/i.test(text);
  const fields: Record<string, string | number> = { Transport: transport, 'Start line': firstLine };
  if (callId) fields['Call-ID'] = callId;
  if (hasSdp) {
    const media = text.match(/\r\nm=([^\r\n]+)/g)?.map(m => m.replace(/\r\n/, '').trim()).join('; ');
    fields['SDP body'] = media || 'present';
  }
  ctx.push('SIP', o, fields);
  ctx.info = `${firstLine}${callId ? ` | Call-ID: ${callId}` : ''}`;
}

function decodeBanner(b: Bytes, o: number, ctx: Ctx, name: string) {
  const line = ascii(b, o, Math.min(200, b.length - o)).split('\r\n')[0];
  ctx.push(name, o, { 'First line': line || 'binary/encrypted payload' });
  ctx.info = line ? `${name}: ${line}` : `${name} payload (not plaintext)`;
}

function decodeMqtt(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 2, ctx)) return;
  const type = (b[o] >> 4) & 0x0f;
  const name = ({ 1: 'CONNECT', 2: 'CONNACK', 3: 'PUBLISH', 4: 'PUBACK', 8: 'SUBSCRIBE', 9: 'SUBACK', 12: 'PINGREQ', 13: 'PINGRESP', 14: 'DISCONNECT' } as Record<number, string>)[type] ?? `Type ${type}`;
  let mult = 1, remaining = 0, cur = o + 1, guard = 0;
  while (cur < b.length && guard++ < 4) {
    remaining += (b[cur] & 0x7f) * mult;
    mult *= 128;
    if ((b[cur] & 0x80) === 0) break;
    cur++;
  }
  ctx.push('MQTT', o, { 'Control packet': name, 'Remaining length': remaining });
  ctx.info = `MQTT ${name}, ${remaining} bytes`;
}

function decodeModbus(b: Bytes, o: number, ctx: Ctx) {
  if (!need(b, o, 8, ctx)) return;
  const fn = b[o + 7];
  const name = ({ 1: 'Read Coils', 2: 'Read Discrete Inputs', 3: 'Read Holding Registers', 4: 'Read Input Registers', 5: 'Write Single Coil', 6: 'Write Single Register', 15: 'Write Multiple Coils', 16: 'Write Multiple Registers' } as Record<number, string>)[fn] ?? `Function ${fn}`;
  ctx.push('Modbus/TCP', o, {
    'Transaction ID': u16(b, o), 'Protocol ID': u16(b, o + 2), Length: u16(b, o + 4), 'Unit ID': b[o + 6], 'Function code': `${fn} (${name})`,
  });
  ctx.info = `Modbus ${name}, unit ${b[o + 6]}`;
}
