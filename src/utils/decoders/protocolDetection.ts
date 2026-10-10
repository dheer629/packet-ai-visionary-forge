/** Stateless, worker-safe signature gates. Ports only resolve ambiguous wire formats. */
import { isDhcpMessage, isDhcpv6Message, isPfcpMessage, isRtcpMessage } from './datagramSignatures';
export interface ProtocolDetection { name: string; evidence: string; length?: number; }
const u16 = (b: Uint8Array, o: number) => b[o] * 256 + b[o + 1];
const u24 = (b: Uint8Array, o: number) => b[o] * 65536 + b[o + 1] * 256 + b[o + 2];
const u32 = (b: Uint8Array, o: number) => b[o] * 16777216 + u24(b, o + 1);
const text = (b: Uint8Array, limit = 2048) => new TextDecoder().decode(b.subarray(0, limit));

export function isDnsMessage(b: Uint8Array): boolean {
  if (b.length < 12 || (b[2] & 0x78) > 0x28 || (b[3] & 0x40)) return false;
  const counts = [4, 6, 8, 10].map((offset) => u16(b, offset));
  if (!counts.some(Boolean) || counts.reduce((a, v) => a + v, 0) > 512) return false;
  let cur = 12;
  const skipName = () => {
    for (let n = 0; n < 128 && cur < b.length; n++) {
      const len = b[cur++];
      if (!len) return true;
      if ((len & 0xc0) === 0xc0) {
        if (cur >= b.length) return false;
        const target = ((len & 0x3f) << 8) | b[cur++];
        return target >= 12 && target < cur - 2;
      }
      if (len > 63 || cur + len > b.length) return false;
      cur += len;
    }
    return false;
  };
  for (let i = 0; i < counts[0]; i++) {
    if (!skipName() || cur + 4 > b.length || !u16(b, cur) || !u16(b, cur + 2)) return false;
    cur += 4;
  }
  for (let i = 0; i < counts[1] + counts[2] + counts[3]; i++) {
    if (!skipName() || cur + 10 > b.length) return false;
    const length = u16(b, cur + 8);
    cur += 10 + length;
    if (cur > b.length) return false;
  }
  return cur === b.length;
}

export function detectApplication(b: Uint8Array, transport: 'TCP' | 'UDP', sport: number, dport: number): ProtocolDetection | null {
  const p = (port: number) => sport === port || dport === port;
  const n = b.length;
  if (!n) return null;
  const hit = (name: string, evidence: string, length?: number): ProtocolDetection => ({ name, evidence, length });
  // Text protocols require a complete, valid start line; arbitrary continuation bytes stay transport-only.
  const head = text(b);
  if (transport === 'TCP' && head.startsWith('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')) return hit('HTTP/2', 'HTTP/2 cleartext connection preface', 24);
  if (/^(?:(?:GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP\/1\.[01]|HTTP\/1\.[01] [1-5]\d{2}[^\r\n]*)\r\n/.test(head)) return hit('HTTP', 'HTTP/1 request or status line');
  if (/^(?:[A-Z]+ sips?:\S+ SIP\/2\.0|SIP\/2\.0 [1-6]\d{2}[^\r\n]*)\r\n/.test(head)) return hit('SIP', 'SIP/2.0 start line');
  if (transport === 'TCP') {
    if (n >= 5 && b[0] >= 20 && b[0] <= 24 && b[1] === 3 && b[2] <= 3 && u16(b, 3) > 0 && u16(b, 3) <= 18432) return hit('TLS', 'TLS record content type, version and bounded length', 5);
    if (/^SSH-(?:2\.0|1\.99)-[^\r\n]{1,200}\r?\n/.test(head)) return hit('SSH', 'SSH identification banner');
    if (n >= 14 && u16(b, 0) <= n - 2 && isDnsMessage(b.subarray(2, 2 + u16(b, 0)))) return hit('DNS (TCP)', 'Length-prefixed DNS message', u16(b, 0) + 2);
    if (n >= 20 && b[0] === 1 && u24(b, 1) >= 20 && u24(b, 1) <= n && u24(b, 5) > 0 && (b[4] & 0x0f) === 0) return hit('Diameter', 'Diameter version, message length and command header', u24(b, 1));
    if (n >= 12 && u32(b, 0) === n && u32(b, 4) === 196608) {
      const tail = text(b.subarray(8));
      const parts = tail.split('\0');
      if (tail.endsWith('\0\0') && parts.includes('user') && parts.length >= 4) return hit('PostgreSQL', 'PostgreSQL v3 startup header and user parameter', n);
    }
    if (n === 8 && u32(b, 0) === 8 && [80877103, 80877104].includes(u32(b, 4))) return hit('PostgreSQL', 'PostgreSQL SSL/GSS negotiation request', 8);
    if (n >= 20 && b[3] === 0 && b[4] === 10) {
      const len = b[0] + b[1] * 256 + b[2] * 65536;
      const end = b.indexOf(0, 5);
      if (len + 4 === n && end > 5 && end + 16 <= n && /^\d+\.\d+[^\0]*\0/.test(text(b.subarray(5)))) return hit('MySQL', 'MySQL protocol-10 server greeting and packet length', n);
    }
    // RESP requests require a complete array of bulk strings; a lone +OK is ambiguous.
    if (/^\*[1-9]\d{0,2}\r\n/.test(head) && n <= 2048 && b.every((byte) => byte < 128)) {
      let cur = head.indexOf('\r\n') + 2;
      const count = Number(head.slice(1, cur - 2));
      let valid = true;
      for (let i = 0; i < count; i++) {
        const end = head.indexOf('\r\n', cur);
        if (b[cur] !== 36 || end < 0 || !/^\d+$/.test(head.slice(cur + 1, end))) { valid = false; break; }
        const size = Number(head.slice(cur + 1, end));
        cur = end + 2 + size;
        if (cur + 2 > n || b[cur] !== 13 || b[cur + 1] !== 10) { valid = false; break; }
        cur += 2;
      }
      if (valid && cur === n) return hit('Redis', 'Complete RESP array of bulk strings', n);
    }
    if (p(1883) || (b[0] === 0x10 && head.includes('MQTT'))) {
      let cur = 1, remaining = 0, mult = 1;
      while (cur < Math.min(n, 5)) {
        const value = b[cur++]; remaining += (value & 127) * mult; mult *= 128;
        if (!(value & 128)) {
          const type = b[0] >> 4;
          const flags = b[0] & 15;
          const validFlags = type === 3 ? (flags & 6) !== 6 : flags === ([6, 8, 10].includes(type) ? 2 : 0);
          if (type >= 1 && type <= 14 && validFlags && cur + remaining === n && (type !== 1 || (remaining >= 10 && u16(b, cur) === 4 && text(b.subarray(cur + 2, cur + 6)) === 'MQTT'))) return hit('MQTT', 'MQTT control flags and complete remaining-length envelope', n);
          break;
        }
      }
    }
    if (p(502) && n >= 8 && u16(b, 2) === 0 && u16(b, 4) >= 2 && u16(b, 4) + 6 <= n && (b[7] & 127) >= 1 && (b[7] & 127) <= 43) return hit('Modbus/TCP', 'Modbus MBAP header and function code');
    for (const [port, name, pattern] of [[21, 'FTP', /^(?:[1-5]\d\d[ -]|USER |PASS |RETR |STOR |QUIT\r\n)/], [25, 'SMTP', /^(?:[2-5]\d\d[ -]|EHLO |HELO |MAIL FROM:|RCPT TO:)/], [587, 'SMTP', /^(?:[2-5]\d\d[ -]|EHLO |HELO |MAIL FROM:|RCPT TO:)/], [110, 'POP3', /^(?:\+OK|-ERR|USER |PASS |STAT\r\n)/], [143, 'IMAP', /^(?:\* (?:OK|PREAUTH|BYE)|[A-Za-z0-9]+ (?:LOGIN|SELECT|FETCH|CAPABILITY) )/]] as const) {
      if (p(port) && pattern.test(head) && head.includes('\r\n')) return hit(name, 'Validated text command/response with service-port context');
    }
    return null;
  }
  if (isDnsMessage(b)) return hit(p(5353) ? 'mDNS' : p(5355) ? 'LLMNR' : 'DNS', 'Structurally valid DNS header, names and record lengths', n);
  if (isDhcpMessage(b)) return hit('DHCP', 'BOOTP header, DHCP cookie and complete message-type option envelope');
  if ((p(546) || p(547)) && isDhcpv6Message(b)) return hit('DHCPv6', 'DHCPv6 header and bounded options/relay envelope with service-port context');
  if (p(123) && n >= 48 && (b[0] >> 3 & 7) >= 1 && (b[0] >> 3 & 7) <= 4 && (b[0] & 7) >= 1 && (b[0] & 7) <= 5) return hit('NTP', 'NTP version/mode and complete base header');
  if ((p(161) || p(162)) && n >= 8 && b[0] === 0x30 && b[2] === 2 && b[3] === 1 && [0, 1, 3].includes(b[4]) && b[1] + 2 === n) return hit('SNMP', 'BER sequence and SNMP version envelope');
  if ([1812, 1813, 1645].some(p) && n >= 20 && [1, 2, 3, 4, 5, 11, 12, 13].includes(b[0]) && u16(b, 2) === n) return hit('RADIUS', 'RADIUS code and datagram length');
  if (p(5683) && n >= 4 && b[0] >> 6 === 1 && (b[0] & 15) <= 8 && n >= 4 + (b[0] & 15) && (b[1] >> 5) <= 5) return hit('CoAP', 'CoAP version, token length and code');
  if (n >= 8 && b[0] >> 5 === 2 && (b[0] & 7) === 0 && b[1] > 0 && u16(b, 2) + 4 === n && n >= (b[0] & 8 ? 12 : 8)) return hit('GTPv2-C', 'GTPv2 header version, flags and message length', n);
  if (n >= 8 && b[0] >> 5 === 1 && (b[0] & 0x10) && !(b[0] & 8) && [1, 2, 26, 31, 254, 255].includes(b[1]) && u16(b, 2) + 8 === n && (!((b[0] & 7)) || n >= 12)) return hit('GTPv1-U', 'GTPv1-U flags, message type and length', n);
  if (isPfcpMessage(b, p(8805))) return hit('PFCP', 'PFCP header and bounded information elements; service-port or Node ID/Recovery Time Stamp corroboration', n);
  if (p(4789) && n >= 22 && b[0] === 8 && b[1] === 0 && b[2] === 0 && b[3] === 0 && b[7] === 0) return hit('VXLAN', 'VXLAN I-bit and reserved fields');
  if (p(6081) && n >= 22 && b[0] >> 6 === 0 && u16(b, 2) === 0x6558 && 8 + (b[0] & 63) * 4 + 14 <= n) return hit('GENEVE', 'GENEVE version, option length and Ethernet protocol');
  // RTP's version bits alone are weak; retain port context and validate variable header size.
  if (sport >= 16384 && dport >= 16384 && isRtcpMessage(b)) return hit('RTCP', 'Complete RTCP block lengths, type-specific header sizes and padding with media-port context', n);
  if (sport >= 16384 && dport >= 16384 && n >= 12 && b[0] >> 6 === 2) {
    const header = 12 + (b[0] & 15) * 4;
    let end = header;
    if (b[0] & 16) {
      if (header + 4 > n) return null;
      end += 4 + u16(b, header + 2) * 4;
    }
    if (end <= n && (!(b[0] & 32) || (b[n - 1] > 0 && b[n - 1] <= n - end))) {
      if ((b[1] & 127) < 64 || (b[1] & 127) > 95) return hit('RTP', 'RTP version and variable-header bounds with media-port context');
    }
  }
  return null;
}