import { describe, expect, it } from 'vitest';
import { decodePacketBytes } from './deepDecoder';
import { detectApplication } from './protocolDetection';
import { detectTraceProfile, captureFilterSuggestions } from '../traceProfile';

const bytes = (text: string) => new TextEncoder().encode(text);
const dns = new Uint8Array([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 97, 0, 0, 1, 0, 1]);
const gtp = new Uint8Array([0x48, 32, 0, 8, 0, 0, 0, 1, 0, 0, 1, 0]);
function packet(payload: Uint8Array, transport: 'TCP' | 'UDP' = 'TCP', port = 45678, padding = 0) {
  const header = transport === 'TCP' ? 20 : 8;
  const b = new Uint8Array(14 + 20 + header + payload.length + padding);
  const view = new DataView(b.buffer);
  view.setUint16(12, 0x0800); b[14] = 0x45;
  view.setUint16(16, 20 + header + payload.length);
  b[22] = 64; b[23] = transport === 'TCP' ? 6 : 17;
  b.set([192, 0, 2, 1, 192, 0, 2, 2], 26);
  view.setUint16(34, 50000); view.setUint16(36, port);
  if (transport === 'TCP') { b[46] = 0x50; b[47] = 0x18; }
  else view.setUint16(38, 8 + payload.length);
  b.set(payload, 34 + header);
  return b;
}
const cases: [string, Uint8Array, 'TCP' | 'UDP'][] = [
  ['HTTP', bytes('GET /example HTTP/1.1\r\nHost: example.test\r\n\r\n'), 'TCP'],
  ['SSH', bytes('SSH-2.0-OpenSSH_9.0\r\n'), 'TCP'],
  ['HTTP/2', bytes('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'), 'TCP'],
  ['Redis', bytes('*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n'), 'TCP'],
  ['TLS', new Uint8Array([23, 3, 3, 0, 3, 1, 2, 3]), 'TCP'],
  ['DNS', dns, 'UDP'], ['GTPv2-C', gtp, 'UDP'],
  ['SIP', bytes('INVITE sip:user@example.test SIP/2.0\r\nCall-ID: test-123\r\n\r\n'), 'UDP'],
  ['PostgreSQL', new Uint8Array([0, 0, 0, 8, 4, 210, 22, 47]), 'TCP'],
];

describe('byte-evidence automatic detection', () => {
  it.each(cases)('recognizes %s on a nonstandard port with evidence', (name, payload, transport) => {
    const decoded = decodePacketBytes(packet(payload, transport));
    expect(decoded.protocol).toBe(name);
    expect(decoded.layers.find((layer) => layer.name === name)?.fields['Detection evidence']).toBeTruthy();
  });
  it.each([80, 443, 22, 53, 1883, 3868, 502])('does not label random TCP bytes using port %i alone', (port) => {
    expect(decodePacketBytes(packet(new Uint8Array(32).fill(255), 'TCP', port)).protocol).toBe('TCP');
  });
  it.each([53, 2152, 2123, 8805, 123, 161, 1812, 5060, 5683])('does not label random UDP bytes using port %i alone', (port) => {
    expect(decodePacketBytes(packet(new Uint8Array(48).fill(255), 'UDP', port)).protocol).toBe('UDP');
  });
  it('retains transport for truncated signatures and continuation segments', () => {
    for (const payload of [bytes('GET / HT'), bytes('encrypted opaque body'), bytes('PRI * HTTP/2.0'), bytes('*2\r\n$3\r\nGET\r\n')]) {
      expect(decodePacketBytes(packet(payload, 'TCP', 80)).protocol).toBe('TCP');
    }
    expect(decodePacketBytes(packet(dns.slice(0, -1), 'UDP', 53)).protocol).toBe('UDP');
  });
  it('does not infer HTTP/2 or gRPC from encrypted TLS application data', () => {
    const decoded = decodePacketBytes(packet(new Uint8Array([23, 3, 3, 0, 4, 99, 98, 97, 96]), 'TCP', 443));
    expect(decoded.protocol).toBe('TLS');
    expect(decoded.stack).not.toContain('HTTP/2');
    expect(decoded.stack).not.toContain('gRPC');
  });
  it('validates TLS lengths and DNS record bounds', () => {
    expect(detectApplication(new Uint8Array([22, 3, 3, 255, 255]), 'TCP', 443, 50000)).toBeNull();
    const invalid = dns.slice(); invalid[12] = 63;
    expect(detectApplication(invalid, 'UDP', 53, 50000)).toBeNull();
  });
  it('ignores Ethernet padding outside the declared IP/UDP lengths', () => {
    const b = packet(new Uint8Array(), 'UDP', 53, dns.length);
    b.set(dns, 42);
    expect(decodePacketBytes(b).protocol).toBe('UDP');
  });
  it('defers application detection for IP fragments', () => {
    const b = packet(dns, 'UDP', 53); b[20] = 0x20;
    expect(decodePacketBytes(b).stack).not.toContain('DNS');
  });
  it('decodes real HTTP fields rather than calling it continuation data', () => {
    const decoded = decodePacketBytes(packet(cases[0][1]));
    expect(decoded.layers.at(-1)?.fields).toMatchObject({ Method: 'GET', URI: '/example', Host: 'example.test' });
  });
  it('recognizes a complete MySQL greeting but rejects a length mismatch', () => {
    const payload = new Uint8Array(34);
    payload[0] = 30; payload[4] = 10;
    payload.set(bytes('8.0.36\0'), 5);
    expect(decodePacketBytes(packet(payload)).protocol).toBe('MySQL');
    payload[0] = 31;
    expect(decodePacketBytes(packet(payload, 'TCP', 3306)).protocol).toBe('TCP');
  });
  it('recognizes MQTT CONNECT without port reliance and rejects invalid flags', () => {
    const payload = new Uint8Array([0x10, 12, 0, 4, 77, 81, 84, 84, 4, 2, 0, 60, 0, 0]);
    expect(decodePacketBytes(packet(payload)).protocol).toBe('MQTT');
    payload[0] = 0x11;
    expect(decodePacketBytes(packet(payload, 'TCP', 1883)).protocol).toBe('TCP');
  });
  it('preserves signature-only HTTP/2 and database coverage as partial', () => {
    const decoded = decodePacketBytes(packet(cases[2][1]));
    expect(decoded.layers.at(-1)?.fields['Decode scope']).toContain('Partial');
    expect(decoded.layers.at(-1)?.fieldOffsets?.Preface).toEqual([54, 24]);
  });
  it('ranks capture profiles by observed frame counts instead of first matched family', () => {
    const packets = [gtp, dns, dns, dns].map((payload) => { const d = decodePacketBytes(packet(payload, 'UDP')); return { protocol: d.protocol, protocolStack: d.stack, info: d.info }; });
    expect(detectTraceProfile(packets)?.name).toBe('Name resolution (DNS)');
    expect(captureFilterSuggestions(packets).find((f) => f.id === 'gtp-control')?.count).toBe(1);
  });
  it('does not imply telecom procedures from SCTP alone', () => {
    expect(detectTraceProfile([{ protocol: 'SCTP', protocolStack: ['IPv4', 'SCTP'] }])?.name).not.toContain('Telecom');
  });
  it('bounds SCTP DATA detection to complete chunks and validates M3UA PPID/signature', () => {
    const frame = packet(new Uint8Array(20), 'TCP', 3868);
    frame[23] = 132; frame.fill(0, 34); const view = new DataView(frame.buffer);
    view.setUint16(34, 3868); view.setUint16(36, 3868);
    frame[46] = 0; frame[47] = 3; view.setUint16(48, 24); view.setUint32(58, 3);
    frame.set([1, 0, 1, 1, 0, 0, 0, 8], 62);
    expect(decodePacketBytes(frame).protocol).toBe('M3UA');
    frame[62] = 255;
    expect(decodePacketBytes(frame).protocol).toBe('SCTP');
  });
});