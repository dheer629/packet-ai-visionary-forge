import { describe, expect, it } from 'vitest';
import { isDhcpMessage, isDhcpv6Message, isPfcpMessage, isRtcpMessage } from './datagramSignatures';
import { detectApplication } from './protocolDetection';
import { decodePacketBytes } from './deepDecoder';

const pfcp = new Uint8Array([32, 1, 0, 12, 0, 0, 7, 0, 0, 96, 0, 4, 1, 2, 3, 4]);
const rr = new Uint8Array([128, 201, 0, 1, 1, 2, 3, 4]);
const relay = new Uint8Array(42);
relay[0] = 12; relay[1] = 2; relay.set([0, 9, 0, 4, 1, 0, 0, 7], 34);
function frame(payload: Uint8Array, port = 45678) {
  const b = new Uint8Array(42 + payload.length), v = new DataView(b.buffer);
  v.setUint16(12, 0x0800); b[14] = 0x45; v.setUint16(16, b.length - 14);
  b[22] = 64; b[23] = 17; v.setUint16(34, 50000); v.setUint16(36, port);
  v.setUint16(38, payload.length + 8); b.set(payload, 42); return b;
}
describe('validated datagram detection', () => {
  it('requires DHCP type evidence and walks padding correctly', () => {
    const b = new Uint8Array(246); b[0] = 1; b[1] = 1; b[2] = 6;
    b.set([99, 130, 83, 99, 0, 0, 53, 1, 1, 255], 236);
    expect(isDhcpMessage(b)).toBe(true);
    expect(decodePacketBytes(frame(b)).layers.at(-1)?.fields['Message type']).toBe('Discover');
    expect(isDhcpMessage(b.slice(0, 245))).toBe(false);
    b[243] = 2; expect(isDhcpMessage(b)).toBe(false);
  });
  it('validates DHCPv6 relay messages without inventing a transaction ID', () => {
    expect(isDhcpv6Message(relay)).toBe(true);
    const decoded = decodePacketBytes(frame(relay, 547));
    expect(decoded.protocol).toBe('DHCPv6');
    expect(decoded.layers.at(-1)?.fields).toMatchObject({ 'Message type': 'RELAY-FORW', 'Hop count': 2 });
    expect(decoded.layers.at(-1)?.fields).not.toHaveProperty('Transaction ID');
    expect(isDhcpv6Message(relay.slice(0, -1))).toBe(false);
    expect(isDhcpv6Message(new Uint8Array([1, 0, 0, 7, 0, 1, 0, 8]))).toBe(false);
  });
  it('recognizes nonstandard-port PFCP using Recovery Time Stamp evidence', () => {
    expect(detectApplication(pfcp, 'UDP', 50000, 45678)?.name).toBe('PFCP');
    expect(decodePacketBytes(frame(pfcp)).layers.at(-1)?.fields['Sequence number']).toBe(7);
    const bare = pfcp.slice(0, 8); bare[3] = 4;
    expect(isPfcpMessage(bare, false)).toBe(false);
    expect(isPfcpMessage(bare, true)).toBe(true);
  });
  it('rejects malformed PFCP IEs even on the service port', () => {
    const b = pfcp.slice(); b[11] = 5;
    expect(decodePacketBytes(frame(b, 8805)).protocol).toBe('UDP');
    b[11] = 4; b[7] = 1; expect(isPfcpMessage(b, true)).toBe(false);
  });
  it('decodes an eight-byte RTCP receiver report and exact SSRC offsets', () => {
    expect(isRtcpMessage(rr)).toBe(true);
    const layer = decodePacketBytes(frame(rr)).layers.at(-1);
    expect(layer?.name).toBe('RTCP');
    expect(layer?.fields).toMatchObject({ SSRC: '0x01020304', 'Block length': 8 });
    expect(layer?.fieldOffsets?.SSRC).toEqual([46, 4]);
  });
  it('validates every compound RTCP block rather than just the first', () => {
    const b = new Uint8Array([...rr, ...rr]); expect(isRtcpMessage(b)).toBe(true);
    b[10] = 255; expect(isRtcpMessage(b)).toBe(false);
    expect(decodePacketBytes(frame(b)).protocol).toBe('UDP');
  });
  it('rejects incomplete RTCP sender reports and claimed receiver report entries', () => {
    const b = rr.slice(); b[1] = 200; expect(isRtcpMessage(b)).toBe(false);
    b[1] = 201; b[0] = 129; expect(isRtcpMessage(b)).toBe(false);
    expect(decodePacketBytes(frame(b)).protocol).toBe('UDP');
  });
  it('accepts feedback control packets without treating feedback flags as RTP CSRCs', () => {
    const feedback = new Uint8Array([143, 206, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]);
    expect(decodePacketBytes(frame(feedback)).protocol).toBe('RTCP');
    expect(detectApplication(feedback, 'UDP', 4000, 4002)).toBeNull();
  });
});