import { describe, expect, it } from 'vitest';
import { analyzeTcpFlows, renderStreamText } from './tcpAnalysis';

const packet = (number: number, source: string, destination: string, seq: number, payload: number[] = [], flags = 'ACK', ack = 1, window = 4096) => ({
  number, source, destination, truncated: false,
  tcp: { seq: String(seq >>> 0), ack: String(ack >>> 0), flags, window: String(window), payloadBytes: payload },
});

describe('TCP evidence analysis', () => {
  it('reassembles captured payload and ignores retransmitted bytes in text', () => {
    const flows = analyzeTcpFlows([
      packet(1, '10.0.0.1:1000', '10.0.0.2:80', 100, [72, 105]),
      packet(2, '10.0.0.1:1000', '10.0.0.2:80', 100, [72, 105]),
      packet(3, '10.0.0.1:1000', '10.0.0.2:80', 102, [33]),
    ]);
    expect(flows[0].retransmissions).toBe(1);
    expect(renderStreamText(flows[0], 0)).toBe('Hi!');
  });

  it('handles sequence wraparound without reporting a gap', () => {
    const flow = analyzeTcpFlows([
      packet(1, 'a:1', 'b:2', 0xfffffff0, new Array(16).fill(65)),
      packet(2, 'a:1', 'b:2', 0, new Array(4).fill(66)),
    ])[0];
    expect(flow.gaps).toBe(0);
  });

  it('reports sequence gaps, duplicate ACKs, zero windows, and resets', () => {
    const packets = [
      packet(1, 'a:1', 'b:2', 10, [1, 2]),
      packet(2, 'a:1', 'b:2', 20, [3]),
      packet(3, 'b:2', 'a:1', 1, [], 'ACK', 12),
      packet(4, 'b:2', 'a:1', 1, [], 'ACK', 12),
      packet(5, 'b:2', 'a:1', 1, [], 'ACK', 12),
      packet(6, 'b:2', 'a:1', 1, [], 'ACK', 12),
      packet(7, 'b:2', 'a:1', 1, [], 'ACK', 12, 0),
      packet(8, 'a:1', 'b:2', 21, [], 'RST ACK'),
    ];
    const flow = analyzeTcpFlows(packets)[0];
    expect(flow.gaps).toBe(1);
    expect(flow.duplicateAcks).toBeGreaterThanOrEqual(1);
    expect(flow.zeroWindows).toBe(1);
    expect(flow.resets).toBe(1);
  });
});