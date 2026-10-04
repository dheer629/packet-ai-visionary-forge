export type ExpertSeverity = 'error' | 'warning' | 'note';

export interface ExpertEvent {
  kind: 'retransmission' | 'out-of-order' | 'duplicate-ack' | 'zero-window' | 'reset' | 'gap';
  severity: ExpertSeverity;
  packetNumber: number;
  flowKey: string;
  summary: string;
}

export interface TcpStreamChunk {
  packetNumber: number;
  direction: 0 | 1;
  sequence: number;
  bytes: Uint8Array;
  retransmission: boolean;
  outOfOrder: boolean;
}

export interface TcpFlowAnalysis {
  key: string;
  endpoints: [string, string];
  packetNumbers: number[];
  chunks: TcpStreamChunk[];
  events: ExpertEvent[];
  bytesByDirection: [number, number];
  gaps: number;
  retransmissions: number;
  duplicateAcks: number;
  zeroWindows: number;
  resets: number;
}

interface DirectionState {
  anchor?: number;
  nextRelative?: number;
  highestRelativeEnd?: number;
  lastAck?: number;
  duplicateAckRun: number;
}

const seqDelta = (a: number, b: number) => (a - b) | 0;

const canonicalFlow = (source: string, destination: string) => {
  const endpoints = [source, destination].sort() as [string, string];
  return { key: `${endpoints[0]} ↔ ${endpoints[1]}`, endpoints };
};

const numeric = (value: unknown) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed >>> 0 : null;
};

const payloadBytes = (packet: any): Uint8Array => {
  const bytes = packet?.tcp?.payloadBytes;
  return Array.isArray(bytes) ? Uint8Array.from(bytes) : bytes instanceof Uint8Array ? bytes : new Uint8Array();
};

/** Builds TCP stream and expert evidence only from decoded packet headers and captured payload bytes. */
export function analyzeTcpFlows(packets: any[]): TcpFlowAnalysis[] {
  const flows = new Map<string, { analysis: TcpFlowAnalysis; dirs: [DirectionState, DirectionState] }>();

  for (const packet of packets) {
    if (!packet?.tcp || packet.truncated) continue;
    const source = String(packet.source || 'Unknown');
    const destination = String(packet.destination || 'Unknown');
    if (source === 'Unknown' || destination === 'Unknown') continue;
    const canonical = canonicalFlow(source, destination);
    let state = flows.get(canonical.key);
    if (!state) {
      state = {
        analysis: {
          key: canonical.key,
          endpoints: canonical.endpoints,
          packetNumbers: [], chunks: [], events: [], bytesByDirection: [0, 0],
          gaps: 0, retransmissions: 0, duplicateAcks: 0, zeroWindows: 0, resets: 0,
        },
        dirs: [{ duplicateAckRun: 0 }, { duplicateAckRun: 0 }],
      };
      flows.set(canonical.key, state);
    }

    const flow = state.analysis;
    const direction: 0 | 1 = source === flow.endpoints[0] ? 0 : 1;
    const dir = state.dirs[direction];
    const peer = state.dirs[direction === 0 ? 1 : 0];
    const packetNumber = Number(packet.number) || flow.packetNumbers.length + 1;
    const seq = numeric(packet.tcp.seq);
    const ack = numeric(packet.tcp.ack);
    const window = Number(packet.tcp.window);
    const flags = String(packet.tcp.flags || '');
    const bytes = payloadBytes(packet);
    flow.packetNumbers.push(packetNumber);

    const addEvent = (event: Omit<ExpertEvent, 'packetNumber' | 'flowKey'>) => {
      flow.events.push({ ...event, packetNumber, flowKey: flow.key });
    };

    if (flags.includes('RST')) {
      flow.resets++;
      addEvent({ kind: 'reset', severity: 'warning', summary: 'TCP reset observed' });
    }
    if (Number.isFinite(window) && window === 0 && flags.includes('ACK')) {
      flow.zeroWindows++;
      addEvent({ kind: 'zero-window', severity: 'warning', summary: 'TCP receive window is zero' });
    }

    if (flags.includes('ACK') && ack !== null && bytes.length === 0) {
      if (peer.lastAck === ack) {
        peer.duplicateAckRun++;
        if (peer.duplicateAckRun >= 3) {
          flow.duplicateAcks++;
          addEvent({ kind: 'duplicate-ack', severity: 'note', summary: `Duplicate ACK ${ack} (${peer.duplicateAckRun} repeats)` });
        }
      } else {
        peer.lastAck = ack;
        peer.duplicateAckRun = 0;
      }
    }

    if (seq === null || bytes.length === 0) continue;
    if (dir.anchor === undefined) dir.anchor = seq;
    const relative = seqDelta(seq, dir.anchor);
    const end = relative + bytes.length;
    let retransmission = false;
    let outOfOrder = false;

    if (dir.nextRelative === undefined) {
      dir.nextRelative = end;
    } else if (end <= dir.nextRelative) {
      retransmission = true;
      flow.retransmissions++;
      addEvent({ kind: 'retransmission', severity: 'warning', summary: `TCP retransmission of ${bytes.length} captured bytes` });
    } else if (relative < dir.nextRelative) {
      retransmission = true;
      flow.retransmissions++;
      addEvent({ kind: 'retransmission', severity: 'warning', summary: `TCP partial-overlap retransmission (${dir.nextRelative - relative} bytes overlap)` });
      dir.nextRelative = end;
    } else if (relative > dir.nextRelative) {
      outOfOrder = true;
      flow.gaps++;
      addEvent({ kind: 'gap', severity: 'warning', summary: `TCP sequence gap of ${relative - dir.nextRelative} bytes` });
      addEvent({ kind: 'out-of-order', severity: 'note', summary: 'TCP segment arrived beyond the next expected sequence' });
    } else {
      dir.nextRelative = end;
    }
    dir.highestRelativeEnd = Math.max(dir.highestRelativeEnd ?? end, end);
    flow.bytesByDirection[direction] += bytes.length;
    flow.chunks.push({ packetNumber, direction, sequence: seq, bytes, retransmission, outOfOrder });
  }

  return Array.from(flows.values()).map(({ analysis }) => analysis);
}

export function streamForPacket(flows: TcpFlowAnalysis[], packetNumber: number) {
  return flows.find((flow) => flow.packetNumbers.includes(packetNumber)) ?? null;
}

export function renderStreamText(flow: TcpFlowAnalysis, direction: 'both' | 0 | 1 = 'both') {
  const decoder = new TextDecoder('utf-8', { fatal: false });
  return flow.chunks
    .filter((chunk) => !chunk.retransmission && (direction === 'both' || chunk.direction === direction))
    .sort((a, b) => a.packetNumber - b.packetNumber)
    .map((chunk) => decoder.decode(chunk.bytes).replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '·'))
    .join('');
}