import { linkTypeName } from './linkTypes';

/**
 * Build a JSON-serialisable export of the decoded packet summaries.
 * Only values that were actually decoded from captured bytes are emitted;
 * absent values are simply omitted rather than filled in.
 */
export interface PacketExportOptions {
  filename?: string;
  size?: number;
  summary?: Record<string, unknown>;
}

export const buildPacketExport = (packets: any[], options: PacketExportOptions = {}) => {
  const list = Array.isArray(packets) ? packets : [];

  const exportedPackets = list.map((packet, index) => {
    const layers = Array.isArray(packet?.decodedLayers) ? packet.decodedLayers : [];

    const entry: Record<string, unknown> = {
      number: packet?.number ?? index + 1,
      timestamp: packet?.time ?? null,
      relativeTime: packet?.relativeTime ?? null,
      source: packet?.source ?? null,
      destination: packet?.destination ?? null,
      protocol: packet?.protocol ?? null,
      length: packet?.length ?? null,
      info: packet?.info ?? null,
      truncated: Boolean(packet?.truncated),
      linkType:
        packet?.linkType === undefined
          ? null
          : { code: packet.linkType, name: packet.linkTypeName || linkTypeName(packet.linkType) },
      protocolStack: Array.isArray(packet?.protocolStack) ? packet.protocolStack : packet?.layers ?? [],
      decodedLayers: layers.map((layer: any) => ({
        name: layer?.name,
        byteOffset: layer?.offset ?? null,
        byteLength: layer?.length ?? null,
        fields: layer?.fields ?? {},
      })),
    };

    return entry;
  });

  const linkTypes = Array.from(
    new Set(
      list
        .map((p) => (p?.linkType === undefined || p?.linkType === null ? null : Number(p.linkType)))
        .filter((v): v is number => v !== null)
    )
  ).map((code) => ({ code, name: linkTypeName(code) }));

  return {
    format: 'pcap-decoded-summary',
    version: 1,
    generatedAt: new Date().toISOString(),
    capture: {
      filename: options.filename ?? null,
      sizeBytes: options.size ?? null,
      linkTypes,
      packetCount: exportedPackets.length,
    },
    summary: options.summary ?? {},
    packets: exportedPackets,
  };
};

export const downloadPacketExport = (packets: any[], options: PacketExportOptions = {}) => {
  const payload = buildPacketExport(packets, options);
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const base = (options.filename || 'capture').replace(/\.(pcapng|pcap)$/i, '');
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${base}-decoded-summary.json`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
  return payload.packets.length;
};
