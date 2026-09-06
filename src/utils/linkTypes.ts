/** PCAP link-layer type codes (subset actually handled by the decoder). */
export const LINK_TYPE_NAMES: Record<number, string> = {
  0: 'NULL/Loopback',
  1: 'Ethernet',
  9: 'PPP',
  12: 'Raw IP',
  101: 'Raw IP (LINUX_IRDA/raw)',
  105: 'IEEE 802.11',
  108: 'OpenBSD Loopback',
  113: 'Linux cooked (SLL)',
  127: 'Radiotap',
  228: 'IPv4',
  229: 'IPv6',
  276: 'Linux cooked v2 (SLL2)',
};

export const linkTypeName = (code: number | undefined | null): string => {
  if (code === undefined || code === null || Number.isNaN(code)) return 'Unknown';
  return LINK_TYPE_NAMES[code] || `Link-type ${code}`;
};
