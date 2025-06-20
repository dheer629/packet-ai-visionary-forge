import { 
  decodeTCPLayer, 
  decodeUDPLayer, 
  decodeICMPLayer, 
  decodeICMPv6Layer,
  decodeDNSLayer,
  decodeHTTPLayer,
  decodeTLSLayer,
  decodeDHCPLayer,
  decodeARPLayer,
  decodeSSHLayer,
  decodeFTPLayer,
  decodeSMTPLayer,
  decodePOPLayer,
  decodeIMAPLayer,
  decodeNTPLayer,
  decodeSNMPLayer
} from './protocolDecoders';

export interface ProcessedData {
  packets: any[];
  summary: any;
  protocolData?: any[];
  timeSeriesData?: any[];
  conversations?: any[];
  filename?: string;
  size?: number;
  timestamp?: number;
  aiEnriched?: boolean;
  aiProvider?: string;
  aiInsights?: string;
}

export const enhancePacketData = (analysisData: any, file: File): ProcessedData => {
  if (analysisData.packets) {
    console.log(`Processing ${analysisData.packets.length} packets with comprehensive protocol decoding`);
    
    analysisData.packets = analysisData.packets.map((packet: any, index: number) => {
      if (!packet) {
        console.warn(`Packet at index ${index} is undefined or null`);
        return createDefaultPacket(index);
      }
      
      let enhancedPacket = {
        ...packet,
        number: packet.number || index + 1,
        time: packet.time || packet.timestamp || packet.relativeTime || (index * 0.001).toFixed(6),
        relativeTime: packet.relativeTime || packet.time || (index * 0.001).toFixed(6),
      };
      
      // Enhanced protocol decoding from raw packet data
      if (packet.rawData || packet.data) {
        enhancedPacket = decodeRawPacketData(enhancedPacket, packet);
      } else if (packet._source?.layers) {
        enhancedPacket = decodeWiresharkLayers(enhancedPacket, packet._source.layers);
      } else {
        enhancedPacket = decodeBasicPacketFields(enhancedPacket, packet);
      }
      
      return enhancedPacket;
    });
    
    console.log('Enhanced packet data sample:', analysisData.packets.slice(0, 3));
  } else {
    console.warn('No packet data found in analysis result, creating default packets');
    analysisData.packets = Array.from({ length: 10 }).map((_, idx) => createDefaultPacket(idx));
  }

  analysisData = generateSummaryData(analysisData);
  
  analysisData.filename = file.name;
  analysisData.size = file.size;
  analysisData.timestamp = Date.now();
  
  console.log('Enhanced analysis data prepared successfully:', {
    summary: {
      totalPackets: analysisData.summary.totalPackets,
      ipAddresses: analysisData.summary.ipAddresses,
      conversationCount: analysisData.summary.conversationCount,
      protocols: Object.keys(analysisData.summary.protocolCounts || {}).length
    }
  });
  
  return analysisData;
};

// New function to decode raw packet data from PCAP
const decodeRawPacketData = (enhancedPacket: any, packet: any) => {
  const rawData = packet.rawData || packet.data;
  if (!rawData || !Array.isArray(rawData)) {
    console.warn('No valid raw data found for packet', packet.number);
    return decodeBasicPacketFields(enhancedPacket, packet);
  }
  
  console.log(`Decoding raw packet ${packet.number}, data length: ${rawData.length}`);
  
  let offset = 0;
  
  // Skip link layer header (varies by link type)
  // For Ethernet (most common), it's 14 bytes
  // For Linux SLL (link type 113), it's 16 bytes
  const linkType = packet.linkType || 1; // Default to Ethernet
  
  if (linkType === 113) {
    // Linux SLL header - 16 bytes
    offset = 16;
  } else {
    // Ethernet header - 14 bytes
    if (rawData.length >= 14) {
      const destMac = rawData.slice(0, 6).map(b => b.toString(16).padStart(2, '0')).join(':');
      const srcMac = rawData.slice(6, 12).map(b => b.toString(16).padStart(2, '0')).join(':');
      const etherType = (rawData[12] << 8) | rawData[13];
      
      enhancedPacket.ethernet = {
        destMac,
        srcMac,
        type: `0x${etherType.toString(16).padStart(4, '0')}`
      };
      
      offset = 14;
    }
  }
  
  // Check if we have enough data for IP header
  if (rawData.length <= offset + 20) {
    console.warn(`Packet ${packet.number} too short for IP header`);
    return decodeBasicPacketFields(enhancedPacket, packet);
  }
  
  // Parse IP header
  const ipVersion = (rawData[offset] >> 4) & 0x0F;
  
  if (ipVersion === 4) {
    enhancedPacket = decodeIPv4Header(enhancedPacket, rawData, offset);
  } else if (ipVersion === 6) {
    enhancedPacket = decodeIPv6Header(enhancedPacket, rawData, offset);
  } else {
    console.warn(`Unknown IP version ${ipVersion} in packet ${packet.number}`);
    return decodeBasicPacketFields(enhancedPacket, packet);
  }
  
  return enhancedPacket;
};

// Decode IPv4 header
const decodeIPv4Header = (enhancedPacket: any, rawData: number[], offset: number) => {
  const headerLength = (rawData[offset] & 0x0F) * 4;
  const protocol = rawData[offset + 9];
  const sourceIP = rawData.slice(offset + 12, offset + 16).join('.');
  const destIP = rawData.slice(offset + 16, offset + 20).join('.');
  
  enhancedPacket.source = sourceIP;
  enhancedPacket.destination = destIP;
  enhancedPacket.ip = {
    version: '4',
    headerLength: headerLength.toString(),
    ttl: rawData[offset + 8].toString(),
    protocol: protocol.toString(),
    source: sourceIP,
    destination: destIP
  };
  
  // Parse transport layer
  const transportOffset = offset + headerLength;
  
  switch (protocol) {
    case 6: // TCP
      enhancedPacket = decodeTCPFromRaw(enhancedPacket, rawData, transportOffset);
      break;
    case 17: // UDP
      enhancedPacket = decodeUDPFromRaw(enhancedPacket, rawData, transportOffset);
      break;
    case 1: // ICMP
      enhancedPacket = decodeICMPFromRaw(enhancedPacket, rawData, transportOffset);
      break;
    default:
      enhancedPacket.protocol = `IP Protocol ${protocol}`;
      enhancedPacket.info = `IP packet with protocol ${protocol}`;
  }
  
  return enhancedPacket;
};

// Decode IPv6 header
const decodeIPv6Header = (enhancedPacket: any, rawData: number[], offset: number) => {
  const nextHeader = rawData[offset + 6];
  
  // IPv6 addresses are 16 bytes each
  const sourceIP = [];
  const destIP = [];
  
  for (let i = 0; i < 16; i += 2) {
    sourceIP.push(((rawData[offset + 8 + i] << 8) | rawData[offset + 8 + i + 1]).toString(16));
    destIP.push(((rawData[offset + 24 + i] << 8) | rawData[offset + 24 + i + 1]).toString(16));
  }
  
  const sourceIPStr = sourceIP.join(':');
  const destIPStr = destIP.join(':');
  
  enhancedPacket.source = sourceIPStr;
  enhancedPacket.destination = destIPStr;
  enhancedPacket.protocol = 'IPv6';
  enhancedPacket.ipv6 = {
    version: '6',
    nextHeader: nextHeader.toString(),
    source: sourceIPStr,
    destination: destIPStr
  };
  
  // Parse next header (transport layer)
  const transportOffset = offset + 40; // IPv6 header is fixed 40 bytes
  
  switch (nextHeader) {
    case 6: // TCP
      enhancedPacket = decodeTCPFromRaw(enhancedPacket, rawData, transportOffset);
      break;
    case 17: // UDP
      enhancedPacket = decodeUDPFromRaw(enhancedPacket, rawData, transportOffset);
      break;
    case 58: // ICMPv6
      enhancedPacket = decodeICMPv6FromRaw(enhancedPacket, rawData, transportOffset);
      break;
    default:
      enhancedPacket.info = `IPv6 packet with next header ${nextHeader}`;
  }
  
  return enhancedPacket;
};

// Decode TCP from raw data
const decodeTCPFromRaw = (enhancedPacket: any, rawData: number[], offset: number) => {
  if (rawData.length < offset + 20) return enhancedPacket;
  
  const srcPort = (rawData[offset] << 8) | rawData[offset + 1];
  const dstPort = (rawData[offset + 2] << 8) | rawData[offset + 3];
  const seqNum = (rawData[offset + 4] << 24) | (rawData[offset + 5] << 16) | (rawData[offset + 6] << 8) | rawData[offset + 7];
  const ackNum = (rawData[offset + 8] << 24) | (rawData[offset + 9] << 16) | (rawData[offset + 10] << 8) | rawData[offset + 11];
  const flags = rawData[offset + 13];
  const windowSize = (rawData[offset + 14] << 8) | rawData[offset + 15];
  
  enhancedPacket.source = `${enhancedPacket.source}:${srcPort}`;
  enhancedPacket.destination = `${enhancedPacket.destination}:${dstPort}`;
  enhancedPacket.protocol = 'TCP';
  
  const flagNames = [];
  if (flags & 0x02) flagNames.push('SYN');
  if (flags & 0x10) flagNames.push('ACK');
  if (flags & 0x08) flagNames.push('PSH');
  if (flags & 0x01) flagNames.push('FIN');
  if (flags & 0x04) flagNames.push('RST');
  if (flags & 0x20) flagNames.push('URG');
  
  enhancedPacket.tcp = {
    srcPort: srcPort.toString(),
    dstPort: dstPort.toString(),
    seq: seqNum.toString(),
    ack: ackNum.toString(),
    flags: flagNames.join(' '),
    window: windowSize.toString()
  };
  
  enhancedPacket.info = `${flagNames.join(' ')} Seq=${seqNum} Ack=${ackNum} Win=${windowSize}`;
  
  return enhancedPacket;
};

// Decode UDP from raw data
const decodeUDPFromRaw = (enhancedPacket: any, rawData: number[], offset: number) => {
  if (rawData.length < offset + 8) return enhancedPacket;
  
  const srcPort = (rawData[offset] << 8) | rawData[offset + 1];
  const dstPort = (rawData[offset + 2] << 8) | rawData[offset + 3];
  const length = (rawData[offset + 4] << 8) | rawData[offset + 5];
  
  enhancedPacket.source = `${enhancedPacket.source}:${srcPort}`;
  enhancedPacket.destination = `${enhancedPacket.destination}:${dstPort}`;
  enhancedPacket.protocol = 'UDP';
  enhancedPacket.length = length;
  
  enhancedPacket.udp = {
    srcPort: srcPort.toString(),
    dstPort: dstPort.toString(),
    length: length.toString()
  };
  
  enhancedPacket.info = `UDP Src Port: ${srcPort}, Dst Port: ${dstPort}, Length: ${length}`;
  
  return enhancedPacket;
};

// Decode ICMP from raw data
const decodeICMPFromRaw = (enhancedPacket: any, rawData: number[], offset: number) => {
  if (rawData.length < offset + 4) return enhancedPacket;
  
  const type = rawData[offset];
  const code = rawData[offset + 1];
  
  enhancedPacket.protocol = 'ICMP';
  enhancedPacket.icmp = {
    type: type.toString(),
    code: code.toString(),
    typeName: getICMPTypeName(type.toString(), code.toString())
  };
  
  enhancedPacket.info = enhancedPacket.icmp.typeName;
  
  return enhancedPacket;
};

// Decode ICMPv6 from raw data
const decodeICMPv6FromRaw = (enhancedPacket: any, rawData: number[], offset: number) => {
  if (rawData.length < offset + 4) return enhancedPacket;
  
  const type = rawData[offset];
  const code = rawData[offset + 1];
  
  enhancedPacket.protocol = 'ICMPv6';
  enhancedPacket.icmpv6 = {
    type: type.toString(),
    code: code.toString(),
    typeName: getICMPv6TypeName(type.toString(), code.toString())
  };
  
  enhancedPacket.info = enhancedPacket.icmpv6.typeName;
  
  return enhancedPacket;
};

// Helper functions for protocol type names
const getICMPTypeName = (type: string, code: string) => {
  const typeNum = parseInt(type);
  switch (typeNum) {
    case 0: return 'Echo Reply';
    case 3: return 'Destination Unreachable';
    case 8: return 'Echo Request';
    case 11: return 'Time Exceeded';
    default: return `ICMP Type ${type}`;
  }
};

const getICMPv6TypeName = (type: string, code: string) => {
  const typeNum = parseInt(type);
  switch (typeNum) {
    case 128: return 'Echo Request';
    case 129: return 'Echo Reply';
    case 133: return 'Router Solicitation';
    case 134: return 'Router Advertisement';
    case 135: return 'Neighbor Solicitation';
    case 136: return 'Neighbor Advertisement';
    default: return `ICMPv6 Type ${type}`;
  }
};

// Comprehensive Wireshark layer decoder
const decodeWiresharkLayers = (enhancedPacket: any, layers: any) => {
  // Frame information (always available)
  if (layers.frame) {
    enhancedPacket.length = parseInt(layers.frame['frame.len'] || '0');
    enhancedPacket.frameTime = layers.frame['frame.time_relative'] || layers.frame['frame.time'];
  }

  // Ethernet layer
  if (layers.eth) {
    enhancedPacket.ethernet = {
      destMac: layers.eth['eth.dst'],
      srcMac: layers.eth['eth.src'],
      type: layers.eth['eth.type']
    };
  }

  // IP layer (IPv4)
  if (layers.ip) {
    enhancedPacket.source = layers.ip['ip.src'];
    enhancedPacket.destination = layers.ip['ip.dst'];
    enhancedPacket.ip = {
      version: layers.ip['ip.version'] || '4',
      headerLength: layers.ip['ip.hdr_len'] || '20',
      ttl: layers.ip['ip.ttl'],
      protocol: layers.ip['ip.proto'],
      source: layers.ip['ip.src'],
      destination: layers.ip['ip.dst'],
      flags: layers.ip['ip.flags'],
      fragOffset: layers.ip['ip.frag_offset']
    };
  }

  // IPv6 layer
  if (layers.ipv6) {
    enhancedPacket.source = layers.ipv6['ipv6.src'];
    enhancedPacket.destination = layers.ipv6['ipv6.dst'];
    enhancedPacket.protocol = 'IPv6';
    enhancedPacket.ipv6 = {
      version: '6',
      flowLabel: layers.ipv6['ipv6.flow'],
      hopLimit: layers.ipv6['ipv6.hlim'],
      nextHeader: layers.ipv6['ipv6.nxt'],
      source: layers.ipv6['ipv6.src'],
      destination: layers.ipv6['ipv6.dst']
    };
  }

  // TCP layer
  if (layers.tcp) {
    enhancedPacket = decodeTCPLayer(enhancedPacket, layers.tcp);
  }
  // UDP layer
  else if (layers.udp) {
    enhancedPacket = decodeUDPLayer(enhancedPacket, layers.udp);
  }
  // ICMP layer
  else if (layers.icmp) {
    enhancedPacket = decodeICMPLayer(enhancedPacket, layers.icmp);
  }
  // ICMPv6 layer
  else if (layers.icmpv6) {
    enhancedPacket = decodeICMPv6Layer(enhancedPacket, layers.icmpv6);
  }

  // Application layer protocols
  if (layers.http) {
    enhancedPacket = decodeHTTPLayer(enhancedPacket, layers.http);
  } else if (layers.https || layers.tls || layers.ssl) {
    enhancedPacket = decodeTLSLayer(enhancedPacket, layers.tls || layers.ssl);
  } else if (layers.dns) {
    enhancedPacket = decodeDNSLayer(enhancedPacket, layers.dns);
  } else if (layers.dhcp || layers.bootp) {
    enhancedPacket = decodeDHCPLayer(enhancedPacket, layers.dhcp || layers.bootp);
  } else if (layers.arp) {
    enhancedPacket = decodeARPLayer(enhancedPacket, layers.arp);
  } else if (layers.ssh) {
    enhancedPacket = decodeSSHLayer(enhancedPacket, layers.ssh);
  } else if (layers.ftp) {
    enhancedPacket = decodeFTPLayer(enhancedPacket, layers.ftp);
  } else if (layers.smtp) {
    enhancedPacket = decodeSMTPLayer(enhancedPacket, layers.smtp);
  } else if (layers.pop) {
    enhancedPacket = decodePOPLayer(enhancedPacket, layers.pop);
  } else if (layers.imap) {
    enhancedPacket = decodeIMAPLayer(enhancedPacket, layers.imap);
  } else if (layers.ntp) {
    enhancedPacket = decodeNTPLayer(enhancedPacket, layers.ntp);
  } else if (layers.snmp) {
    enhancedPacket = decodeSNMPLayer(enhancedPacket, layers.snmp);
  }

  // Set default protocol if not determined
  if (!enhancedPacket.protocol || enhancedPacket.protocol === 'Unknown') {
    if (layers.frame?.['frame.protocols']) {
      const protocols = layers.frame['frame.protocols'].split(':');
      enhancedPacket.protocol = protocols[protocols.length - 1]?.toUpperCase() || 'Unknown';
    }
  }

  // Set default info if not set
  if (!enhancedPacket.info) {
    enhancedPacket.info = `${enhancedPacket.protocol} Packet`;
  }

  return enhancedPacket;
};

// Basic packet decoder for non-Wireshark format
const decodeBasicPacketFields = (enhancedPacket: any, packet: any) => {
  enhancedPacket.source = packet.source || packet.srcIP || packet.src || packet['ip.src'] || 'Unknown';
  enhancedPacket.destination = packet.destination || packet.dstIP || packet.dst || packet['ip.dst'] || 'Unknown';
  enhancedPacket.protocol = packet.protocol || packet.type || 'Unknown';
  enhancedPacket.length = packet.length || packet.len || 0;
  enhancedPacket.info = packet.info || packet.summary || `${enhancedPacket.protocol} Packet`;
  
  return enhancedPacket;
};

const createDefaultPacket = (index: number) => {
  return {
    number: index + 1,
    time: (index * 0.001).toFixed(6),
    source: 'Unknown',
    destination: 'Unknown',
    protocol: 'Unknown',
    length: 78,
    info: 'Missing Packet Data'
  };
};

// Generate summary data from packets
const generateSummaryData = (analysisData: any): ProcessedData => {
  const uniqueIPs = new Set<string>();
  const protocolCounts: Record<string, number> = {};
  const conversations = new Set<string>();
  
  analysisData.packets.forEach((packet: any) => {
    const src = packet.source || 'Unknown';
    const dst = packet.destination || 'Unknown';
    
    if (src !== 'Unknown') uniqueIPs.add(src.split(':')[0]);
    if (dst !== 'Unknown') uniqueIPs.add(dst.split(':')[0]);
    
    const protocol = packet.protocol || 'Unknown';
    protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
    
    const pair = `${src}-${dst}`;
    const reversePair = `${dst}-${src}`;
    if (!conversations.has(pair) && !conversations.has(reversePair)) {
      conversations.add(pair);
    }
  });
  
  if (!analysisData.summary) {
    analysisData.summary = {};
  }
  
  analysisData.summary.totalPackets = analysisData.packets.length;
  analysisData.summary.ipAddresses = uniqueIPs.size;
  analysisData.summary.conversationCount = conversations.size;
  analysisData.summary.startTime = analysisData.packets[0]?.time || '0.000000';
  analysisData.summary.endTime = analysisData.packets[analysisData.packets.length - 1]?.time || '0.000000';
  
  analysisData.summary.protocolCounts = Object.entries(protocolCounts).map(([protocol, count]) => ({
    protocol,
    count
  }));
  
  analysisData.protocolData = Object.entries(protocolCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({
      name,
      value: count
    }));
  
  if (!analysisData.timeSeriesData || !analysisData.timeSeriesData.length) {
    const timeIntervals = 10;
    const startTime = parseFloat(analysisData.summary.startTime);
    const endTime = parseFloat(analysisData.summary.endTime) || startTime + 1;
    const timeRange = endTime - startTime || 1;
    const intervalSize = timeRange / timeIntervals;
    
    const timeSeriesData = Array(timeIntervals).fill(0).map((_, i) => {
      const intervalStart = startTime + (i * intervalSize);
      const intervalEnd = intervalStart + intervalSize;
      
      const packetsInInterval = analysisData.packets.filter((p: any) => {
        const packetTime = parseFloat(p.time);
        return packetTime >= intervalStart && packetTime < intervalEnd;
      }).length;
      
      return {
        time: `${i * 10}%`,
        value: packetsInInterval
      };
    });
    
    analysisData.timeSeriesData = timeSeriesData;
  }
  
  if (!analysisData.conversations || !analysisData.conversations.length) {
    const conversationMap = new Map();
    
    analysisData.packets.forEach((packet: any) => {
      const src = packet.source || 'Unknown';
      const dst = packet.destination || 'Unknown';
      const key = src < dst ? `${src}-${dst}` : `${dst}-${src}`;
      
      if (!conversationMap.has(key)) {
        conversationMap.set(key, {
          endpointA: src,
          endpointB: dst,
          packetCount: 1,
          bytes: packet.length || 0,
          duration: '0s',
          startTime: packet.time || '0',
          endTime: packet.time || '0'
        });
      } else {
        const convo = conversationMap.get(key);
        convo.packetCount++;
        convo.bytes += (packet.length || 0);
        convo.endTime = packet.time || convo.endTime;
      }
    });
    
    const conversationList = Array.from(conversationMap.values()).map(convo => {
      const duration = parseFloat(convo.endTime) - parseFloat(convo.startTime);
      return {
        ...convo,
        duration: duration.toFixed(6) + 's'
      };
    });
    
    analysisData.conversations = conversationList;
  }
  
  return analysisData;
};
