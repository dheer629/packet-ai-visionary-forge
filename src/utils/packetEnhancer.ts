
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
      
      // Comprehensive protocol decoding
      if (packet._source?.layers) {
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
