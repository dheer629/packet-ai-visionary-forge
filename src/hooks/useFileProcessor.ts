import { useState } from 'react';
import { processPcapFile } from '../utils/pcapProcessor';
import { getProviderSettings, callAIModel } from '../services/aiService';
import { useToast } from '@/components/ui/use-toast';

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

export const useFileProcessor = (onFileUpload: (data: ProcessedData) => void) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [dataFormat, setDataFormat] = useState<string | null>(null);
  const [aiEnrichment, setAiEnrichment] = useState<boolean>(false);

  const processFile = async (file: File) => {
    if (!file) return;

    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
      toast({
        title: "Invalid File",
        description: "Please upload a valid PCAP or PCAPNG file",
        variant: "destructive"
      });
      return;
    }

    setFileName(file.name);
    setIsUploading(true);
    setProcessingProgress(0);
    setDataFormat(file.name.endsWith('.pcapng') ? 'PCAPNG' : 'PCAP');
    
    try {
      console.log(`Processing file: ${file.name}, size: ${file.size} bytes`);
      
      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };
      
      let analysisData = await processPcapFile(file, progressCallback);
      
      console.log('PCAP processing complete. First few packets:', 
        analysisData?.packets?.slice(0, 3).map((p: any) => ({
          number: p.number,
          time: p.time,
          source: p.source,
          destination: p.destination,
          protocol: p.protocol
        }))
      );
      console.log('Total packet count:', analysisData?.packets?.length || 0);
      
      if (!analysisData) {
        console.warn('No analysis data returned from processor');
        analysisData = { packets: [], summary: {} };
      }
      
      const enhancedData = enhancePacketData(analysisData, file);
      const aiEnhancedData = await applyAIEnhancement(enhancedData);

      onFileUpload(aiEnhancedData);
      
      toast({
        title: "Analysis Complete",
        description: `Successfully processed ${file.name} (${aiEnhancedData.summary.totalPackets} packets)`,
      });
    } catch (error) {
      console.error('Error processing PCAP file:', error);
      toast({
        title: "Processing Error",
        description: `Failed to process the PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
      
      const fallbackData = createFallbackData(file);
      onFileUpload(fallbackData);
    } finally {
      setIsUploading(false);
    }
  };

  // Enhanced packet data processing with comprehensive protocol support
  const enhancePacketData = (analysisData: any, file: File): ProcessedData => {
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

  // TCP decoder
  const decodeTCPLayer = (packet: any, tcp: any) => {
    const srcPort = tcp['tcp.srcport'];
    const dstPort = tcp['tcp.dstport'];
    
    if (srcPort) packet.source = `${packet.source}:${srcPort}`;
    if (dstPort) packet.destination = `${packet.destination}:${dstPort}`;
    
    packet.protocol = 'TCP';
    
    // Extract TCP flags
    const flags = [];
    if (tcp['tcp.flags_tree']) {
      const flagsTree = tcp['tcp.flags_tree'];
      if (flagsTree['tcp.flags.syn'] === '1') flags.push('SYN');
      if (flagsTree['tcp.flags.ack'] === '1') flags.push('ACK');
      if (flagsTree['tcp.flags.psh'] === '1') flags.push('PSH');
      if (flagsTree['tcp.flags.fin'] === '1') flags.push('FIN');
      if (flagsTree['tcp.flags.rst'] === '1') flags.push('RST');
      if (flagsTree['tcp.flags.urg'] === '1') flags.push('URG');
    }
    
    packet.tcp = {
      srcPort,
      dstPort,
      seq: tcp['tcp.seq'],
      ack: tcp['tcp.ack'],
      flags: flags.join(' '),
      window: tcp['tcp.window_size'],
      length: tcp['tcp.len'] || '0'
    };
    
    const seqNum = tcp['tcp.seq'] || '';
    const ackNum = tcp['tcp.ack'] || '';
    const winSize = tcp['tcp.window_size'] || '';
    const len = tcp['tcp.len'] || '';
    
    packet.info = `${flags.join(' ')} Seq=${seqNum} Ack=${ackNum} Win=${winSize} Len=${len}`;
    packet.length = parseInt(len || packet.length || '0');
    
    return packet;
  };

  // UDP decoder
  const decodeUDPLayer = (packet: any, udp: any) => {
    const srcPort = udp['udp.srcport'];
    const dstPort = udp['udp.dstport'];
    const length = udp['udp.length'];
    
    if (srcPort) packet.source = `${packet.source}:${srcPort}`;
    if (dstPort) packet.destination = `${packet.destination}:${dstPort}`;
    
    packet.protocol = 'UDP';
    packet.length = parseInt(length || '0');
    
    packet.udp = {
      srcPort,
      dstPort,
      length
    };
    
    packet.info = `Src Port: ${srcPort}, Dst Port: ${dstPort}, Length: ${length}`;
    
    return packet;
  };

  // ICMP decoder
  const decodeICMPLayer = (packet: any, icmp: any) => {
    packet.protocol = 'ICMP';
    
    const type = icmp['icmp.type'];
    const code = icmp['icmp.code'];
    
    packet.icmp = {
      type,
      code,
      typeName: getICMPTypeName(type, code)
    };
    
    packet.info = packet.icmp.typeName;
    
    return packet;
  };

  // ICMPv6 decoder
  const decodeICMPv6Layer = (packet: any, icmpv6: any) => {
    packet.protocol = 'ICMPv6';
    
    const type = icmpv6['icmpv6.type'];
    const code = icmpv6['icmpv6.code'];
    
    packet.icmpv6 = {
      type,
      code,
      typeName: getICMPv6TypeName(type, code)
    };
    
    packet.info = packet.icmpv6.typeName;
    
    return packet;
  };

  // DNS decoder
  const decodeDNSLayer = (packet: any, dns: any) => {
    packet.protocol = 'DNS';
    
    const queryName = dns['dns.qry.name'];
    const responseCode = dns['dns.resp.code'];
    const queryType = dns['dns.qry.type'];
    
    if (queryName) {
      packet.info = `Query ${queryType || 'A'}: ${queryName}`;
    } else if (responseCode !== undefined) {
      packet.info = `Response: ${getDNSResponseCodeName(responseCode)}`;
    } else {
      packet.info = 'DNS Query/Response';
    }
    
    return packet;
  };

  // HTTP decoder
  const decodeHTTPLayer = (packet: any, http: any) => {
    packet.protocol = 'HTTP';
    
    const method = http['http.request.method'];
    const uri = http['http.request.uri'];
    const responseCode = http['http.response.code'];
    const responsePhrase = http['http.response.phrase'];
    
    if (method) {
      packet.info = `${method} ${uri || '/'}`;
    } else if (responseCode) {
      packet.info = `HTTP ${responseCode} ${responsePhrase || ''}`;
    } else {
      packet.info = 'HTTP Request/Response';
    }
    
    return packet;
  };

  // TLS/SSL decoder
  const decodeTLSLayer = (packet: any, tls: any) => {
    const version = tls['tls.record.version'];
    
    if (version === '0x0303') packet.protocol = 'TLSv1.2';
    else if (version === '0x0304') packet.protocol = 'TLSv1.3';
    else if (version === '0x0301') packet.protocol = 'TLSv1';
    else packet.protocol = 'TLS';
    
    const contentType = tls['tls.record.content_type'];
    
    if (contentType === '22') packet.info = 'Handshake';
    else if (contentType === '23') packet.info = 'Application Data';
    else if (contentType === '21') packet.info = 'Alert';
    else packet.info = 'TLS Record';
    
    return packet;
  };

  // DHCP decoder
  const decodeDHCPLayer = (packet: any, dhcp: any) => {
    packet.protocol = 'DHCP';
    
    const messageType = dhcp['dhcp.option.dhcp_message_type'];
    const clientIP = dhcp['dhcp.ip.client'];
    const serverIP = dhcp['dhcp.ip.server'];
    
    if (messageType) {
      packet.info = getDHCPMessageTypeName(messageType);
      if (clientIP) packet.info += ` Client: ${clientIP}`;
      if (serverIP) packet.info += ` Server: ${serverIP}`;
    } else {
      packet.info = 'DHCP Message';
    }
    
    return packet;
  };

  // ARP decoder
  const decodeARPLayer = (packet: any, arp: any) => {
    packet.protocol = 'ARP';
    
    const opcode = arp['arp.opcode'];
    const senderIP = arp['arp.src.proto_ipv4'];
    const targetIP = arp['arp.dst.proto_ipv4'];
    const senderMac = arp['arp.src.hw_mac'];
    
    packet.arp = {
      operation: opcode === '1' ? 'Request' : 'Reply',
      senderMac,
      senderIP,
      targetMac: arp['arp.dst.hw_mac'],
      targetIP
    };
    
    if (opcode === '1') {
      packet.info = `Who has ${targetIP}? Tell ${senderIP}`;
    } else {
      packet.info = `${senderIP} is at ${senderMac}`;
    }
    
    return packet;
  };

  // SSH decoder
  const decodeSSHLayer = (packet: any, ssh: any) => {
    packet.protocol = 'SSH';
    const version = ssh['ssh.protocol'] || ssh['ssh.version'];
    packet.info = version ? `SSH ${version}` : 'SSH Protocol';
    return packet;
  };

  // FTP decoder
  const decodeFTPLayer = (packet: any, ftp: any) => {
    packet.protocol = 'FTP';
    const command = ftp['ftp.request.command'];
    const response = ftp['ftp.response.code'];
    
    if (command) {
      packet.info = `Command: ${command}`;
    } else if (response) {
      packet.info = `Response: ${response}`;
    } else {
      packet.info = 'FTP';
    }
    
    return packet;
  };

  // SMTP decoder
  const decodeSMTPLayer = (packet: any, smtp: any) => {
    packet.protocol = 'SMTP';
    const command = smtp['smtp.req.command'];
    const response = smtp['smtp.response.code'];
    
    if (command) {
      packet.info = `Command: ${command}`;
    } else if (response) {
      packet.info = `Response: ${response}`;
    } else {
      packet.info = 'SMTP';
    }
    
    return packet;
  };

  // POP decoder
  const decodePOPLayer = (packet: any, pop: any) => {
    packet.protocol = 'POP3';
    packet.info = 'POP3 Protocol';
    return packet;
  };

  // IMAP decoder
  const decodeIMAPLayer = (packet: any, imap: any) => {
    packet.protocol = 'IMAP';
    packet.info = 'IMAP Protocol';
    return packet;
  };

  // NTP decoder
  const decodeNTPLayer = (packet: any, ntp: any) => {
    packet.protocol = 'NTP';
    const mode = ntp['ntp.mode'];
    packet.info = mode ? `NTP Mode ${mode}` : 'NTP';
    return packet;
  };

  // SNMP decoder
  const decodeSNMPLayer = (packet: any, snmp: any) => {
    packet.protocol = 'SNMP';
    const version = snmp['snmp.version'];
    packet.info = version ? `SNMP v${version}` : 'SNMP';
    return packet;
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

  // Helper functions for protocol type names
  const getICMPTypeName = (type: string, code: string) => {
    const typeNum = parseInt(type);
    switch (typeNum) {
      case 0: return 'Echo Reply';
      case 3: return 'Destination Unreachable';
      case 4: return 'Source Quench';
      case 5: return 'Redirect';
      case 8: return 'Echo Request';
      case 11: return 'Time Exceeded';
      case 12: return 'Parameter Problem';
      case 13: return 'Timestamp Request';
      case 14: return 'Timestamp Reply';
      default: return `ICMP Type ${type}`;
    }
  };

  const getICMPv6TypeName = (type: string, code: string) => {
    const typeNum = parseInt(type);
    switch (typeNum) {
      case 1: return 'Destination Unreachable';
      case 2: return 'Packet Too Big';
      case 3: return 'Time Exceeded';
      case 4: return 'Parameter Problem';
      case 128: return 'Echo Request';
      case 129: return 'Echo Reply';
      case 133: return 'Router Solicitation';
      case 134: return 'Router Advertisement';
      case 135: return 'Neighbor Solicitation';
      case 136: return 'Neighbor Advertisement';
      default: return `ICMPv6 Type ${type}`;
    }
  };

  const getDNSResponseCodeName = (code: string) => {
    const codeNum = parseInt(code);
    switch (codeNum) {
      case 0: return 'No Error';
      case 1: return 'Format Error';
      case 2: return 'Server Failure';
      case 3: return 'Name Error';
      case 4: return 'Not Implemented';
      case 5: return 'Refused';
      default: return `Response Code ${code}`;
    }
  };

  const getDHCPMessageTypeName = (type: string) => {
    const typeNum = parseInt(type);
    switch (typeNum) {
      case 1: return 'DHCP Discover';
      case 2: return 'DHCP Offer';
      case 3: return 'DHCP Request';
      case 4: return 'DHCP Decline';
      case 5: return 'DHCP ACK';
      case 6: return 'DHCP NAK';
      case 7: return 'DHCP Release';
      case 8: return 'DHCP Inform';
      default: return `DHCP Type ${type}`;
    }
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

  // Apply AI enhancement to the analysis data if possible
  const applyAIEnhancement = async (analysisData: ProcessedData): Promise<ProcessedData> => {
    // Check if we have API keys available for AI enhancement
    const apiKeys = JSON.parse(localStorage.getItem('nettracer-api-keys') || '[]');
    let aiProviderKey = null;
    let aiProvider = null;
    
    // Check for available AI providers in this order of preference
    const preferredProviders = ['openai', 'anthropic', 'cohere', 'groq', 'deepseek'];
    
    for (const providerId of preferredProviders) {
      const providerKey = apiKeys.find((key: any) => key.providerId === providerId && key.value);
      if (providerKey) {
        aiProviderKey = providerKey;
        aiProvider = providerId;
        break;
      }
    }
    
    // AI enhancement if keys are available
    if (aiProviderKey && aiProviderKey.value && aiProviderKey.selectedModel) {
      try {
        setAiEnrichment(true);
        toast({
          title: "AI Enhancement Started",
          description: `Using ${aiProviderKey.name} to enhance analysis`,
        });
        
        // Generate a summary of the packet capture using the selected model
        const packetSummary = `${analysisData.summary.totalPackets} packets captured between ${analysisData.summary.startTime} and ${analysisData.summary.endTime}. 
        ${analysisData.summary.protocolCounts?.map((p: any) => `${p.protocol}: ${p.count}`).join(', ') || ''}. 
        IP addresses involved: ${analysisData.summary.topIPs?.slice(0, 5).map((ip: any) => ip.address).join(', ') || ''}`;
        
        const aiResponse = await callAIModel({
          providerId: aiProvider!,
          apiKey: aiProviderKey.value,
          modelId: aiProviderKey.selectedModel,
          prompt: `Analyze this network capture summary and provide insights: ${packetSummary}. Identify any potential security concerns, unusual patterns, or notable traffic characteristics.`,
          maxTokens: 500,
          temperature: 0.3
        });
        
        if (aiResponse.error) {
          console.error('AI enrichment error:', aiResponse.error);
          toast({
            title: "AI Enhancement Failed",
            description: aiResponse.error,
            variant: "destructive"
          });
        } else {
          // Add AI insights to the analysis data
          analysisData.aiEnriched = true;
          analysisData.aiProvider = aiProviderKey.name;
          analysisData.aiInsights = aiResponse.text;
          console.log('Analysis enriched with AI from provider:', aiProviderKey.name);
          
          toast({
            title: "AI Enhancement Complete",
            description: `Analysis enhanced with ${aiProviderKey.name}`,
          });
        }
      } catch (error) {
        console.error('Error processing with AI:', error);
        toast({
          title: "AI Enhancement Failed",
          description: error instanceof Error ? error.message : 'Unknown error',
          variant: "destructive"
        });
      } finally {
        setAiEnrichment(false);
      }
    }
    
    return analysisData;
  };

  // Create fallback data in case of error
  const createFallbackData = (file: File): ProcessedData => {
    return {
      packets: Array.from({ length: 10 }).map((_, idx) => ({
        number: idx + 1,
        time: (idx * 0.001).toFixed(6),
        source: 'Unknown',
        destination: 'Unknown',
        protocol: 'Unknown',
        length: 78,
        info: 'Unknown Packet'
      })),
      summary: {
        totalPackets: 10,
        ipAddresses: 0,
        conversationCount: 0,
        startTime: '0.000000',
        endTime: '0.010000',
        protocolCounts: [{ protocol: 'Unknown', count: 10 }]
      },
      protocolData: [{ name: 'Unknown', value: 10 }],
      timeSeriesData: Array(10).fill(0).map((_, i) => ({ time: `${i * 10}%`, value: 1 })),
      conversations: [],
      filename: file.name,
      size: file.size,
      timestamp: Date.now()
    };
  };

  return {
    isUploading,
    fileName,
    processingProgress,
    dataFormat,
    aiEnrichment,
    processFile
  };
};
