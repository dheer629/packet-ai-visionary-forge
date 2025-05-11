/**
 * Process a PCAP file and extract network data in a browser environment
 */
export const processPcapFile = async (file: File, progressCallback?: (progress: number) => void): Promise<any> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = async (event) => {
      try {
        // Start processing - report 10% progress
        progressCallback?.(0.1);
        
        // Get the binary data from the file
        const buffer = event.target?.result as ArrayBuffer;
        if (!buffer) {
          reject(new Error('Failed to read file buffer'));
          return;
        }
        
        // Process the PCAP data
        progressCallback?.(0.3);
        const analysisData = await parseActualPcapData(file.name, buffer);
        
        // Complete processing
        progressCallback?.(1.0);
        
        resolve(analysisData);
      } catch (error) {
        console.error('Error processing PCAP file:', error);
        reject(error);
      }
    };
    
    reader.onerror = () => {
      reject(new Error('Failed to read file'));
    };
    
    // Read the file as an array buffer for binary processing
    reader.readAsArrayBuffer(file);
  });
};

/**
 * Parse actual PCAP binary data in the browser
 */
const parseActualPcapData = async (filename: string, buffer: ArrayBuffer): Promise<any> => {
  // Create a DataView to read binary data
  const dataView = new DataView(buffer);
  const fileSize = buffer.byteLength;
  
  try {
    // PCAP Global Header - first 24 bytes
    // Verify magic number (first 4 bytes) - detect endianness
    const magicNumber = dataView.getUint32(0, false);
    
    // Check and determine endianness
    // 0xa1b2c3d4 (big-endian) or 0xd4c3b2a1 (little-endian)
    const isLittleEndian = magicNumber === 0xd4c3b2a1;
    const isBigEndian = magicNumber === 0xa1b2c3d4;
    
    // Check for PCAPNG format (0x0a0d0d0a)
    const isPcapNg = magicNumber === 0x0a0d0d0a;
    
    if (!isLittleEndian && !isBigEndian && !isPcapNg) {
      console.log('Invalid PCAP magic number:', magicNumber.toString(16));
      throw new Error('Invalid PCAP file format: Magic number mismatch');
    }
    
    console.log(`Processing ${isPcapNg ? 'PCAPNG' : 'PCAP'} file: ${filename}, size: ${fileSize} bytes, endianness: ${isLittleEndian ? 'little' : (isBigEndian ? 'big' : 'N/A')}`);
    
    if (isPcapNg) {
      return parsePcapNgFormat(dataView, fileSize, filename);
    }
    
    // Parse standard PCAP format
    const versionMajor = dataView.getUint16(4, isLittleEndian);
    const versionMinor = dataView.getUint16(6, isLittleEndian);
    const timezone = dataView.getInt32(8, isLittleEndian); // GMT to local correction
    const sigfigs = dataView.getUint32(12, isLittleEndian); // accuracy of timestamps
    const snaplen = dataView.getUint32(16, isLittleEndian); // max length of captured packets
    const network = dataView.getUint32(20, isLittleEndian); // data link type
    
    console.log(`PCAP version: ${versionMajor}.${versionMinor}, network type: ${network}, snaplen: ${snaplen}`);
    
    // Packet parsing starts at byte 24
    const packets = [];
    let offset = 24;
    let packetCount = 0;
    const ipAddresses = new Set();
    const protocolCounts: Record<string, number> = {};
    const conversations = new Map();
    const packetSizes: number[] = [];
    let minTimestamp = Number.MAX_VALUE;
    let maxTimestamp = 0;
    
    // Debug the first few bytes to understand the format
    const firstPacketData = new Uint8Array(buffer.slice(offset, offset + 48));
    console.log('First packet header and data (hex):', Array.from(firstPacketData).map(b => b.toString(16).padStart(2, '0')).join(' '));
    
    // Process packets until we reach the end of the file
    while (offset + 16 <= buffer.byteLength) {
      try {
        // PCAP Packet Header - 16 bytes
        const tsSec = dataView.getUint32(offset, isLittleEndian);
        const tsUsec = dataView.getUint32(offset + 4, isLittleEndian);
        const inclLen = dataView.getUint32(offset + 8, isLittleEndian); // captured length
        const origLen = dataView.getUint32(offset + 12, isLittleEndian); // original length
        
        // Calculate timestamp in seconds
        const timestamp = tsSec + tsUsec / 1000000;
        minTimestamp = Math.min(minTimestamp, timestamp);
        maxTimestamp = Math.max(maxTimestamp, timestamp);
        
        // Move to packet data
        offset += 16;
        
        // Check if there's enough data for the packet
        if (offset + inclLen > buffer.byteLength) {
          console.warn(`Packet at offset ${offset-16} has incorrect length: ${inclLen}, remaining: ${buffer.byteLength - offset}`);
          break;
        }
        
        // Parse the packet based on the link-layer type (network)
        // Ethernet is the most common (network = 1)
        let packetDetails: any = {
          number: packetCount + 1,
          time: timestamp.toFixed(6),
          relativeTime: '0.000000',
          source: "Unknown",
          destination: "Unknown",
          protocol: "Unknown",
          length: inclLen,
          info: '',
          layers: [],
          hexDump: '',
          asciiDump: ''
        };
        
        // Create hex dump for debugging and display
        const dumpBytes = Math.min(48, inclLen);
        const packetBytes = new Uint8Array(buffer.slice(offset, offset + dumpBytes));
        packetDetails.hexDump = createHexDump(packetBytes);
        packetDetails.asciiDump = createAsciiDump(packetBytes);
        
        // Debug the first few packets extensively
        if (packetCount < 3) {
          console.log(`Packet #${packetCount + 1} at offset ${offset}, length ${inclLen}`);
          console.log(`Packet data (first ${dumpBytes} bytes):`, Array.from(packetBytes).map(b => b.toString(16).padStart(2, '0')).join(' '));
        }
        
        // For Ethernet frames
        if (network === 1 && inclLen >= 14) {
          packetDetails.layers.push("Ethernet");
          
          // Parse Ethernet header (14 bytes)
          const destMac = formatMacAddress(new Uint8Array(buffer.slice(offset, offset + 6)));
          const srcMac = formatMacAddress(new Uint8Array(buffer.slice(offset + 6, offset + 12)));
          const etherType = dataView.getUint16(offset + 12, false); // Ethernet type is always big-endian
          
          if (packetCount < 3) {
            console.log(`Packet #${packetCount + 1} Ethernet: dst=${destMac}, src=${srcMac}, type=0x${etherType.toString(16).padStart(4, '0')}`);
          }
          
          packetDetails.ethernet = {
            destMac,
            srcMac,
            type: `0x${etherType.toString(16).padStart(4, '0')}`
          };
          
          // Process based on EtherType
          // IPv4 is 0x0800
          if (etherType === 0x0800 && offset + 14 + 20 <= offset + inclLen) {
            try {
              // Parse IPv4 header
              const ipVer = (dataView.getUint8(offset + 14) >> 4) & 0xF;
              
              if (ipVer === 4) {
                packetDetails.layers.push("IPv4");
                
                const ipHeaderLength = (dataView.getUint8(offset + 14) & 0x0F) * 4;
                const protocol = dataView.getUint8(offset + 14 + 9);
                const sourceIP = formatIPv4(dataView, offset + 14 + 12);
                const destIP = formatIPv4(dataView, offset + 14 + 16);
                
                if (packetCount < 3) {
                  console.log(`Packet #${packetCount + 1} IPv4: src=${sourceIP}, dst=${destIP}, proto=${protocol}`);
                }
                
                // Add IPs to set and update packet details
                ipAddresses.add(sourceIP);
                ipAddresses.add(destIP);
                
                packetDetails.source = sourceIP;
                packetDetails.destination = destIP;
                packetDetails.ip = {
                  version: ipVer,
                  headerLength: ipHeaderLength,
                  protocol,
                  ttl: dataView.getUint8(offset + 14 + 8),
                  source: sourceIP,
                  destination: destIP
                };
                
                // Process specific protocols
                const ipHeaderEnd = offset + 14 + ipHeaderLength;
                
                // TCP
                if (protocol === 6 && ipHeaderEnd + 20 <= offset + inclLen) {
                  packetDetails.layers.push("TCP");
                  
                  const srcPort = dataView.getUint16(ipHeaderEnd, false); // Ports are in network byte order
                  const dstPort = dataView.getUint16(ipHeaderEnd + 2, false);
                  const seqNum = dataView.getUint32(ipHeaderEnd + 4, false);
                  const ackNum = dataView.getUint32(ipHeaderEnd + 8, false);
                  const dataOffset = ((dataView.getUint8(ipHeaderEnd + 12) >> 4) & 0xF) * 4;
                  const flags = dataView.getUint8(ipHeaderEnd + 13);
                  
                  // Update protocol name
                  packetDetails.protocol = "TCP";
                  protocolCounts["TCP"] = (protocolCounts["TCP"] || 0) + 1;
                  
                  // Set source and destination with ports
                  packetDetails.source = `${sourceIP}:${srcPort}`;
                  packetDetails.destination = `${destIP}:${dstPort}`;
                  
                  // Decode TCP flags
                  const flagsStr = getTcpFlags(flags);
                  
                  if (packetCount < 3) {
                    console.log(`Packet #${packetCount + 1} TCP: ${sourceIP}:${srcPort} -> ${destIP}:${dstPort}, flags=${flagsStr}`);
                  }
                  
                  // Add TCP-specific info
                  packetDetails.tcp = {
                    srcPort,
                    dstPort,
                    seq: seqNum,
                    ack: ackNum,
                    dataOffset,
                    flags: flagsStr,
                    window: dataView.getUint16(ipHeaderEnd + 14, false)
                  };
                  
                  // Check for higher-layer protocols based on well-known ports
                  if (srcPort === 80 || dstPort === 80) {
                    packetDetails.protocol = "HTTP";
                    packetDetails.layers.push("HTTP");
                    protocolCounts["HTTP"] = (protocolCounts["HTTP"] || 0) + 1;
                    packetDetails.info = `HTTP ${srcPort === 80 ? "Response" : "Request"}`;
                  } else if (srcPort === 443 || dstPort === 443) {
                    packetDetails.protocol = "HTTPS";
                    packetDetails.layers.push("TLS");
                    protocolCounts["HTTPS"] = (protocolCounts["HTTPS"] || 0) + 1;
                    packetDetails.info = `HTTPS ${srcPort === 443 ? "Response" : "Request"}`;
                  } else if (srcPort === 22 || dstPort === 22) {
                    packetDetails.protocol = "SSH";
                    packetDetails.layers.push("SSH");
                    protocolCounts["SSH"] = (protocolCounts["SSH"] || 0) + 1;
                    packetDetails.info = `SSH ${srcPort === 22 ? "Response" : "Request"}`;
                  } else if (srcPort === 21 || dstPort === 21) {
                    packetDetails.protocol = "FTP";
                    packetDetails.layers.push("FTP");
                    protocolCounts["FTP"] = (protocolCounts["FTP"] || 0) + 1;
                    packetDetails.info = `FTP ${srcPort === 21 ? "Response" : "Request"}`;
                  } else if (srcPort === 25 || dstPort === 25) {
                    packetDetails.protocol = "SMTP";
                    packetDetails.layers.push("SMTP");
                    protocolCounts["SMTP"] = (protocolCounts["SMTP"] || 0) + 1;
                    packetDetails.info = `SMTP ${srcPort === 25 ? "Response" : "Request"}`;
                  } else if (srcPort === 110 || dstPort === 110) {
                    packetDetails.protocol = "POP3";
                    packetDetails.layers.push("POP3");
                    protocolCounts["POP3"] = (protocolCounts["POP3"] || 0) + 1;
                    packetDetails.info = `POP3 ${srcPort === 110 ? "Response" : "Request"}`;
                  } else if (srcPort === 143 || dstPort === 143) {
                    packetDetails.protocol = "IMAP";
                    packetDetails.layers.push("IMAP");
                    protocolCounts["IMAP"] = (protocolCounts["IMAP"] || 0) + 1;
                    packetDetails.info = `IMAP ${srcPort === 143 ? "Response" : "Request"}`;
                  } else if (srcPort === 20 || dstPort === 20) {
                    packetDetails.protocol = "FTP-DATA";
                    packetDetails.layers.push("FTP-DATA");
                    protocolCounts["FTP-DATA"] = (protocolCounts["FTP-DATA"] || 0) + 1;
                    packetDetails.info = `FTP Data ${srcPort === 20 ? "from server" : "to server"}`;
                  } else if (srcPort === 23 || dstPort === 23) {
                    packetDetails.protocol = "TELNET";
                    packetDetails.layers.push("TELNET");
                    protocolCounts["TELNET"] = (protocolCounts["TELNET"] || 0) + 1;
                    packetDetails.info = `TELNET ${srcPort === 23 ? "Response" : "Request"}`;
                  } else {
                    packetDetails.info = `${srcPort} → ${dstPort} [${flagsStr}] Seq=${seqNum} Ack=${ackNum} Win=${packetDetails.tcp.window}`;
                  }
                  
                  // Register conversation
                  const conversationKey = sourceIP < destIP ? 
                    `${sourceIP}:${srcPort}-${destIP}:${dstPort}` : 
                    `${destIP}:${dstPort}-${sourceIP}:${srcPort}`;
                  
                  if (!conversations.has(conversationKey)) {
                    conversations.set(conversationKey, {
                      endpointA: `${sourceIP}:${srcPort}`,
                      endpointB: `${destIP}:${dstPort}`,
                      protocol: packetDetails.protocol,
                      packetCount: 1,
                      bytes: inclLen,
                      startTime: timestamp,
                      endTime: timestamp
                    });
                  } else {
                    const conv = conversations.get(conversationKey);
                    conv.packetCount++;
                    conv.bytes += inclLen;
                    conv.endTime = timestamp;
                  }
                }
                // UDP
                else if (protocol === 17 && ipHeaderEnd + 8 <= offset + inclLen) {
                  packetDetails.layers.push("UDP");
                  
                  const srcPort = dataView.getUint16(ipHeaderEnd, false);
                  const dstPort = dataView.getUint16(ipHeaderEnd + 2, false);
                  const length = dataView.getUint16(ipHeaderEnd + 4, false);
                  
                  // Update protocol name
                  packetDetails.protocol = "UDP";
                  protocolCounts["UDP"] = (protocolCounts["UDP"] || 0) + 1;
                  
                  // Set source and destination with ports
                  packetDetails.source = `${sourceIP}:${srcPort}`;
                  packetDetails.destination = `${destIP}:${dstPort}`;
                  
                  if (packetCount < 3) {
                    console.log(`Packet #${packetCount + 1} UDP: ${sourceIP}:${srcPort} -> ${destIP}:${dstPort}, length=${length}`);
                  }
                  
                  // Add UDP-specific info
                  packetDetails.udp = {
                    srcPort,
                    dstPort,
                    length
                  };
                  
                  // Check for common UDP protocols
                  if (srcPort === 53 || dstPort === 53) {
                    packetDetails.protocol = "DNS";
                    packetDetails.layers.push("DNS");
                    protocolCounts["DNS"] = (protocolCounts["DNS"] || 0) + 1;
                    packetDetails.info = `${dstPort === 53 ? "Standard query" : "Standard response"}`;
                  } else if (srcPort === 67 || srcPort === 68 || dstPort === 67 || dstPort === 68) {
                    packetDetails.protocol = "DHCP";
                    packetDetails.layers.push("DHCP");
                    protocolCounts["DHCP"] = (protocolCounts["DHCP"] || 0) + 1;
                    packetDetails.info = `DHCP ${(srcPort === 67 || dstPort === 67) ? "Server" : "Client"}`;
                  } else if (srcPort === 123 || dstPort === 123) {
                    packetDetails.protocol = "NTP";
                    packetDetails.layers.push("NTP");
                    protocolCounts["NTP"] = (protocolCounts["NTP"] || 0) + 1;
                    packetDetails.info = `NTP ${srcPort === 123 ? "Server" : "Client"}`;
                  } else if (srcPort === 161 || dstPort === 161 || srcPort === 162 || dstPort === 162) {
                    packetDetails.protocol = "SNMP";
                    packetDetails.layers.push("SNMP");
                    protocolCounts["SNMP"] = (protocolCounts["SNMP"] || 0) + 1;
                    packetDetails.info = `SNMP ${(srcPort === 161 || dstPort === 161) ? "Get/Set" : "Trap"}`;
                  } else if (srcPort === 5060 || dstPort === 5060) {
                    packetDetails.protocol = "SIP";
                    packetDetails.layers.push("SIP");
                    protocolCounts["SIP"] = (protocolCounts["SIP"] || 0) + 1;
                    packetDetails.info = `SIP ${srcPort === 5060 ? "Response" : "Request"}`;
                  } else if (srcPort === 514 || dstPort === 514) {
                    packetDetails.protocol = "Syslog";
                    packetDetails.layers.push("Syslog");
                    protocolCounts["Syslog"] = (protocolCounts["Syslog"] || 0) + 1;
                    packetDetails.info = `Syslog message`;
                  } else {
                    packetDetails.info = `${srcPort} → ${dstPort} Len=${length}`;
                  }
                  
                  // Register conversation
                  const conversationKey = sourceIP < destIP ? 
                    `${sourceIP}:${srcPort}-${destIP}:${dstPort}` : 
                    `${destIP}:${dstPort}-${sourceIP}:${srcPort}`;
                  
                  if (!conversations.has(conversationKey)) {
                    conversations.set(conversationKey, {
                      endpointA: `${sourceIP}:${srcPort}`,
                      endpointB: `${destIP}:${dstPort}`,
                      protocol: packetDetails.protocol,
                      packetCount: 1,
                      bytes: inclLen,
                      startTime: timestamp,
                      endTime: timestamp
                    });
                  } else {
                    const conv = conversations.get(conversationKey);
                    conv.packetCount++;
                    conv.bytes += inclLen;
                    conv.endTime = timestamp;
                  }
                }
                // ICMP
                else if (protocol === 1 && ipHeaderEnd + 4 <= offset + inclLen) {
                  packetDetails.layers.push("ICMP");
                  
                  const type = dataView.getUint8(ipHeaderEnd);
                  const code = dataView.getUint8(ipHeaderEnd + 1);
                  
                  // Update protocol name
                  packetDetails.protocol = "ICMP";
                  protocolCounts["ICMP"] = (protocolCounts["ICMP"] || 0) + 1;
                  
                  // Add ICMP-specific info
                  packetDetails.icmp = {
                    type,
                    code,
                    checksum: dataView.getUint16(ipHeaderEnd + 2, false),
                    typeName: getIcmpTypeName(type, code)
                  };
                  
                  packetDetails.info = getIcmpTypeName(type, code);
                  
                  if (packetCount < 3) {
                    console.log(`Packet #${packetCount + 1} ICMP: ${sourceIP} -> ${destIP}, type=${type}, code=${code}`);
                  }
                }
                // IGMP
                else if (protocol === 2 && ipHeaderEnd + 4 <= offset + inclLen) {
                  packetDetails.layers.push("IGMP");
                  packetDetails.protocol = "IGMP";
                  protocolCounts["IGMP"] = (protocolCounts["IGMP"] || 0) + 1;
                  
                  const type = dataView.getUint8(ipHeaderEnd);
                  packetDetails.info = `IGMP ${type === 0x11 ? "Membership Query" : 
                                          (type === 0x16 ? "Membership Report" : 
                                          (type === 0x17 ? "Leave Group" : `Type ${type}`))}`;
                }
                // ESP (50)
                else if (protocol === 50) {
                  packetDetails.layers.push("ESP");
                  packetDetails.protocol = "ESP";
                  protocolCounts["ESP"] = (protocolCounts["ESP"] || 0) + 1;
                  packetDetails.info = "IPsec Encapsulating Security Payload";
                }
                // AH (51)
                else if (protocol === 51) {
                  packetDetails.layers.push("AH");
                  packetDetails.protocol = "AH";
                  protocolCounts["AH"] = (protocolCounts["AH"] || 0) + 1;
                  packetDetails.info = "IPsec Authentication Header";
                }
                // GRE (47)
                else if (protocol === 47) {
                  packetDetails.layers.push("GRE");
                  packetDetails.protocol = "GRE";
                  protocolCounts["GRE"] = (protocolCounts["GRE"] || 0) + 1;
                  packetDetails.info = "Generic Routing Encapsulation";
                }
                // SCTP (132)
                else if (protocol === 132) {
                  packetDetails.layers.push("SCTP");
                  packetDetails.protocol = "SCTP";
                  protocolCounts["SCTP"] = (protocolCounts["SCTP"] || 0) + 1;
                  packetDetails.info = "Stream Control Transmission Protocol";
                }
                // Other IP protocols
                else {
                  const protocolName = getProtocolName(protocol);
                  packetDetails.protocol = protocolName;
                  protocolCounts[protocolName] = (protocolCounts[protocolName] || 0) + 1;
                  packetDetails.info = `Protocol: ${protocolName} (${protocol})`;
                }
              } 
              // IPv6
              else if (ipVer === 6) {
                packetDetails.layers.push("IPv6");
                packetDetails.protocol = "IPv6";
                protocolCounts["IPv6"] = (protocolCounts["IPv6"] || 0) + 1;
                
                // Basic IPv6 header parsing (simplified)
                const payloadLength = dataView.getUint16(offset + 14 + 4, false);
                const nextHeader = dataView.getUint8(offset + 14 + 6); // Similar to IPv4's protocol field
                const hopLimit = dataView.getUint8(offset + 14 + 7);
                
                // Source and destination addresses (16 bytes each)
                const sourceIPv6 = formatIPv6(new Uint8Array(buffer.slice(offset + 14 + 8, offset + 14 + 24)));
                const destIPv6 = formatIPv6(new Uint8Array(buffer.slice(offset + 14 + 24, offset + 14 + 40)));
                
                packetDetails.source = sourceIPv6;
                packetDetails.destination = destIPv6;
                ipAddresses.add(sourceIPv6);
                ipAddresses.add(destIPv6);
                
                packetDetails.ipv6 = {
                  payloadLength,
                  nextHeader,
                  hopLimit,
                  source: sourceIPv6,
                  destination: destIPv6
                };
                
                packetDetails.info = `IPv6 ${sourceIPv6} → ${destIPv6}`;
                
                // Handle IPv6 extension headers and upper-layer protocols (simplified)
                if (nextHeader === 6) { // TCP
                  packetDetails.protocol = "TCP";
                  packetDetails.layers.push("TCP");
                  protocolCounts["TCP"] = (protocolCounts["TCP"] || 0) + 1;
                } else if (nextHeader === 17) { // UDP
                  packetDetails.protocol = "UDP";
                  packetDetails.layers.push("UDP");
                  protocolCounts["UDP"] = (protocolCounts["UDP"] || 0) + 1;
                } else if (nextHeader === 58) { // ICMPv6
                  packetDetails.protocol = "ICMPv6";
                  packetDetails.layers.push("ICMPv6");
                  protocolCounts["ICMPv6"] = (protocolCounts["ICMPv6"] || 0) + 1;
                }
              }
            } catch (e) {
              console.warn(`Error parsing IP packet at offset ${offset}:`, e);
            }
          } 
          // ARP (0x0806)
          else if (etherType === 0x0806 && offset + 14 + 28 <= offset + inclLen) {
            packetDetails.layers.push("ARP");
            packetDetails.protocol = "ARP";
            protocolCounts["ARP"] = (protocolCounts["ARP"] || 0) + 1;
            
            const hardwareType = dataView.getUint16(offset + 14, false);
            const protocolType = dataView.getUint16(offset + 16, false);
            const hardwareSize = dataView.getUint8(offset + 18);
            const protocolSize = dataView.getUint8(offset + 19);
            const operation = dataView.getUint16(offset + 20, false);
            
            const senderMac = formatMacAddress(new Uint8Array(buffer.slice(offset + 22, offset + 22 + hardwareSize)));
            const senderIP = formatIPv4(dataView, offset + 22 + hardwareSize);
            const targetMac = formatMacAddress(new Uint8Array(buffer.slice(offset + 22 + hardwareSize + protocolSize, offset + 22 + 2*hardwareSize + protocolSize)));
            const targetIP = formatIPv4(dataView, offset + 22 + hardwareSize + protocolSize + hardwareSize);
            
            // Add IPs to set and update packet details
            ipAddresses.add(senderIP);
            ipAddresses.add(targetIP);
            
            packetDetails.source = senderIP;
            packetDetails.destination = targetIP;
            
            packetDetails.arp = {
              hardwareType,
              protocolType: `0x${protocolType.toString(16).padStart(4, '0')}`,
              operation: operation === 1 ? "Request" : "Reply",
              senderMac,
              senderIP,
              targetMac,
              targetIP
            };
            
            packetDetails.info = `${operation === 1 ? "Who has" : "Is at"} ${targetIP}? Tell ${senderIP}`;
            
            if (packetCount < 3) {
              console.log(`Packet #${packetCount + 1} ARP: ${operation === 1 ? "Request" : "Reply"}, sender=${senderIP}, target=${targetIP}`);
            }
          }
          // IPv6 (0x86DD)
          else if (etherType === 0x86DD && offset + 14 + 40 <= offset + inclLen) {
            packetDetails.layers.push("IPv6");
            packetDetails.protocol = "IPv6";
            protocolCounts["IPv6"] = (protocolCounts["IPv6"] || 0) + 1;
            
            // Parse IPv6 header (40 bytes)
            const ipv6VerClassFlow = dataView.getUint32(offset + 14, false);
            const payloadLength = dataView.getUint16(offset + 14 + 4, false);
            const nextHeader = dataView.getUint8(offset + 14 + 6);
            const hopLimit = dataView.getUint8(offset + 14 + 7);
            
            // Source and destination addresses (16 bytes each)
            const sourceIPv6 = formatIPv6(new Uint8Array(buffer.slice(offset + 14 + 8, offset + 14 + 24)));
            const destIPv6 = formatIPv6(new Uint8Array(buffer.slice(offset + 14 + 24, offset + 14 + 40)));
            
            packetDetails.source = sourceIPv6;
            packetDetails.destination = destIPv6;
            ipAddresses.add(sourceIPv6);
            ipAddresses.add(destIPv6);
            
            packetDetails.ipv6 = {
              version: (ipv6VerClassFlow >> 28) & 0xF,
              trafficClass: (ipv6VerClassFlow >> 20) & 0xFF,
              flowLabel: ipv6VerClassFlow & 0xFFFFF,
              payloadLength,
              nextHeader,
              hopLimit,
              source: sourceIPv6,
              destination: destIPv6
            };
            
            // Basic info
            packetDetails.info = `IPv6 ${sourceIPv6} → ${destIPv6}`;
            
            // Process upper-layer protocols based on Next Header field
            const ipHeaderEnd = offset + 14 + 40;
            let currentHeader = nextHeader;
            let headerOffset = ipHeaderEnd;
            let isExtensionHeader = true;
            
            // This is a simplified approach - proper IPv6 extension header handling would be more complex
            if (nextHeader === 6 && headerOffset + 20 <= offset + inclLen) { // TCP
              packetDetails.protocol = "TCP";
              packetDetails.layers.push("TCP");
              protocolCounts["TCP"] = (protocolCounts["TCP"] || 0) + 1;
              // TCP header parsing would go here (similar to IPv4)
            } else if (nextHeader === 17 && headerOffset + 8 <= offset + inclLen) { // UDP
              packetDetails.protocol = "UDP";
              packetDetails.layers.push("UDP");
              protocolCounts["UDP"] = (protocolCounts["UDP"] || 0) + 1;
              // UDP header parsing would go here (similar to IPv4)
            } else if (nextHeader === 58 && headerOffset + 4 <= offset + inclLen) { // ICMPv6
              packetDetails.protocol = "ICMPv6";
              packetDetails.layers.push("ICMPv6");
              protocolCounts["ICMPv6"] = (protocolCounts["ICMPv6"] || 0) + 1;
              
              const type = dataView.getUint8(headerOffset);
              const code = dataView.getUint8(headerOffset + 1);
              
              packetDetails.icmpv6 = {
                type,
                code,
                checksum: dataView.getUint16(headerOffset + 2, false)
              };
              
              // ICMPv6 type descriptions
              let typeName = "Unknown ICMPv6";
              if (type === 1) typeName = "Destination Unreachable";
              else if (type === 2) typeName = "Packet Too Big";
              else if (type === 3) typeName = "Time Exceeded";
              else if (type === 4) typeName = "Parameter Problem";
              else if (type === 128) typeName = "Echo Request";
              else if (type === 129) typeName = "Echo Reply";
              else if (type === 133) typeName = "Router Solicitation";
              else if (type === 134) typeName = "Router Advertisement";
              else if (type === 135) typeName = "Neighbor Solicitation";
              else if (type === 136) typeName = "Neighbor Advertisement";
              
              packetDetails.info = `ICMPv6 ${typeName}`;
            }
          }
          // 802.1Q VLAN tagged frame (0x8100)
          else if (etherType === 0x8100 && offset + 14 + 4 <= offset + inclLen) {
            const vlanInfo = dataView.getUint16(offset + 14, false);
            const vlanId = vlanInfo & 0x0FFF; // 12 bits VLAN ID
            const priority = (vlanInfo >> 13) & 0x07; // 3 bits priority
            const innerEtherType = dataView.getUint16(offset + 14 + 2, false);
            
            packetDetails.layers.push("802.1Q VLAN");
            packetDetails.vlan = {
              id: vlanId,
              priority
            };
            
            packetDetails.protocol = `VLAN (${vlanId})`;
            protocolCounts[`VLAN`] = (protocolCounts[`VLAN`] || 0) + 1;
            packetDetails.info = `VLAN ID: ${vlanId}, Priority: ${priority}, Type: 0x${innerEtherType.toString(16).padStart(4, '0')}`;
          }
          // PPPoE Discovery (0x8863) or Session (0x8864)
          else if ((etherType === 0x8863 || etherType === 0x8864) && offset + 14 + 6 <= offset + inclLen) {
            const isPPPoEDiscovery = etherType === 0x8863;
            packetDetails.layers.push(isPPPoEDiscovery ? "PPPoE Discovery" : "PPPoE Session");
            packetDetails.protocol = isPPPoEDiscovery ? "PPPoE-Discovery" : "PPPoE-Session";
            protocolCounts[packetDetails.protocol] = (protocolCounts[packetDetails.protocol] || 0) + 1;
            
            const versionType = dataView.getUint8(offset + 14);
            const code = dataView.getUint8(offset + 14 + 1);
            const sessionId = dataView.getUint16(offset + 14 + 2, false);
            const length = dataView.getUint16(offset + 14 + 4, false);
            
            packetDetails.pppoe = {
              version: (versionType >> 4) & 0x0F,
              type: versionType & 0x0F,
              code,
              sessionId,
              length
            };
            
            // PPPoE Discovery packet types
            if (isPPPoEDiscovery) {
              let codeDesc = "Unknown";
              if (code === 0x09) codeDesc = "PADI (Discovery Initiation)";
              else if (code === 0x07) codeDesc = "PADO (Discovery Offer)";
              else if (code === 0x19) codeDesc = "PADR (Discovery Request)";
              else if (code === 0x65) codeDesc = "PADS (Discovery Session-confirmation)";
              else if (code === 0xa7) codeDesc = "PADT (Discovery Terminate)";
              
              packetDetails.info = `PPPoE ${codeDesc}, Session ID: ${sessionId}`;
            } else {
              // PPPoE Session packet
              packetDetails.info = `PPPoE Session ${sessionId}, Length: ${length}`;
            }
          }
          // Other EtherTypes
          else {
            packetDetails.protocol = `EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
            protocolCounts[packetDetails.protocol] = (protocolCounts[packetDetails.protocol] || 0) + 1;
            packetDetails.info = `EtherType: 0x${etherType.toString(16).padStart(4, '0')}`;
            
            if (packetCount < 3) {
              console.log(`Packet #${packetCount + 1} Unknown EtherType: 0x${etherType.toString(16).padStart(4, '0')}`);
            }
          }
        }
        // Raw IP (network = 101)
        else if (network === 101 && inclLen >= 20) {
          const ipVer = (dataView.getUint8(offset) >> 4) & 0xF;
          if (ipVer === 4) {
            // Similar IP parsing as Ethernet, but starting directly at the IP header
            packetDetails.protocol = "IPv4 (Raw)";
            packetDetails.layers.push("IPv4");
            protocolCounts["IPv4"] = (protocolCounts["IPv4"] || 0) + 1;
            
            const ipHeaderLength = (dataView.getUint8(offset) & 0x0F) * 4;
            const totalLength = dataView.getUint16(offset + 2, true); // Assuming little-endian
            const protocol = dataView.getUint8(offset + 9);
            const sourceIP = formatIPv4(dataView, offset + 12);
            const destIP = formatIPv4(dataView, offset + 16);
            
            // Add IPs to set and update packet details
            ipAddresses.add(sourceIP);
            ipAddresses.add(destIP);
            
            packetDetails.source = sourceIP;
            packetDetails.destination = destIP;
            packetDetails.ip = {
              version: ipVer,
              headerLength: ipHeaderLength,
              protocol,
              ttl: dataView.getUint8(offset + 8),
              source: sourceIP,
              destination: destIP
            };
            
            packetDetails.info = `IPv4 ${sourceIP} → ${destIP} (${getProtocolName(protocol)})`;
          }
        } 
        // IEEE 802.11 Wireless LAN (network = 105)
        else if (network === 105) {
          packetDetails.protocol = "802.11";
          packetDetails.layers.push("802.11");
          protocolCounts["802.11"] = (protocolCounts["802.11"] || 0) + 1;
          packetDetails.info = "802.11 Wireless LAN frame";
          
          // Basic 802.11 frame control parsing
          if (inclLen >= 2) {
            const frameControl = dataView.getUint16(offset, true);
            const frameType = (frameControl >> 2) & 0x03;
            const frameSubtype = (frameControl >> 4) & 0x0F;
            
            let frameTypeDesc = "";
            if (frameType === 0) frameTypeDesc = "Management";
            else if (frameType === 1) frameTypeDesc = "Control";
            else if (frameType === 2) frameTypeDesc = "Data";
            else frameTypeDesc = "Extension";
            
            packetDetails.info = `802.11 ${frameTypeDesc} frame`;
          }
        }
        // Linux cooked capture (network = 113)
        else if (network === 113 && inclLen >= 16) {
          packetDetails.protocol = "Linux Cooked";
          packetDetails.layers.push("SLL");
          protocolCounts["Linux Cooked"] = (protocolCounts["Linux Cooked"] || 0) + 1;
          
          // Linux cooked header (16 bytes)
          const packetType = dataView.getUint16(offset, true);
          const addressType = dataView.getUint16(offset + 2, true);
          const addressLen = dataView.getUint16(offset + 4, true);
          // Source address is 8 bytes at offset + 6
          const protocol = dataView.getUint16(offset + 14, true);
          
          packetDetails.info = `Linux cooked capture, protocol type: 0x${protocol.toString(16)}`;
          
          // If it's IP after the SLL header
          if (protocol === 0x0800 && inclLen >= 16 + 20) {
            const ipOffset = offset + 16;
            const ipVer = (dataView.getUint8(ipOffset) >> 4) & 0xF;
            
            if (ipVer === 4) {
              // Parse IPv4 similar to other cases
              packetDetails.protocol = "IPv4";
              packetDetails.layers.push("IPv4");
              protocolCounts["IPv4"] = (protocolCounts["IPv4"] || 0) + 1;
              // IPv4 parsing would go here
            }
          }
        }
        // DOCSIS (network = 143)
        else if (network === 143) {
          packetDetails.protocol = "DOCSIS";
          packetDetails.layers.push("DOCSIS");
          protocolCounts["DOCSIS"] = (protocolCounts["DOCSIS"] || 0) + 1;
          packetDetails.info = "DOCSIS MAC frame";
        }
        else {
          // Unsupported link-layer type
          packetDetails.protocol = `Link-type ${network}`;
          packetDetails.info = `Unsupported link-layer type: ${network}`;
          
          if (packetCount < 3) {
            console.log(`Packet #${packetCount + 1} Unsupported network type: ${network}`);
          }
        }
        
        // Always set a relative time once we know the minimum timestamp
        if (minTimestamp !== Number.MAX_VALUE && minTimestamp <= timestamp) {
          packetDetails.relativeTime = (timestamp - minTimestamp).toFixed(6);
        }
        
        // Add packet size to statistics
        packetSizes.push(inclLen);
        
        // Store the packet (limit to 1000 for browser performance)
        if (packetCount < 10000) {
          packets.push(packetDetails);
        }
        
        // Move to next packet
        offset += inclLen;
        packetCount++;
        
        // Log progress occasionally
        if (packetCount % 1000 === 0) {
          console.log(`Processed ${packetCount} packets...`);
          progressCallback?.(0.3 + (0.7 * Math.min(packetCount / 50000, 1))); // Update progress
        }
      } catch (error) {
        console.error(`Error parsing packet at offset ${offset}:`, error);
        // Try to recover and move to the next 16-byte boundary
        offset = (Math.floor(offset / 16) + 1) * 16;
      }
    }
    
    console.log(`Finished processing ${packetCount} packets`);
    console.log(`Detected IP addresses: ${Array.from(ipAddresses).join(', ')}`);
    console.log(`Detected protocols: ${Object.keys(protocolCounts).join(', ')}`);
    console.log(`Conversation count: ${conversations.size}`);
    
    // Calculate statistics
    const avgPacketSize = packetSizes.length > 0 
      ? Math.round(packetSizes.reduce((sum, size) => sum + size, 0) / packetSizes.length) 
      : 0;
    
    // Sort packet sizes for median calculation
    packetSizes.sort((a, b) => a - b);
    const medianPacketSize = packetSizes.length > 0 
      ? packetSizes[Math.floor(packetSizes.length / 2)]
      : 0;
    
    // Convert protocol counts to array for chart
    const protocolData = Object.entries(protocolCounts).map(([name, value]) => ({
      name,
      value
    }));
    
    // Generate time series data for visualization
    const duration = maxTimestamp - minTimestamp;
    const timeSeriesData = generateTimeSeriesData(packets, duration);
    
    // Format conversations with duration
    const conversationsArray = Array.from(conversations.values()).map(conv => {
      return {
        ...conv,
        duration: `${(conv.endTime - conv.startTime).toFixed(2)} sec`
      };
    });
    
    // Get top IPs by packet count
    const ipCountMap = new Map();
    packets.forEach(packet => {
      // Extract IP without port
      const sourceIP = packet.source?.split(':')?.[0] || packet.source;
      const destIP = packet.destination?.split(':')?.[0] || packet.destination;
      
      if (sourceIP && sourceIP !== "Unknown") {
        ipCountMap.set(sourceIP, (ipCountMap.get(sourceIP) || 0) + 1);
      }
      if (destIP && destIP !== "Unknown") {
        ipCountMap.set(destIP, (ipCountMap.get(destIP) || 0) + 1);
      }
    });
    
    // Convert to array and sort
    const topIPs = Array.from(ipCountMap.entries())
      .map(([address, count]) => ({ address, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    
    return {
      filename,
      size: fileSize,
      timestamp: new Date().toISOString(),
      summary: {
        totalPackets: packetCount,
        ipAddresses: ipAddresses.size,
        conversationCount: conversations.size,
        tcpPackets: protocolCounts['TCP'] || 0,
        udpPackets: protocolCounts['UDP'] || 0,
        icmpPackets: protocolCounts['ICMP'] || 0,
        otherPackets: packetCount - ((protocolCounts['TCP'] || 0) + (protocolCounts['UDP'] || 0) + (protocolCounts['ICMP'] || 0)),
        avgPacketSize,
        medianPacketSize,
        minPacketSize: packetSizes[0] || 0,
        maxPacketSize: packetSizes[packetSizes.length - 1] || 0,
        captureDuration: formatDuration(duration),
        startTime: new Date(minTimestamp * 1000).toISOString(),
        endTime: new Date(maxTimestamp * 1000).toISOString(),
        packetsPerSecond: (packetCount / Math.max(duration, 0.001)).toFixed(1),
        topIPs,
        protocolCounts: Object.entries(protocolCounts)
          .map(([protocol, count]) => ({ protocol, count }))
          .sort((a, b) => b.count - a.count)
      },
      packets,
      protocols: Object.keys(protocolCounts),
      protocolData,
      timeSeriesData,
      ipAddresses: Array.from(ipAddresses),
      conversations: conversationsArray,
      pcapVersion: `${versionMajor}.${versionMinor}`,
      pcapInfo: {
        timezone,
        sigfigs,
        snaplen,
        network,
        isLittleEndian
      }
    };
  } catch (error) {
    console.error('Error parsing PCAP data:', error);
    throw new Error(`Failed to parse PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

/**
 * Parse PCAP-NG format files
 * This is a simplified implementation as PCAP-NG is much more complex
 */
const parsePcapNgFormat = (dataView: DataView, fileSize: number, filename: string) => {
  console.log('Detected PCAP-NG format, processing block structure');
  
  // PCAP-NG variables
  const packets: any[] = [];
  const ipAddresses = new Set<string>();
  const protocolCounts: Record<string, number> = {};
  const conversations = new Map();
  const packetSizes: number[] = [];
  let minTimestamp = Number.MAX_VALUE;
  let maxTimestamp = 0;
  let interfaceDescriptions: any[] = [];
  
  // Block Type values
  const SHB_TYPE = 0x0a0d0d0a; // Section Header Block
  const IDB_TYPE = 0x00000001; // Interface Description Block
  const EPB_TYPE = 0x00000006; // Enhanced Packet Block
  const SPB_TYPE = 0x00000003; // Simple Packet Block
  
  // Parse PCAP-NG blocks
  let offset = 0;
  let packetCount = 0;
  
  while (offset + 12 <= dataView.byteLength) {
    // Each block starts with type and length
    const blockType = dataView.getUint32(offset, true);  // Always little-endian per specification
    const blockTotalLength = dataView.getUint32(offset + 4, true);
    
    // Validate block size
    if (blockTotalLength < 12 || offset + blockTotalLength > dataView.byteLength) {
      console.warn(`Invalid block length at offset ${offset}: ${blockTotalLength}`);
      break;
    }
    
    // Process blocks based on type
    switch(blockType) {
      // Section Header Block
      case SHB_TYPE:
        if (blockTotalLength >= 28) {
          const byteOrderMagic = dataView.getUint32(offset + 8, true);
          const isLittleEndian = byteOrderMagic === 0x1a2b3c4d;
          
          if (!isLittleEndian && byteOrderMagic !== 0x4d3c2b1a) {
            console.warn(`Invalid byte-order magic in SHB: 0x${byteOrderMagic.toString(16)}`);
          }
          
          const versionMajor = dataView.getUint16(offset + 12, isLittleEndian);
          const versionMinor = dataView.getUint16(offset + 14, isLittleEndian);
          console.log(`PCAP-NG version ${versionMajor}.${versionMinor}, endianness: ${isLittleEndian ? 'little' : 'big'}`);
        }
        break;
      
      // Interface Description Block
      case IDB_TYPE:
        if (blockTotalLength >= 20) {
          const linkType = dataView.getUint16(offset + 8, true);
          const snapLen = dataView.getUint32(offset + 12, true);
          
          interfaceDescriptions.push({
            index: interfaceDescriptions.length,
            linkType,
            snapLen
          });
          
          console.log(`Interface ${interfaceDescriptions.length-1}: link-type ${linkType}, snap length ${snapLen}`);
        }
        break;
      
      // Enhanced Packet Block
      case EPB_TYPE:
        if (blockTotalLength >= 32) {
          try {
            const interfaceId = dataView.getUint32(offset + 8, true);
            const timestampHigh = dataView.getUint32(offset + 12, true);
            const timestampLow = dataView.getUint32(offset + 16, true);
            const capturedLen = dataView.getUint32(offset + 20, true);
            const packetLen = dataView.getUint32(offset + 24, true);
            
            // Calculate timestamp (EPB uses 64-bit int)
            // This is a simplification - proper handling depends on interface options
            const timestamp = timestampHigh * 4294967296 + timestampLow; // 2^32
            const timestampSec = timestamp / 1000000; // Assume microseconds
            
            // Track timestamp range
            minTimestamp = Math.min(minTimestamp, timestampSec);
            maxTimestamp = Math.max(maxTimestamp, timestampSec);
            
            // Get interface info if available
            const iface = interfaceDescriptions[interfaceId] || { linkType: 1 }; // Default to Ethernet
            
            // Parse packet based on link type (similar to parseActualPcapData)
            let packetDetails: any = {
              number: packetCount + 1,
              time: timestampSec.toFixed(6),
              relativeTime: '0.000000',
              source: "Unknown",
              destination: "Unknown",
              protocol: "Unknown",
              length: capturedLen,
              info: '',
              layers: [],
              hexDump: '',
              asciiDump: ''
            };
            
            // Extract actual packet data (starts at offset + 28, aligned to 32 bits)
            const packetDataOffset = offset + 28;
            
            // Create hex dump for debugging and display
            const dumpBytes = Math.min(48, capturedLen);
            packetDetails.hexDump = createHexDump(new Uint8Array(dataView.buffer.slice(packetDataOffset, packetDataOffset + dumpBytes)));
            packetDetails.asciiDump = createAsciiDump(new Uint8Array(dataView.buffer.slice(packetDataOffset, packetDataOffset + dumpBytes)));
            
            // Parse based on link type (only handling Ethernet for simplicity)
            if (iface.linkType === 1 && capturedLen >= 14) {
              packetDetails.layers.push("Ethernet");
              
              // Extract Ethernet header
              const destMac = formatMacAddress(new Uint8Array(dataView.buffer.slice(packetDataOffset, packetDataOffset + 6)));
              const srcMac = formatMacAddress(new Uint8Array(dataView.buffer.slice(packetDataOffset + 6, packetDataOffset + 12)));
              const etherType = dataView.getUint16(packetDataOffset + 12, false);
              
              packetDetails.ethernet = {
                destMac,
                srcMac,
                type: `0x${etherType.toString(16).padStart(4, '0')}`
              };
              
              // Further parsing for IP, etc. (similar to parseActualPcapData)
              if (etherType === 0x0800) { // IPv4
                packetDetails.protocol = "IPv4";
                packetDetails.layers.push("IPv4");
                protocolCounts["IPv4"] = (protocolCounts["IPv4"] || 0) + 1;
                
                // Parse IPv4 header if we have enough data
                if (capturedLen >= 14 + 20) {
                  const ipVer = (dataView.getUint8(packetDataOffset + 14) >> 4) & 0xF;
                  if (ipVer === 4) {
                    const ipHeaderLength = (dataView.getUint8(packetDataOffset + 14) & 0x0F) * 4;
                    const protocol = dataView.getUint8(packetDataOffset + 14 + 9);
                    const sourceIP = formatIPv4(dataView, packetDataOffset + 14 + 12);
                    const destIP = formatIPv4(dataView, packetDataOffset + 14 + 16);
                    
                    packetDetails.source = sourceIP;
                    packetDetails.destination = destIP;
                    ipAddresses.add(sourceIP);
                    ipAddresses.add(destIP);
                    
                    // Protocol identification
                    const protocolName = getProtocolName(protocol);
                    packetDetails.protocol = protocolName;
                    protocolCounts[protocolName] = (protocolCounts[protocolName] || 0) + 1;
                    
                    packetDetails.info = `${sourceIP} → ${destIP} (${protocolName})`;
                    
                    // For TCP and UDP, add port information
                    const ipHeaderEnd = packetDataOffset + 14 + ipHeaderLength;
                    
                    if (protocol === 6 && ipHeaderEnd + 8 <= packetDataOffset + capturedLen) { // TCP
                      const srcPort = dataView.getUint16(ipHeaderEnd, false);
                      const dstPort = dataView.getUint16(ipHeaderEnd + 2, false);
                      packetDetails.source = `${sourceIP}:${srcPort}`;
                      packetDetails.destination = `${destIP}:${dstPort}`;
                      packetDetails.info = `${sourceIP}:${srcPort} → ${destIP}:${dstPort} (TCP)`;
                    } else if (protocol === 17 && ipHeaderEnd + 8 <= packetDataOffset + capturedLen) { // UDP
                      const srcPort = dataView.getUint16(ipHeaderEnd, false);
                      const dstPort = dataView.getUint16(ipHeaderEnd + 2, false);
                      packetDetails.source = `${sourceIP}:${srcPort}`;
                      packetDetails.destination = `${destIP}:${dstPort}`;
                      packetDetails.info = `${sourceIP}:${srcPort} → ${destIP}:${dstPort} (UDP)`;
                    }
                  }
                }
              } else if (etherType === 0x0806) { // ARP
                packetDetails.protocol = "ARP";
                packetDetails.layers.push("ARP");
                protocolCounts["ARP"] = (protocolCounts["ARP"] || 0) + 1;
                packetDetails.info = "ARP";
              } else if (etherType === 0x86DD) { // IPv6
                packetDetails.protocol = "IPv6";
                packetDetails.layers.push("IPv6");
                protocolCounts["IPv6"] = (protocolCounts["IPv6"] || 0) + 1;
                packetDetails.info = "IPv6";
              } else {
                packetDetails.protocol = `EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
                protocolCounts[packetDetails.protocol] = (protocolCounts[packetDetails.protocol] || 0) + 1;
                packetDetails.info = `EtherType: 0x${etherType.toString(16).padStart(4, '0')}`;
              }
            } else {
              packetDetails.protocol = `Link-type ${iface.linkType}`;
              packetDetails.info = `Unsupported link-layer type: ${iface.linkType}`;
              protocolCounts[packetDetails.protocol] = (protocolCounts[packetDetails.protocol] || 0) + 1;
            }
            
            // Add packet to collection and update stats
            packetSizes.push(capturedLen);
            if (packetCount < 10000) {
              packets.push(packetDetails);
            }
            
            packetCount++;
            
            // Log progress occasionally
            if (packetCount % 1000 === 0) {
              console.log(`Processed ${packetCount} PCAP-NG packets...`);
            }
          } catch (e) {
            console.warn(`Error parsing EPB at offset ${offset}:`, e);
          }
        }
        break;
      
      // Simple Packet Block (limited info)
      case SPB_TYPE:
        if (blockTotalLength >= 16) {
          const packetLen = dataView.getUint32(offset + 8, true);
          
          // Create simple packet representation
          const packetDetails = {
            number: packetCount + 1,
            time: "0.000000",
            relativeTime: "0.000000",
            source: "Unknown",
            destination: "Unknown",
            protocol: "Unknown",
            length: packetLen,
            info: "Simple Packet (no timestamp)",
            layers: ["Raw"],
            hexDump: "",
            asciiDump: ""
          };
          
          // Add hex dump
          const dumpBytes = Math.min(48, packetLen);
          const dataOffset = offset + 12;
          packetDetails.hexDump = createHexDump(new Uint8Array(dataView.buffer.slice(dataOffset, dataOffset + dumpBytes)));
          packetDetails.asciiDump = createAsciiDump(new Uint8Array(dataView.buffer.slice(dataOffset, dataOffset + dumpBytes)));
          
          // Add packet to collection and update stats
          packetSizes.push(packetLen);
          if (packetCount < 10000) {
            packets.push(packetDetails);
          }
          
          packetCount++;
        }
        break;
      
      default:
        // Skip unknown block types
        break;
    }
    
    // Move to next block
    offset += blockTotalLength;
  }
  
  console.log(`Finished processing ${packetCount} PCAP-NG packets across ${interfaceDescriptions.length} interfaces`);
  
  // Calculate statistics (similar to parseActualPcapData)
  const avgPacketSize = packetSizes.length > 0 
    ? Math.round(packetSizes.reduce((sum, size) => sum + size, 0) / packetSizes.length) 
    : 0;
  
  // Sort packet sizes for median calculation
  packetSizes.sort((a, b) => a - b);
  const medianPacketSize = packetSizes.length > 0 
    ? packetSizes[Math.floor(packetSizes.length / 2)]
    : 0;
  
  // Convert protocol counts to array for chart
  const protocolData = Object.entries(protocolCounts).map(([name, value]) => ({
    name,
    value
  }));
  
  // Update relative timestamps now that we know minTimestamp
  if (minTimestamp !== Number.MAX_VALUE) {
    for (const packet of packets) {
      if (parseFloat(packet.time) >= minTimestamp) {
        packet.relativeTime = (parseFloat(packet.time) - minTimestamp).toFixed(6);
      }
    }
  }
  
  // Generate time series data
  const duration = maxTimestamp - minTimestamp;
  const timeSeriesData = generateTimeSeriesData(packets, duration);
  
  // Get top IPs by packet count
  const ipCountMap = new Map();
  packets.forEach(packet => {
    // Extract IP without port
    const sourceIP = packet.source?.split(':')?.[0] || packet.source;
    const destIP = packet.destination?.split(':')?.[0] || packet.destination;
    
    if (sourceIP && sourceIP !== "Unknown") {
      ipCountMap.set(sourceIP, (ipCountMap.get(sourceIP) || 0) + 1);
    }
    if (destIP && destIP !== "Unknown") {
      ipCountMap.set(destIP, (ipCountMap.get(destIP) || 0) + 1);
    }
  });
  
  // Convert to array and sort
  const topIPs = Array.from(ipCountMap.entries())
    .map(([address, count]) => ({ address, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  return {
    filename,
    size: fileSize,
    timestamp: new Date().toISOString(),
    format: 'PCAP-NG',
    summary: {
      totalPackets: packetCount,
      ipAddresses: ipAddresses.size,
      conversationCount: conversations.size,
      tcpPackets: protocolCounts['TCP'] || 0,
      udpPackets: protocolCounts['UDP'] || 0,
      icmpPackets: protocolCounts['ICMP'] || 0,
      otherPackets: packetCount - ((protocolCounts['TCP'] || 0) + (protocolCounts['UDP'] || 0) + (protocolCounts['ICMP'] || 0)),
      avgPacketSize,
      medianPacketSize,
      minPacketSize: packetSizes[0] || 0,
      maxPacketSize: packetSizes[packetSizes.length - 1] || 0,
      captureDuration: formatDuration(duration),
      startTime: new Date(minTimestamp * 1000).toISOString(),
      endTime: new Date(maxTimestamp * 1000).toISOString(),
      packetsPerSecond: (packetCount / Math.max(duration, 0.001)).toFixed(1),
      topIPs,
      protocolCounts: Object.entries(protocolCounts)
        .map(([protocol, count]) => ({ protocol, count }))
        .sort((a, b) => b.count - a.count)
    },
    packets,
    protocols: Object.keys(protocolCounts),
    protocolData,
    timeSeriesData,
    ipAddresses: Array.from(ipAddresses),
    conversations: Array.from(conversations.values()),
    interfaces: interfaceDescriptions
  };
};

/**
 * Format a MAC address from a byte array
 */
const formatMacAddress = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join(':');
};

/**
 * Format an IPv4 address from DataView at specified offset
 */
const formatIPv4 = (view: DataView, offset: number): string => {
  return `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`;
};

/**
 * Format an IPv6 address from a byte array
 */
const formatIPv6 = (bytes: Uint8Array): string => {
  // Group bytes into 16-bit words
  const words: string[] = [];
  for (let i = 0; i < bytes.length; i += 2) {
    const word = (bytes[i] << 8) + bytes[i+1];
    words.push(word.toString(16));
  }
  
  // Find the longest run of zeros for compression
  let longestZerosStart = -1;
  let longestZerosLength = 0;
  let currentZerosStart = -1;
  let currentZerosLength = 0;
  
  for (let i = 0; i < words.length; i++) {
    if (words[i] === '0') {
      if (currentZerosStart === -1) {
        currentZerosStart = i;
        currentZerosLength = 1;
      } else {
        currentZerosLength++;
      }
    } else if (currentZerosStart !== -1) {
      if (currentZerosLength > longestZerosLength) {
        longestZerosStart = currentZerosStart;
        longestZerosLength = currentZerosLength;
      }
      currentZerosStart = -1;
      currentZerosLength = 0;
    }
  }
  
  // Check if the last sequence was zeros
  if (currentZerosLength > longestZerosLength) {
    longestZerosStart = currentZerosStart;
    longestZerosLength = currentZerosLength;
  }
  
  // Build the IPv6 string with compression if applicable
  let result = '';
  
  if (longestZerosLength >= 2) { // Only compress if at least 2 consecutive zeros
    for (let i = 0; i < words.length; i++) {
      if (i === longestZerosStart) {
        result += (i === 0 ? '' : ':') + ':';
        i += longestZerosLength - 1; // Skip the run of zeros
      } else {
        result += (i === 0 ? '' : ':') + words[i];
      }
    }
  } else {
    result = words.join(':');
  }
  
  return result;
};

/**
 * Get protocol name from IP protocol number
 */
const getProtocolName = (protocol: number): string => {
  switch (protocol) {
    case 1: return 'ICMP';
    case 2: return 'IGMP';
    case 6: return 'TCP';
    case 17: return 'UDP';
    case 41: return 'IPv6';
    case 47: return 'GRE';
    case 50: return 'ESP';
    case 51: return 'AH';
    case 58: return 'ICMPv6';
    case 89: return 'OSPF';
    case 103: return 'PIM';
    case 132: return 'SCTP';
    default: return `Protocol-${protocol}`;
  }
};

/**
 * Get TCP flags as string
 */
const getTcpFlags = (flags: number): string => {
  const flagMap = [
    { mask: 0x01, name: 'FIN' },
    { mask: 0x02, name: 'SYN' },
    { mask: 0x04, name: 'RST' },
    { mask: 0x08, name: 'PSH' },
    { mask: 0x10, name: 'ACK' },
    { mask: 0x20, name: 'URG' },
    { mask: 0x40, name: 'ECE' },
    { mask: 0x80, name: 'CWR' }
  ];
  
  const activeFlags = flagMap
    .filter(flag => (flags & flag.mask) !== 0)
    .map(flag => flag.name);
    
  return activeFlags.length > 0 ? activeFlags.join(' ') : 'None';
};

/**
 * Get ICMP type and code as human-readable string
 */
const getIcmpTypeName = (type: number, code: number): string => {
  switch (type) {
    case 0: return 'Echo Reply';
    case 3: 
      switch (code) {
        case 0: return 'Destination Network Unreachable';
        case 1: return 'Destination Host Unreachable';
        case 3: return 'Destination Port Unreachable';
        case 4: return 'Fragmentation Needed but DF Set';
        default: return `Destination Unreachable (code ${code})`;
      }
    case 5: return 'Redirect';
    case 8: return 'Echo Request';
    case 11: 
      switch (code) {
        case 0: return 'TTL Expired in Transit';
        case 1: return 'Fragment Reassembly Time Exceeded';
        default: return `Time Exceeded (code ${code})`;
      }
    default: return `ICMP Type ${type}, Code ${code}`;
  }
};

/**
 * Create a hex dump from a byte array
 */
const createHexDump = (bytes: Uint8Array): string => {
  let result = '';
  const rowSize = 16;
  
  for (let i = 0; i < bytes.length; i += rowSize) {
    // Offset
    const offset = i.toString(16).padStart(4, '0');
    result += `${offset}: `;
    
    // Hex values
    for (let j = 0; j < rowSize; j++) {
      if (i + j < bytes.length) {
        result += bytes[i + j].toString(16).padStart(2, '0') + ' ';
      } else {
        result += '   ';
      }
    }
    
    // ASCII representation
    result += ' ';
    for (let j = 0; j < rowSize; j++) {
      if (i + j < bytes.length) {
        const byte = bytes[i + j];
        // Only print printable ASCII characters (32-126)
        result += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
      }
    }
    
    result += '\n';
  }
  
  return result;
};

/**
 * Create an ASCII dump from a byte array (only printable characters)
 */
const createAsciiDump = (bytes: Uint8Array): string => {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    result += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
    
    // Add a newline every 32 characters for readability
    if ((i + 1) % 32 === 0) {
      result += '\n';
    }
  }
  return result;
};

/**
 * Generate time series data for visualization
 */
const generateTimeSeriesData = (packets: any[], duration: number): any[] => {
  const numPoints = 20; // Number of data points for the chart
  const timeSeriesData = Array(numPoints).fill(0).map((_, i) => ({
    time: `${Math.round((i / numPoints) * 100)}%`,
    value: 0
  }));
  
  // Count packets in each time bucket
  packets.forEach(packet => {
    const time = parseFloat(packet.relativeTime || packet.time);
    const bucketIndex = Math.min(
      Math.floor((time / Math.max(duration, 0.001)) * numPoints),
      numPoints - 1
    );
    if (bucketIndex >= 0) {
      timeSeriesData[bucketIndex].value++;
    }
  });
  
  return timeSeriesData;
};

/**
 * Format duration in seconds as human-readable string
 */
const formatDuration = (seconds: number): string => {
  if (isNaN(seconds) || !isFinite(seconds)) return '00:00:00.000';
  
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  const ms = Math.floor((seconds % 1) * 1000);
  
  return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}.${ms.toString().padStart(3, '0')}`;
};
