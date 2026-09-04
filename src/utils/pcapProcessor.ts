import { decodePacketBytes } from './decoders/deepDecoder';

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
        const analysisData = await parseActualPcapData(file.name, buffer, progressCallback);
        
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
const parseActualPcapData = async (filename: string, buffer: ArrayBuffer, progressCallback?: (progress: number) => void): Promise<any> => {
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
      return parsePcapNgFormat(dataView, fileSize, filename, progressCallback);
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
        
        // Full protocol decoding is delegated to the byte-level decoder so the
        // whole encapsulation chain is walked, not just Ethernet/IP/TCP.
        const frame = new Uint8Array(buffer.slice(offset, offset + inclLen));
        const decoded = decodePacketBytes(frame, network);

        packetDetails.protocol = decoded.protocol;
        packetDetails.source = decoded.source;
        packetDetails.destination = decoded.destination;
        packetDetails.info = decoded.info;
        packetDetails.layers = decoded.stack;
        packetDetails.protocolStack = decoded.stack;
        packetDetails.decodedLayers = decoded.layers;
        packetDetails.truncated = decoded.truncated;

        for (const layer of decoded.layers) {
          const f: any = layer.fields;
          if (layer.name === 'Ethernet') {
            packetDetails.ethernet = { destMac: f['Destination MAC'], srcMac: f['Source MAC'], type: f.EtherType };
          } else if (layer.name === 'IPv4') {
            packetDetails.ip = {
              version: '4', headerLength: String(f['Header length']), ttl: String(f.TTL),
              protocol: String(f.Protocol), source: f.Source, destination: f.Destination,
            };
          } else if (layer.name === 'IPv6') {
            packetDetails.ipv6 = {
              version: '6', hopLimit: String(f['Hop limit']), nextHeader: String(f['Next header']),
              source: f.Source, destination: f.Destination, flowLabel: String(f['Flow label']),
            };
          } else if (layer.name === 'TCP') {
            packetDetails.tcp = {
              srcPort: String(f['Source port']), dstPort: String(f['Destination port']),
              seq: String(f['Sequence number']), ack: String(f['Acknowledgment number']),
              flags: String(f.Flags), window: String(f['Window size']), length: String(f['Payload length']),
            };
          } else if (layer.name === 'UDP') {
            packetDetails.udp = { srcPort: String(f['Source port']), dstPort: String(f['Destination port']), length: String(f.Length) };
          } else if (layer.name === 'ARP' || layer.name === 'RARP') {
            packetDetails.arp = {
              operation: String(f.Operation).includes('request') ? 'Request' : 'Reply',
              senderMac: f['Sender MAC'], senderIP: f['Sender IP'],
              targetMac: f['Target MAC'], targetIP: f['Target IP'],
            };
          } else if (layer.name === 'ICMP' || layer.name === 'ICMPv6') {
            packetDetails[layer.name.toLowerCase()] = { type: String(f.Type), code: String(f.Code), typeName: String(f.Type) };
          }
        }

        const srcHost = String(decoded.source).split(':').slice(0, -1).join(':') || decoded.source;
        const dstHost = String(decoded.destination).split(':').slice(0, -1).join(':') || decoded.destination;
        if (srcHost && srcHost !== 'Unknown') ipAddresses.add(srcHost);
        if (dstHost && dstHost !== 'Unknown') ipAddresses.add(dstHost);
        protocolCounts[decoded.protocol] = (protocolCounts[decoded.protocol] || 0) + 1;
        const convKey = [srcHost, dstHost].sort().join('-');
        const existing = conversations.get(convKey);
        if (existing) {
          existing.packetCount++;
          existing.bytes += inclLen;
          existing.endTime = timestamp;
        } else {
          conversations.set(convKey, {
            endpointA: srcHost, endpointB: dstHost,
            packetCount: 1, bytes: inclLen,
            startTime: timestamp, endTime: timestamp,
          });
        }


      
        // Always set a relative time once we know the minimum timestamp
        if (minTimestamp !== Number.MAX_VALUE && minTimestamp <= timestamp) {
          packetDetails.relativeTime = (timestamp - minTimestamp).toFixed(6);
        }
      
        // Add packet size to statistics
        packetSizes.push(inclLen);
      
        // Store every packet so the displayed count matches the capture
        packets.push(packetDetails);

      
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
const parsePcapNgFormat = (dataView: DataView, fileSize: number, filename: string, progressCallback?: (progress: number) => void): any => {
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
  
  try {
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
              
              const frame = new Uint8Array(
                dataView.buffer.slice(packetDataOffset, packetDataOffset + capturedLen)
              );
              applyDecodedFrame(
                packetDetails, frame, iface.linkType, capturedLen, timestampSec,
                ipAddresses, protocolCounts, conversations
              );

              // Add packet to collection and update stats
              packetSizes.push(capturedLen);
              packets.push(packetDetails);

              
              packetCount++;
              
              // Log progress occasionally
              if (packetCount % 1000 === 0) {
                console.log(`Processed ${packetCount} PCAP-NG packets...`);
                if (progressCallback) {
                  progressCallback(0.3 + (0.7 * Math.min(packetCount / 50000, 1)));
                }
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
  } catch (error) {
    console.error(`Error parsing PCAP-NG format:`, error);
    // Continue with whatever packets we managed to parse
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
