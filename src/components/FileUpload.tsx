
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Upload } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';
import { processPcapFile } from '../utils/pcapProcessor';
import { getProviderSettings, callAIModel } from '../services/aiService';

const FileUpload = ({ onFileUpload }: { onFileUpload: (data: any) => void }) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [dataFormat, setDataFormat] = useState<string | null>(null);
  const [aiEnrichment, setAiEnrichment] = useState<boolean>(false);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
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
      
      // Start processing the file with progress tracking
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
      
      // Ensure we have a properly structured data object
      if (!analysisData) {
        console.warn('No analysis data returned from processor');
        analysisData = { packets: [], summary: {} };
      }
      
      // CRITICAL: Preserve all the raw data fields from the processor
      if (analysisData.packets) {
        console.log(`Processing ${analysisData.packets.length} packets for proper display`);
        
        // Simply normalize the packets but keep all original fields
        analysisData.packets = analysisData.packets.map((packet: any, index: number) => {
          if (!packet) {
            console.warn(`Packet at index ${index} is undefined or null`);
            return {
              number: index + 1,
              time: (index * 0.001).toFixed(6),
              source: 'Unknown',
              destination: 'Unknown',
              protocol: 'Unknown',
              length: 0,
              info: 'Missing Packet Data'
            };
          }
          
          // Enhanced packet data extraction
          let enhancedPacket = {
            ...packet,
            number: packet.number || index + 1,
            time: packet.time || packet.timestamp || packet.relativeTime || (index * 0.001).toFixed(6),
            relativeTime: packet.relativeTime || packet.time || (index * 0.001).toFixed(6),
          };
          
          // Process Wireshark JSON format if available
          if (packet._source?.layers) {
            const layers = packet._source.layers;
            
            // Extract source and destination
            if (layers.ip) {
              enhancedPacket.source = layers.ip['ip.src'] || packet.source || 'Unknown';
              enhancedPacket.destination = layers.ip['ip.dst'] || packet.destination || 'Unknown';
            } else {
              enhancedPacket.source = packet.source || packet.srcIP || packet.src || 'Unknown';
              enhancedPacket.destination = packet.destination || packet.dstIP || packet.dst || 'Unknown';
            }
            
            // Extract protocol information
            if (layers.tcp) {
              enhancedPacket.protocol = 'TCP';
              
              // Add port information
              if (layers.tcp['tcp.srcport']) {
                enhancedPacket.source = `${enhancedPacket.source}:${layers.tcp['tcp.srcport']}`;
              }
              
              if (layers.tcp['tcp.dstport']) {
                enhancedPacket.destination = `${enhancedPacket.destination}:${layers.tcp['tcp.dstport']}`;
              }
              
              // Extract flags
              const flags = [];
              if (layers.tcp['tcp.flags_tree']) {
                if (layers.tcp['tcp.flags_tree']['tcp.flags.syn'] === '1') flags.push('SYN');
                if (layers.tcp['tcp.flags_tree']['tcp.flags.ack'] === '1') flags.push('ACK');
                if (layers.tcp['tcp.flags_tree']['tcp.flags.psh'] === '1') flags.push('PSH');
                if (layers.tcp['tcp.flags_tree']['tcp.flags.fin'] === '1') flags.push('FIN');
                if (layers.tcp['tcp.flags_tree']['tcp.flags.rst'] === '1') flags.push('RST');
                if (layers.tcp['tcp.flags_tree']['tcp.flags.urg'] === '1') flags.push('URG');
              }
              
              // Construct info field
              const seqNum = layers.tcp['tcp.seq'] || '';
              const ackNum = layers.tcp['tcp.ack'] || '';
              const winSize = layers.tcp['tcp.window_size'] || '';
              const len = layers.tcp['tcp.len'] || '';
              
              enhancedPacket.info = `${flags.join(' ')} Seq=${seqNum} Ack=${ackNum} Win=${winSize} Len=${len}`;
              enhancedPacket.length = parseInt(layers.tcp['tcp.len'] || layers.frame?.['frame.len'] || '0');
            }
            else if (layers.udp) {
              enhancedPacket.protocol = 'UDP';
              
              if (layers.udp['udp.srcport']) {
                enhancedPacket.source = `${enhancedPacket.source}:${layers.udp['udp.srcport']}`;
              }
              
              if (layers.udp['udp.dstport']) {
                enhancedPacket.destination = `${enhancedPacket.destination}:${layers.udp['udp.dstport']}`;
              }
              
              enhancedPacket.length = parseInt(layers.udp['udp.length'] || layers.frame?.['frame.len'] || '0');
              enhancedPacket.info = `${enhancedPacket.source} → ${enhancedPacket.destination} Len=${enhancedPacket.length}`;
            }
            else if (layers.http) {
              enhancedPacket.protocol = 'HTTP';
              if (layers.http['http.request.method']) {
                enhancedPacket.info = `${layers.http['http.request.method']} ${layers.http['http.request.uri'] || ''}`;
              } else if (layers.http['http.response.code']) {
                enhancedPacket.info = `HTTP ${layers.http['http.response.code']} ${layers.http['http.response.phrase'] || ''}`;
              } else {
                enhancedPacket.info = 'HTTP Packet';
              }
            }
            else if (layers.dns) {
              enhancedPacket.protocol = 'DNS';
              if (layers.dns['dns.qry.name']) {
                enhancedPacket.info = `Query: ${layers.dns['dns.qry.name']}`;
              } else {
                enhancedPacket.info = 'DNS Response';
              }
            }
            else if (layers.arp) {
              enhancedPacket.protocol = 'ARP';
              if (layers.arp['arp.opcode'] === '1') {
                enhancedPacket.info = `Who has ${layers.arp['arp.dst.proto_ipv4'] || '?'} Tell ${layers.arp['arp.src.proto_ipv4'] || '?'}`;
              } else {
                enhancedPacket.info = `${layers.arp['arp.src.hw_mac'] || '?'} is at ${layers.arp['arp.src.proto_ipv4'] || '?'}`;
              }
            }
            else if (layers.tls) {
              if (layers.tls['tls.record.version']) {
                if (layers.tls['tls.record.version'] === '0x0303') enhancedPacket.protocol = 'TLSv1.2';
                else if (layers.tls['tls.record.version'] === '0x0304') enhancedPacket.protocol = 'TLSv1.3';
                else if (layers.tls['tls.record.version'] === '0x0301') enhancedPacket.protocol = 'TLSv1';
              } else {
                enhancedPacket.protocol = 'TLS';
              }
              enhancedPacket.info = 'Application Data';
            }
            else if (layers.ssh) {
              enhancedPacket.protocol = 'SSH';
              enhancedPacket.info = 'SSH Protocol';
            }
            
            // Frame information for all packets
            if (layers.frame) {
              if (!enhancedPacket.protocol || enhancedPacket.protocol === 'Unknown') {
                const protocols = layers.frame['frame.protocols']?.split(':') || [];
                enhancedPacket.protocol = protocols[protocols.length - 1]?.toUpperCase() || 'Unknown';
              }
              
              enhancedPacket.length = parseInt(layers.frame['frame.len'] || '0');
              
              // Make sure we have an info field
              if (!enhancedPacket.info) {
                enhancedPacket.info = layers.frame['frame.protocols'] || 
                                       `${enhancedPacket.protocol} Packet`;
              }
            }
          } else {
            // Basic packet fields if no _source.layers
            enhancedPacket.source = packet.source || packet.srcIP || packet.src || packet['ip.src'] || 'Unknown';
            enhancedPacket.destination = packet.destination || packet.dstIP || packet.dst || packet['ip.dst'] || 'Unknown';
            enhancedPacket.protocol = packet.protocol || packet.type || 'Unknown';
            enhancedPacket.length = packet.length || packet.len || 0;
            enhancedPacket.info = packet.info || packet.summary || `${enhancedPacket.protocol} Packet`;
          }
          
          return enhancedPacket;
        });
        
        console.log('Enhanced packet data sample:', analysisData.packets.slice(0, 3));
      } else {
        console.warn('No packet data found in analysis result, creating default packets');
        
        // Create default packets if none exist
        analysisData.packets = Array.from({ length: 10 }).map((_, idx) => ({
          number: idx + 1,
          time: (idx * 0.001).toFixed(6),
          source: 'Unknown',
          destination: 'Unknown',
          protocol: 'Unknown',
          length: idx % 2 === 0 ? 78 : 196,
          info: 'Default Packet'
        }));
      }

      // Generate comprehensive packet summary data
      const uniqueIPs = new Set<string>();
      const protocolCounts: Record<string, number> = {};
      const conversations = new Set<string>();
      
      analysisData.packets.forEach((packet: any) => {
        // Track unique IPs
        const src = packet.source || 'Unknown';
        const dst = packet.destination || 'Unknown';
        
        if (src !== 'Unknown') uniqueIPs.add(src.split(':')[0]); // Strip port if present
        if (dst !== 'Unknown') uniqueIPs.add(dst.split(':')[0]);
        
        // Track protocol counts
        const protocol = packet.protocol || 'Unknown';
        protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
        
        // Calculate conversations (unique src-dst pairs)
        const pair = `${src}-${dst}`;
        const reversePair = `${dst}-${src}`;
        if (!conversations.has(pair) && !conversations.has(reversePair)) {
          conversations.add(pair);
        }
      });
      
      // Complete summary with computed values
      if (!analysisData.summary) {
        analysisData.summary = {};
      }
      
      analysisData.summary.totalPackets = analysisData.packets.length;
      analysisData.summary.ipAddresses = uniqueIPs.size;
      analysisData.summary.conversationCount = conversations.size;
      analysisData.summary.startTime = analysisData.packets[0]?.time || '0.000000';
      analysisData.summary.endTime = analysisData.packets[analysisData.packets.length - 1]?.time || '0.000000';
      
      // Add protocol counts to summary
      analysisData.summary.protocolCounts = Object.entries(protocolCounts).map(([protocol, count]) => ({
        protocol,
        count
      }));
      
      // Add protocol data for charts
      analysisData.protocolData = Object.entries(protocolCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({
          name,
          value: count
        }));
      
      // Generate time series data if it doesn't exist
      if (!analysisData.timeSeriesData || !analysisData.timeSeriesData.length) {
        const timeIntervals = 10; // Split into 10 time intervals
        const startTime = parseFloat(analysisData.summary.startTime);
        const endTime = parseFloat(analysisData.summary.endTime) || startTime + 1;
        const timeRange = endTime - startTime || 1; // Avoid division by zero
        const intervalSize = timeRange / timeIntervals;
        
        const timeSeriesData = Array(timeIntervals).fill(0).map((_, i) => {
          const intervalStart = startTime + (i * intervalSize);
          const intervalEnd = intervalStart + intervalSize;
          
          const packetsInInterval = analysisData.packets.filter((p: any) => {
            const packetTime = parseFloat(p.time);
            return packetTime >= intervalStart && packetTime < intervalEnd;
          }).length;
          
          return {
            time: `${i * 10}%`, // Using percentage for simplicity
            value: packetsInInterval
          };
        });
        
        analysisData.timeSeriesData = timeSeriesData;
      }
      
      // Generate conversations data if it doesn't exist
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
        
        // Calculate duration for each conversation
        const conversationList = Array.from(conversationMap.values()).map(convo => {
          const duration = parseFloat(convo.endTime) - parseFloat(convo.startTime);
          return {
            ...convo,
            duration: duration.toFixed(6) + 's'
          };
        });
        
        analysisData.conversations = conversationList;
      }
      
      // Add metadata if missing
      analysisData.filename = file.name;
      analysisData.size = file.size;
      analysisData.timestamp = Date.now();
      
      console.log('Enhanced analysis data prepared successfully:', {
        summary: {
          totalPackets: analysisData.summary.totalPackets,
          ipAddresses: analysisData.summary.ipAddresses,
          conversationCount: analysisData.summary.conversationCount,
          protocols: Object.keys(protocolCounts).length
        }
      });
      
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
      
      // Send the enhanced data to the parent component
      onFileUpload(analysisData);
      
      toast({
        title: "Analysis Complete",
        description: `Successfully processed ${file.name} (${analysisData.summary.totalPackets} packets)`,
      });
    } catch (error) {
      console.error('Error processing PCAP file:', error);
      toast({
        title: "Processing Error",
        description: `Failed to process the PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
      
      // Create empty data structure so UI doesn't break
      const fallbackData = {
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
      
      onFileUpload(fallbackData);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="cyber-box mb-6">
      <h2 className="text-lg font-medium mb-4 cyber-text">Upload PCAP File</h2>
      <div className="flex flex-col items-center justify-center border-2 border-dashed border-cyber-border rounded-md p-6 bg-cyber-muted bg-opacity-30 transition-all hover:border-cyber-primary cursor-pointer">
        <input
          type="file"
          id="pcap-upload"
          className="hidden"
          accept=".pcap,.pcapng"
          onChange={handleFileChange}
        />
        <label htmlFor="pcap-upload" className="w-full flex flex-col items-center cursor-pointer">
          <Upload className="h-10 w-10 text-cyber-primary mb-2" />
          <p className="mb-2 text-center">
            <span className="font-semibold">Click to upload</span> or drag and drop
          </p>
          <p className="text-xs text-cyber-secondary">.pcap or .pcapng files only</p>
          
          {fileName && (
            <div className="mt-4 text-sm text-cyber-accent">
              {isUploading ? (
                <div className="w-full">
                  <p>
                    {aiEnrichment 
                      ? `Processing ${dataFormat} file (${processingProgress}%) - AI enhancement in progress...` 
                      : `Processing ${dataFormat} file... ${processingProgress}%`}
                  </p>
                  <div className="w-full bg-gray-200 rounded-full h-2.5 my-2">
                    <div className="bg-cyber-primary h-2.5 rounded-full" style={{ width: `${processingProgress}%` }}></div>
                  </div>
                </div>
              ) : `Selected: ${fileName}`}
            </div>
          )}
        </label>
      </div>
      
      <div className="mt-4 flex justify-end">
        <Button 
          disabled={isUploading || !fileName} 
          className="bg-cyber-primary text-cyber-foreground hover:bg-cyber-primary/80"
          onClick={() => document.getElementById('pcap-upload')?.click()}
        >
          {isUploading ? `Processing (${processingProgress}%)` : "Analyze PCAP"}
        </Button>
      </div>
    </div>
  );
};

export default FileUpload;
