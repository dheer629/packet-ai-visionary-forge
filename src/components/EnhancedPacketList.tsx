
import React, { useState, useMemo, useEffect } from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Search, Filter } from 'lucide-react';
import PacketDetails from './PacketDetails';

interface EnhancedPacketListProps {
  packets: any[];
}

const EnhancedPacketList: React.FC<EnhancedPacketListProps> = ({ packets = [] }) => {
  const [filter, setFilter] = useState('');
  const [selectedPacket, setSelectedPacket] = useState<any>(null);
  const [showFilters, setShowFilters] = useState(false);
  const [filterOptions, setFilterOptions] = useState({
    protocol: '',
    source: '',
    destination: '',
    minLength: '',
    maxLength: '',
    flags: ''
  });
  const [page, setPage] = useState(0);
  const pageSize = 100; // Show 100 packets per page
  const maxPackets = packets.length;

  useEffect(() => {
    console.log('EnhancedPacketList received packets:', {
      packetCount: packets?.length || 0, 
      first3Packets: packets?.slice(0, 3).map(p => ({
        number: p.number,
        time: p.time,
        source: p.source || p.srcIP || p.src || p['ip.src'],
        destination: p.destination || p.dstIP || p.dst || p['ip.dst'],
        protocol: p.protocol || p.type,
        length: p.length,
        info: p.info
      })),
      validArray: Array.isArray(packets),
      hasLayers: packets?.some(p => p._source?.layers)
    });
  }, [packets]);
  
  // Ensure we have a valid packets array
  const safePackets = useMemo(() => {
    if (!packets || !Array.isArray(packets)) {
      console.warn('Invalid packets data received in EnhancedPacketList');
      return [];
    }
    
    // Process packets to ensure all required fields are available
    return packets.map((packet, index) => {
      if (!packet) {
        return {
          number: index + 1,
          time: '0.000000',
          source: 'Unknown',
          destination: 'Unknown',
          protocol: 'Unknown',
          length: 0,
          info: 'Invalid Packet'
        };
      }
      
      // Extract data from Wireshark JSON format if available
      let source = packet.source || 'Unknown';
      let destination = packet.destination || 'Unknown'; 
      let protocol = packet.protocol || 'Unknown';
      let info = packet.info || 'Unknown Packet';
      let length = packet.length || 0;
      
      // Try to extract from _source.layers if available (Wireshark JSON format)
      if (packet._source?.layers) {
        const layers = packet._source.layers;
        
        // IP layer
        if (layers.ip) {
          source = layers.ip['ip.src'] || source;
          destination = layers.ip['ip.dst'] || destination;
        }
        
        // Extract TCP/UDP port info if available
        if (layers.tcp) {
          source = source + ':' + (layers.tcp['tcp.srcport'] || '');
          destination = destination + ':' + (layers.tcp['tcp.dstport'] || '');
          protocol = 'TCP';
          
          // Detailed TCP flags handling
          const flags = [];
          if (layers.tcp['tcp.flags_tree']) {
            if (layers.tcp['tcp.flags_tree']['tcp.flags.syn'] === '1') flags.push('SYN');
            if (layers.tcp['tcp.flags_tree']['tcp.flags.ack'] === '1') flags.push('ACK');
            if (layers.tcp['tcp.flags_tree']['tcp.flags.fin'] === '1') flags.push('FIN');
            if (layers.tcp['tcp.flags_tree']['tcp.flags.psh'] === '1') flags.push('PSH');
            if (layers.tcp['tcp.flags_tree']['tcp.flags.rst'] === '1') flags.push('RST');
            if (layers.tcp['tcp.flags_tree']['tcp.flags.urg'] === '1') flags.push('URG');
          }
          
          // Construct meaningful TCP info
          const seqNum = layers.tcp['tcp.seq'] || '';
          const ackNum = layers.tcp['tcp.ack'] || '';
          const winSize = layers.tcp['tcp.window_size'] || '';
          const len = layers.tcp['tcp.len'] || '';
          
          info = `${flags.join(' ')} Seq=${seqNum} Ack=${ackNum} Win=${winSize} Len=${len}`;
          length = parseInt(layers.tcp['tcp.len'] || length);
        } else if (layers.udp) {
          source = source + ':' + (layers.udp['udp.srcport'] || '');
          destination = destination + ':' + (layers.udp['udp.dstport'] || '');
          protocol = 'UDP';
          length = parseInt(layers.udp['udp.length'] || length);
        }
        
        // Get highest layer protocol
        if (layers.http) {
          protocol = 'HTTP';
          info = layers.http['http.request.method'] 
            ? `${layers.http['http.request.method']} ${layers.http['http.request.uri']}`
            : layers.http['http.response.code'] 
              ? `HTTP ${layers.http['http.response.code']} ${layers.http['http.response.phrase']}`
              : 'HTTP Packet';
        } else if (layers.dns) {
          protocol = 'DNS';
          info = layers.dns['dns.qry.name'] ? `Query: ${layers.dns['dns.qry.name']}` : 'DNS Packet';
        } else if (layers.ssh) {
          protocol = 'SSH';
          info = 'SSH ' + (layers.ssh['ssh.protocol'] || '');
        } else if (layers.arp) {
          protocol = 'ARP';
          info = layers.arp['arp.opcode'] === '1' ? 'Who has ' + (layers.arp['arp.dst.proto_ipv4'] || '?') : 'ARP Reply';
        } else if (layers.tls) {
          protocol = 'TLS';
          if (layers.tls['tls.record.version']) {
            if (layers.tls['tls.record.version'] === '0x0303') protocol = 'TLSv1.2';
            else if (layers.tls['tls.record.version'] === '0x0304') protocol = 'TLSv1.3';
            else if (layers.tls['tls.record.version'] === '0x0301') protocol = 'TLSv1';
          }
          info = 'Application Data';
        }
        
        // Use frame protocol if we still don't have a good protocol
        if (protocol === 'Unknown' && layers.frame?.['frame.protocols']) {
          const protocols = layers.frame['frame.protocols'].split(':');
          protocol = protocols[protocols.length - 1].toUpperCase();
        }
        
        // Get packet length from frame if available
        if (layers.frame && layers.frame['frame.len']) {
          length = parseInt(layers.frame['frame.len']);
        }
      }
      
      // Clean and normalize packet data
      return {
        ...packet, // Keep all original data
        number: packet.number || index + 1,
        time: packet.time || packet.timestamp || packet.relativeTime || '0.000000',
        relativeTime: packet.relativeTime || packet.time || '0.000000',
        source: source,
        destination: destination,
        protocol: protocol,
        length: length,
        info: info
      };
    });
  }, [packets]);
  
  // Filter packets based on search term and filters - memoized for performance
  const filteredPackets = useMemo(() => {
    if (!safePackets || safePackets.length === 0) {
      return [];
    }
    
    console.log(`Filtering ${safePackets.length} packets with filter: ${filter}`);
    
    return safePackets.filter(packet => {
      // Skip undefined packets
      if (!packet) return false;
      
      // Global search filter
      if (filter && 
          !Object.entries(packet).some(([key, val]) => {
            // Only search certain fields to improve performance
            if (['number', 'time', 'source', 'destination', 'protocol', 'info'].includes(key)) {
              return String(val || '').toLowerCase().includes(filter.toLowerCase());
            }
            return false;
          })) {
        return false;
      }
      
      // Protocol filter
      if (filterOptions.protocol && 
          !String(packet.protocol || '').toLowerCase().includes(filterOptions.protocol.toLowerCase())) {
        return false;
      }
      
      // Source filter
      if (filterOptions.source && 
          !String(packet.source || '').includes(filterOptions.source)) {
        return false;
      }
      
      // Destination filter
      if (filterOptions.destination && 
          !String(packet.destination || '').includes(filterOptions.destination)) {
        return false;
      }
      
      // Min length filter
      if (filterOptions.minLength && packet.length && 
          packet.length < parseInt(filterOptions.minLength)) {
        return false;
      }
      
      // Max length filter
      if (filterOptions.maxLength && packet.length && 
          packet.length > parseInt(filterOptions.maxLength)) {
        return false;
      }
      
      // Flag filter (in info field or tcp.flags if available)
      if (filterOptions.flags) {
        const flagsLower = filterOptions.flags.toLowerCase();
        const infoMatches = String(packet.info || '').toLowerCase().includes(flagsLower);
        const tcpFlagsMatch = packet.tcp?.flags?.toLowerCase().includes(flagsLower) || 
                             packet._source?.layers?.tcp?.['tcp.flags_tree']?.toString().toLowerCase().includes(flagsLower);
        
        if (!infoMatches && !tcpFlagsMatch) {
          return false;
        }
      }
      
      return true;
    });
  }, [safePackets, filter, filterOptions]);

  // Get paginated packets to display
  const displayedPackets = useMemo(() => {
    const start = page * pageSize;
    return filteredPackets.slice(start, start + pageSize);
  }, [filteredPackets, page, pageSize]);

  const handlePacketClick = (packet: any) => {
    setSelectedPacket(packet);
    console.log('Selected packet details:', packet);
  };

  const closePacketDetails = () => {
    setSelectedPacket(null);
  };

  const getProtocolColor = (protocol: string = "") => {
    const protocolUpper = String(protocol).toUpperCase();
    switch (protocolUpper) {
      case 'TCP': return 'text-cyber-primary';
      case 'UDP': return 'text-green-500';
      case 'ICMP': return 'text-orange-500';
      case 'IGMP': return 'text-purple-600';
      case 'DNS': return 'text-cyber-secondary';
      case 'HTTP': return 'text-blue-500';
      case 'HTTPS': return 'text-emerald-400';
      case 'ARP': return 'text-purple-500';
      case 'IPV6': return 'text-pink-500';
      case 'SSH': return 'text-yellow-600';
      case 'SMTP': return 'text-cyan-500';
      case 'FTP': return 'text-amber-500';
      case 'DHCP': return 'text-indigo-500';
      case 'NTP': return 'text-teal-500';
      case 'TLSV1': case 'TLSV1.2': case 'TLSV1.3': 
        return 'text-emerald-500';
      case 'ETHERNET': case 'ETH': return 'text-blue-300';
      case 'IP': case 'IPV4': return 'text-blue-500';
      case 'LINK-TYPE 113':
      case 'LINK-TYPE':
        return 'text-gray-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="cyber-box">
      <div className="flex flex-col mb-4">
        <div className="flex justify-between items-center mb-2">
          <h3 className="text-sm font-medium cyber-text">
            Packet Capture ({maxPackets} total packets)
          </h3>
          <Button 
            variant="outline" 
            size="sm" 
            className="text-xs"
            onClick={() => setShowFilters(!showFilters)}
          >
            <Filter className="h-3 w-3 mr-1" />
            {showFilters ? 'Hide Filters' : 'Show Filters'}
          </Button>
        </div>
        
        <div className="relative">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-cyber-foreground/50" />
          <Input
            placeholder="Filter packets..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="pl-8 bg-cyber-muted border-cyber-border"
          />
        </div>
      </div>
      
      {showFilters && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mb-4">
          <Input
            placeholder="Protocol (TCP, UDP, HTTP...)"
            value={filterOptions.protocol}
            onChange={(e) => setFilterOptions({...filterOptions, protocol: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
          />
          <Input
            placeholder="Source IP/Port"
            value={filterOptions.source}
            onChange={(e) => setFilterOptions({...filterOptions, source: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
          />
          <Input
            placeholder="Destination IP/Port"
            value={filterOptions.destination}
            onChange={(e) => setFilterOptions({...filterOptions, destination: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
          />
          <Input
            placeholder="Min Packet Size"
            value={filterOptions.minLength}
            onChange={(e) => setFilterOptions({...filterOptions, minLength: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
            type="number"
          />
          <Input
            placeholder="Max Packet Size"
            value={filterOptions.maxLength}
            onChange={(e) => setFilterOptions({...filterOptions, maxLength: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
            type="number"
          />
          <Input
            placeholder="Flags (SYN, ACK, FIN...)"
            value={filterOptions.flags}
            onChange={(e) => setFilterOptions({...filterOptions, flags: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
          />
        </div>
      )}
      
      <div className="border border-cyber-border rounded-md overflow-hidden">
        <ScrollArea className="h-[400px]">
          <Table>
            <TableHeader>
              <TableRow className="border-cyber-border bg-cyber-muted bg-opacity-30 hover:bg-cyber-muted">
                <TableHead className="text-cyber-foreground/70 w-12">#</TableHead>
                <TableHead className="text-cyber-foreground/70 w-20">Time</TableHead>
                <TableHead className="text-cyber-foreground/70">Source</TableHead>
                <TableHead className="text-cyber-foreground/70">Destination</TableHead>
                <TableHead className="text-cyber-foreground/70 w-24">Protocol</TableHead>
                <TableHead className="text-cyber-foreground/70 w-16">Length</TableHead>
                <TableHead className="text-cyber-foreground/70">Info</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!safePackets || safePackets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-4 text-cyber-foreground/50">
                    No packet data available
                  </TableCell>
                </TableRow>
              ) : displayedPackets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-4 text-cyber-foreground/50">
                    No packets match the current filters
                  </TableCell>
                </TableRow>
              ) : (
                displayedPackets.map((packet, idx) => (
                  <TableRow 
                    key={`packet-${idx}-${packet.number || idx}`} 
                    className="border-cyber-border hover:bg-cyber-muted hover:bg-opacity-30 cursor-pointer"
                    onClick={() => handlePacketClick(packet)}
                  >
                    <TableCell className="font-mono">{packet.number || (page * pageSize) + idx + 1}</TableCell>
                    <TableCell className="font-mono">{typeof packet.relativeTime === 'string' ? packet.relativeTime : packet.time}</TableCell>
                    <TableCell className="font-mono">{packet.source || 'Unknown'}</TableCell>
                    <TableCell className="font-mono">{packet.destination || 'Unknown'}</TableCell>
                    <TableCell className={`font-mono ${getProtocolColor(packet.protocol)}`}>
                      {packet.protocol || 'Unknown'}
                    </TableCell>
                    <TableCell className="font-mono">{packet.length || 0}</TableCell>
                    <TableCell className="font-mono text-xs max-w-[200px] truncate">
                      {packet.info || (packet.protocol ? `${packet.protocol} Packet` : 'Raw Packet')}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </div>
      
      {/* Pagination controls */}
      <div className="flex justify-between items-center mt-4">
        <div className="text-sm text-cyber-foreground/70">
          Showing {page * pageSize + 1} - {Math.min((page + 1) * pageSize, filteredPackets.length)} of {filteredPackets.length} packets
          {filteredPackets.length !== maxPackets && <span> (filtered from {maxPackets})</span>}
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => setPage(0)} 
            disabled={page === 0}
            className="text-xs"
          >
            First
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => setPage(p => Math.max(0, p - 1))} 
            disabled={page === 0}
            className="text-xs"
          >
            Previous
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => setPage(p => Math.min(Math.ceil(filteredPackets.length / pageSize) - 1, p + 1))} 
            disabled={page >= Math.ceil(filteredPackets.length / pageSize) - 1}
            className="text-xs"
          >
            Next
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => setPage(Math.ceil(filteredPackets.length / pageSize) - 1)} 
            disabled={page >= Math.ceil(filteredPackets.length / pageSize) - 1}
            className="text-xs"
          >
            Last
          </Button>
        </div>
      </div>
      
      {selectedPacket && (
        <div className="mt-4">
          <PacketDetails packet={selectedPacket} onClose={closePacketDetails} />
        </div>
      )}
    </div>
  );
};

export default EnhancedPacketList;
