
import React, { useState, useMemo } from 'react';
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
  
  // Filter packets based on search term and filters - memoized for performance
  const filteredPackets = useMemo(() => {
    return packets.filter(packet => {
      // Search filter
      if (filter && 
          !Object.values(packet).some(val => 
            val?.toString().toLowerCase().includes(filter.toLowerCase())
          )) {
        return false;
      }
      
      // Protocol filter
      if (filterOptions.protocol && 
          !packet.protocol.toLowerCase().includes(filterOptions.protocol.toLowerCase())) {
        return false;
      }
      
      // Source filter
      if (filterOptions.source && 
          !packet.source.includes(filterOptions.source)) {
        return false;
      }
      
      // Destination filter
      if (filterOptions.destination && 
          !packet.destination.includes(filterOptions.destination)) {
        return false;
      }
      
      // Min length filter
      if (filterOptions.minLength && 
          packet.length < parseInt(filterOptions.minLength)) {
        return false;
      }
      
      // Max length filter
      if (filterOptions.maxLength && 
          packet.length > parseInt(filterOptions.maxLength)) {
        return false;
      }
      
      // Flag filter (in info field)
      if (filterOptions.flags && 
          !packet.info.toLowerCase().includes(filterOptions.flags.toLowerCase())) {
        return false;
      }
      
      return true;
    });
  }, [packets, filter, filterOptions]);

  const handlePacketClick = (packet: any) => {
    setSelectedPacket(packet);
    console.log('Selected packet details:', packet);
  };

  const closePacketDetails = () => {
    setSelectedPacket(null);
  };

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toUpperCase()) {
      case 'TCP': return 'text-cyber-primary';
      case 'UDP': return 'text-green-500';
      case 'ICMP': return 'text-orange-500';
      case 'DNS': return 'text-cyber-secondary';
      case 'HTTP': return 'text-blue-500';
      case 'HTTPS': return 'text-emerald-400';
      case 'ARP': return 'text-purple-500';
      case 'IPV6': return 'text-pink-500';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="cyber-box">
      <div className="flex flex-col mb-4">
        <div className="flex justify-between items-center mb-2">
          <h3 className="text-sm font-medium cyber-text">Packet Capture</h3>
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
            placeholder="Source IP"
            value={filterOptions.source}
            onChange={(e) => setFilterOptions({...filterOptions, source: e.target.value})}
            className="text-xs bg-cyber-muted border-cyber-border"
          />
          <Input
            placeholder="Destination IP"
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
              {filteredPackets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-4 text-cyber-foreground/50">
                    {packets.length === 0 ? 'No packet data available' : 'No packets match the current filters'}
                  </TableCell>
                </TableRow>
              ) : (
                filteredPackets.map((packet) => (
                  <TableRow 
                    key={packet.number} 
                    className="border-cyber-border hover:bg-cyber-muted hover:bg-opacity-30 cursor-pointer"
                    onClick={() => handlePacketClick(packet)}
                  >
                    <TableCell className="font-mono">{packet.number}</TableCell>
                    <TableCell className="font-mono">{typeof packet.relativeTime === 'string' ? packet.relativeTime : packet.time}</TableCell>
                    <TableCell className="font-mono">{packet.source}</TableCell>
                    <TableCell className="font-mono">{packet.destination}</TableCell>
                    <TableCell className={`font-mono ${getProtocolColor(packet.protocol)}`}>{packet.protocol}</TableCell>
                    <TableCell className="font-mono">{packet.length}</TableCell>
                    <TableCell className="font-mono text-xs max-w-[200px] truncate">{packet.info}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>
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
