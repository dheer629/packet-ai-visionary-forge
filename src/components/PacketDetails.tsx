
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';

interface PacketDetailsProps {
  packet: any;
  onClose: () => void;
}

const PacketDetails: React.FC<PacketDetailsProps> = ({ packet, onClose }) => {
  if (!packet) return null;

  return (
    <div className="cyber-box bg-cyber-background border border-cyber-border p-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium cyber-text">Packet #{packet.number}</h3>
        <button 
          onClick={onClose} 
          className="text-cyber-foreground/70 hover:text-cyber-foreground"
        >
          ×
        </button>
      </div>
      
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="bg-cyber-muted bg-opacity-30 p-2 rounded">
          <p className="text-xs text-cyber-foreground/70">Source</p>
          <p className="font-mono text-sm">{packet.source}</p>
        </div>
        <div className="bg-cyber-muted bg-opacity-30 p-2 rounded">
          <p className="text-xs text-cyber-foreground/70">Destination</p>
          <p className="font-mono text-sm">{packet.destination}</p>
        </div>
        <div className="bg-cyber-muted bg-opacity-30 p-2 rounded">
          <p className="text-xs text-cyber-foreground/70">Protocol</p>
          <p className="font-mono text-sm text-cyber-primary">{packet.protocol}</p>
        </div>
        <div className="bg-cyber-muted bg-opacity-30 p-2 rounded">
          <p className="text-xs text-cyber-foreground/70">Length</p>
          <p className="font-mono text-sm">{packet.length} bytes</p>
        </div>
      </div>
      
      <Tabs defaultValue="hex">
        <TabsList className="bg-cyber-muted border border-cyber-border">
          <TabsTrigger value="hex">Hexadecimal</TabsTrigger>
          <TabsTrigger value="ascii">ASCII</TabsTrigger>
          <TabsTrigger value="headers">Headers</TabsTrigger>
          <TabsTrigger value="layers">Protocol Layers</TabsTrigger>
        </TabsList>
        
        <TabsContent value="hex" className="mt-4">
          <ScrollArea className="h-60">
            <div className="font-mono text-xs whitespace-pre p-2">
              {packet.hexDump || "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n0000: 45 00 00 73 00 00 40 00 40 11 B8 61 C0 A8 00 01\n0010: C0 A8 00 C7 00 35 E1 15 00 5F 96 9B 84 00 00 01"}
            </div>
          </ScrollArea>
        </TabsContent>
        
        <TabsContent value="ascii" className="mt-4">
          <ScrollArea className="h-60">
            <div className="font-mono text-xs whitespace-pre p-2">
              {packet.asciiDump || "E..s..@.@..a....\n.....5..._......."}
            </div>
          </ScrollArea>
        </TabsContent>
        
        <TabsContent value="headers" className="mt-4">
          <ScrollArea className="h-60">
            <div className="space-y-3">
              {packet.ethernet && (
                <div>
                  <h4 className="text-sm font-medium text-cyber-accent">Ethernet Header</h4>
                  <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                    <p>Destination MAC:</p>
                    <p className="font-mono">{packet.ethernet?.destMac || "00:1A:2B:3C:4D:5E"}</p>
                    <p>Source MAC:</p>
                    <p className="font-mono">{packet.ethernet?.srcMac || "AA:BB:CC:DD:EE:FF"}</p>
                    <p>Type:</p>
                    <p className="font-mono">{packet.ethernet?.type || "0x0800 (IPv4)"}</p>
                  </div>
                </div>
              )}
              
              {packet.vlan && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">802.1Q VLAN Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>VLAN ID:</p>
                      <p className="font-mono">{packet.vlan?.id || "0"}</p>
                      <p>Priority:</p>
                      <p className="font-mono">{packet.vlan?.priority || "0"}</p>
                    </div>
                  </div>
                </>
              )}
              
              {packet.ip && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">IP Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>Version:</p>
                      <p className="font-mono">{packet.ip?.version || "4"}</p>
                      <p>Header Length:</p>
                      <p className="font-mono">{packet.ip?.headerLength || "20 bytes"}</p>
                      <p>TTL:</p>
                      <p className="font-mono">{packet.ip?.ttl || "64"}</p>
                      <p>Protocol:</p>
                      <p className="font-mono">{packet.ip?.protocol || "TCP (6)"}</p>
                      <p>Source:</p>
                      <p className="font-mono">{packet.ip?.source || packet.source}</p>
                      <p>Destination:</p>
                      <p className="font-mono">{packet.ip?.destination || packet.destination}</p>
                    </div>
                  </div>
                </>
              )}

              {packet.ipv6 && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">IPv6 Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>Version:</p>
                      <p className="font-mono">{packet.ipv6?.version || "6"}</p>
                      <p>Flow Label:</p>
                      <p className="font-mono">{packet.ipv6?.flowLabel || "0"}</p>
                      <p>Hop Limit:</p>
                      <p className="font-mono">{packet.ipv6?.hopLimit || "64"}</p>
                      <p>Next Header:</p>
                      <p className="font-mono">{packet.ipv6?.nextHeader || "6"}</p>
                      <p>Source:</p>
                      <p className="font-mono">{packet.ipv6?.source || packet.source}</p>
                      <p>Destination:</p>
                      <p className="font-mono">{packet.ipv6?.destination || packet.destination}</p>
                    </div>
                  </div>
                </>
              )}
              
              {packet.tcp && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">TCP Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>Source Port:</p>
                      <p className="font-mono">{packet.tcp?.srcPort || "443"}</p>
                      <p>Destination Port:</p>
                      <p className="font-mono">{packet.tcp?.dstPort || "52134"}</p>
                      <p>Sequence Number:</p>
                      <p className="font-mono">{packet.tcp?.seq || "1234567890"}</p>
                      <p>ACK Number:</p>
                      <p className="font-mono">{packet.tcp?.ack || "0987654321"}</p>
                      <p>Flags:</p>
                      <p className="font-mono">{packet.tcp?.flags || "SYN ACK"}</p>
                      <p>Window Size:</p>
                      <p className="font-mono">{packet.tcp?.window || "8192"}</p>
                    </div>
                  </div>
                </>
              )}

              {packet.udp && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">UDP Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>Source Port:</p>
                      <p className="font-mono">{packet.udp?.srcPort || "53"}</p>
                      <p>Destination Port:</p>
                      <p className="font-mono">{packet.udp?.dstPort || "12345"}</p>
                      <p>Length:</p>
                      <p className="font-mono">{packet.udp?.length || "8"} bytes</p>
                    </div>
                  </div>
                </>
              )}

              {packet.icmp && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">ICMP Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>Type:</p>
                      <p className="font-mono">{packet.icmp?.type || "8"}</p>
                      <p>Code:</p>
                      <p className="font-mono">{packet.icmp?.code || "0"}</p>
                      <p>Description:</p>
                      <p className="font-mono">{packet.icmp?.typeName || "Echo Request"}</p>
                    </div>
                  </div>
                </>
              )}

              {packet.arp && (
                <>
                  <Separator className="bg-cyber-border" />
                  <div>
                    <h4 className="text-sm font-medium text-cyber-accent">ARP Header</h4>
                    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
                      <p>Operation:</p>
                      <p className="font-mono">{packet.arp?.operation || "Request"}</p>
                      <p>Sender MAC:</p>
                      <p className="font-mono">{packet.arp?.senderMac || "00:00:00:00:00:00"}</p>
                      <p>Sender IP:</p>
                      <p className="font-mono">{packet.arp?.senderIP || "0.0.0.0"}</p>
                      <p>Target MAC:</p>
                      <p className="font-mono">{packet.arp?.targetMac || "00:00:00:00:00:00"}</p>
                      <p>Target IP:</p>
                      <p className="font-mono">{packet.arp?.targetIP || "0.0.0.0"}</p>
                    </div>
                  </div>
                </>
              )}
            </div>
          </ScrollArea>
        </TabsContent>
        
        <TabsContent value="layers" className="mt-4">
          <ScrollArea className="h-60">
            <div className="space-y-2">
              {(packet.layers || ['Ethernet', 'IP', 'TCP', 'TLS']).map((layer: string, idx: number) => (
                <div key={idx} className="flex items-center space-x-2 p-2 bg-cyber-muted bg-opacity-20 rounded">
                  <span className="w-6 h-6 flex items-center justify-center bg-cyber-primary bg-opacity-30 rounded-full text-xs">{idx+1}</span>
                  <span className="font-mono text-sm">{layer}</span>
                </div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default PacketDetails;
