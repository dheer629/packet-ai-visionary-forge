
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import HexView from './HexView';

interface PacketDetailsProps {
  packet: any;
  onClose: () => void;
}

type FieldValue = string | number | undefined | null;

/** Renders only values that were actually decoded from the captured bytes. */
const HeaderBlock: React.FC<{ title: string; rows: [string, FieldValue][] }> = ({ title, rows }) => (
  <div>
    <h4 className="text-sm font-medium text-cyber-accent">{title}</h4>
    <div className="grid grid-cols-2 gap-2 p-2 bg-cyber-muted bg-opacity-20 rounded text-xs">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <p>{label}:</p>
          {value === undefined || value === null || value === '' ? (
            <p className="font-mono text-cyber-foreground/40">Unavailable</p>
          ) : (
            <p className="font-mono break-all">{String(value)}</p>
          )}
        </div>
      ))}
    </div>
  </div>
);

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
          <HexView packet={packet} />
        </TabsContent>
        
        <TabsContent value="ascii" className="mt-4">
          <ScrollArea className="h-60">
            <div className="font-mono text-xs whitespace-pre p-2">
              {packet.asciiDump || "No ASCII payload captured for this packet."}
            </div>
          </ScrollArea>
        </TabsContent>

        
        <TabsContent value="headers" className="mt-4">
          <ScrollArea className="h-60">
            <div className="space-y-3">
              {packet.ethernet && (
                <HeaderBlock
                  title="Ethernet Header"
                  rows={[
                    ['Destination MAC', packet.ethernet.destMac],
                    ['Source MAC', packet.ethernet.srcMac],
                    ['Type', packet.ethernet.type],
                  ]}
                />
              )}

              {packet.vlan && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="802.1Q VLAN Header"
                    rows={[
                      ['VLAN ID', packet.vlan.id],
                      ['Priority', packet.vlan.priority],
                    ]}
                  />
                </div>
              )}

              {packet.ip && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="IP Header"
                    rows={[
                      ['Version', packet.ip.version],
                      ['Header Length', packet.ip.headerLength],
                      ['TTL', packet.ip.ttl],
                      ['Protocol', packet.ip.protocol],
                      ['Source', packet.ip.source],
                      ['Destination', packet.ip.destination],
                    ]}
                  />
                </div>
              )}

              {packet.ipv6 && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="IPv6 Header"
                    rows={[
                      ['Version', packet.ipv6.version],
                      ['Flow Label', packet.ipv6.flowLabel],
                      ['Hop Limit', packet.ipv6.hopLimit],
                      ['Next Header', packet.ipv6.nextHeader],
                      ['Source', packet.ipv6.source],
                      ['Destination', packet.ipv6.destination],
                    ]}
                  />
                </div>
              )}

              {packet.tcp && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="TCP Header"
                    rows={[
                      ['Source Port', packet.tcp.srcPort],
                      ['Destination Port', packet.tcp.dstPort],
                      ['Sequence Number', packet.tcp.seq],
                      ['ACK Number', packet.tcp.ack],
                      ['Flags', packet.tcp.flags],
                      ['Window Size', packet.tcp.window],
                    ]}
                  />
                </div>
              )}

              {packet.udp && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="UDP Header"
                    rows={[
                      ['Source Port', packet.udp.srcPort],
                      ['Destination Port', packet.udp.dstPort],
                      ['Length', packet.udp.length],
                    ]}
                  />
                </div>
              )}

              {packet.icmp && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="ICMP Header"
                    rows={[
                      ['Type', packet.icmp.type],
                      ['Code', packet.icmp.code],
                      ['Description', packet.icmp.typeName],
                    ]}
                  />
                </div>
              )}

              {packet.arp && (
                <div>
                  <Separator className="bg-cyber-border" />
                  <HeaderBlock
                    title="ARP Header"
                    rows={[
                      ['Operation', packet.arp.operation],
                      ['Sender MAC', packet.arp.senderMac],
                      ['Sender IP', packet.arp.senderIP],
                      ['Target MAC', packet.arp.targetMac],
                      ['Target IP', packet.arp.targetIP],
                    ]}
                  />
                </div>
              )}

              {!packet.ethernet && !packet.ip && !packet.ipv6 && !packet.tcp && !packet.udp && !packet.icmp && !packet.arp && (
                <p className="text-xs text-cyber-foreground/70">
                  No header fields were decoded from the captured bytes of this packet.
                </p>
              )}
            </div>
          </ScrollArea>
        </TabsContent>
        
        <TabsContent value="layers" className="mt-4">
          <ScrollArea className="h-60">
            {packet.decodedLayers?.length ? (
              <div className="space-y-2 pr-2">
                {packet.protocolStack?.length > 0 && (
                  <p className="font-mono text-xs text-cyber-secondary">
                    {packet.protocolStack.join(' → ')}
                  </p>
                )}
                {packet.decodedLayers.map((layer: any, idx: number) => (
                  <div key={idx} className="rounded bg-cyber-muted bg-opacity-20 p-2">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-mono text-sm text-cyber-accent">{layer.name}</span>
                      <span className="font-mono text-[10px] text-cyber-foreground/60">
                        offset {layer.offset}
                        {layer.length ? ` · ${layer.length} bytes` : ''}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
                      {Object.entries(layer.fields || {}).map(([k, v]) => (
                        <div key={k} className="contents">
                          <p className="text-cyber-foreground/70">{k}</p>
                          <p className="font-mono break-all">{String(v)}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                {packet.truncated && (
                  <p className="text-xs text-cyber-accent">
                    Frame was truncated in the capture — decoding stopped at the last complete header.
                  </p>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                {(packet.layers || []).map((layer: string, idx: number) => (
                  <div key={idx} className="flex items-center space-x-2 rounded bg-cyber-muted bg-opacity-20 p-2">
                    <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-primary bg-opacity-30 text-xs">{idx + 1}</span>
                    <span className="font-mono text-sm">{layer}</span>
                  </div>
                ))}
                {!packet.layers?.length && (
                  <p className="text-xs text-cyber-foreground/70">No decoded layers available for this packet.</p>
                )}
              </div>
            )}
          </ScrollArea>
        </TabsContent>

      </Tabs>
    </div>
  );
};

export default PacketDetails;
