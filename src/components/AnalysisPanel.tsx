
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import VisualizationChart from './VisualizationChart';
import { Card } from '@/components/ui/card';

interface AnalysisPanelProps {
  data: any;
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ data }) => {
  if (!data) return <div>No analysis data available</div>;

  return (
    <div>
      <h2 className="text-xl font-bold mb-4 cyber-text">PCAP Analysis Results</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold cyber-text">{data.summary.totalPackets}</div>
          <div className="text-xs text-cyber-foreground">Total Packets</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-cyber-secondary">{data.summary.ipAddresses}</div>
          <div className="text-xs text-cyber-foreground">Unique IP Addresses</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-cyber-accent">{data.summary.conversationCount}</div>
          <div className="text-xs text-cyber-foreground">Conversations</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-orange-500">{data.protocols.length}</div>
          <div className="text-xs text-cyber-foreground">Protocols</div>
        </Card>
      </div>

      <Tabs defaultValue="overview" className="mb-6">
        <TabsList className="bg-cyber-muted border border-cyber-border">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="packets">Packets</TabsTrigger>
          <TabsTrigger value="conversations">Conversations</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <VisualizationChart 
              type="pie" 
              title="Protocol Distribution" 
              data={data.protocolData || []} 
              dataKey="value"
            />
            
            <VisualizationChart 
              type="area" 
              title="Packet Timeline" 
              data={data.timeSeriesData || []} 
              dataKey="value"
              xAxisKey="time"
            />
            
            <VisualizationChart 
              type="bar" 
              title="Packet Size Distribution" 
              data={[
                { size: '0-100', count: data.packets.filter((p: any) => p.length <= 100).length },
                { size: '100-500', count: data.packets.filter((p: any) => p.length > 100 && p.length <= 500).length },
                { size: '500-1000', count: data.packets.filter((p: any) => p.length > 500 && p.length <= 1000).length },
                { size: '1000+', count: data.packets.filter((p: any) => p.length > 1000).length }
              ]} 
              dataKey="count"
              xAxisKey="size"
            />
            
            <div className="cyber-box">
              <h3 className="text-sm font-medium mb-2 cyber-text">File Information</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Filename:</span>
                  <span className="font-mono">{data.filename}</span>
                </div>
                <Separator className="bg-cyber-border" />
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Size:</span>
                  <span className="font-mono">
                    {data.size ? `${(data.size / 1024).toFixed(2)} KB` : 'N/A'}
                  </span>
                </div>
                <Separator className="bg-cyber-border" />
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Captured on:</span>
                  <span className="font-mono">
                    {data.timestamp ? new Date(data.timestamp).toLocaleString() : 'N/A'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="packets" className="mt-4">
          <div className="cyber-box">
            <h3 className="text-sm font-medium mb-4 cyber-text">Packet List</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-cyber-border">
                    <th className="py-2 px-4 text-left text-cyber-secondary">#</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Time</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Source</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Destination</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Protocol</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Length</th>
                  </tr>
                </thead>
                <tbody>
                  {data.packets.slice(0, 20).map((packet: any) => (
                    <tr key={packet.number} className="border-b border-cyber-border hover:bg-cyber-muted">
                      <td className="py-2 px-4">{packet.number}</td>
                      <td className="py-2 px-4">{packet.time}</td>
                      <td className="py-2 px-4">{packet.source}</td>
                      <td className="py-2 px-4">{packet.destination}</td>
                      <td className="py-2 px-4 text-cyber-primary">{packet.protocol}</td>
                      <td className="py-2 px-4">{packet.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="conversations" className="mt-4">
          <div className="cyber-box">
            <h3 className="text-sm font-medium mb-4 cyber-text">Conversations</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-cyber-border">
                    <th className="py-2 px-4 text-left text-cyber-secondary">Address A</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Address B</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Packets</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Bytes</th>
                    <th className="py-2 px-4 text-left text-cyber-secondary">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {data.conversations?.map((conversation: any, index: number) => (
                    <tr key={index} className="border-b border-cyber-border hover:bg-cyber-muted">
                      <td className="py-2 px-4">{conversation.endpointA}</td>
                      <td className="py-2 px-4">{conversation.endpointB}</td>
                      <td className="py-2 px-4">{conversation.packetCount}</td>
                      <td className="py-2 px-4">{(conversation.bytes / 1024).toFixed(2)} KB</td>
                      <td className="py-2 px-4">{conversation.duration}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AnalysisPanel;
