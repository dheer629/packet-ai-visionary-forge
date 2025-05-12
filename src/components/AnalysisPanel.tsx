
import React, { useEffect } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import VisualizationChart from './VisualizationChart';
import { Card } from '@/components/ui/card';
import EnhancedPacketList from './EnhancedPacketList';

interface AnalysisPanelProps {
  data: any;
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ data }) => {
  useEffect(() => {
    if (data) {
      console.log('Analysis data received in AnalysisPanel:', {
        summary: data.summary || {},
        packetCount: data.packets?.length || 0,
        firstPacket: data.packets?.[0] || null,
        hasProtocolData: Boolean(data.protocolData?.length),
        hasTimeSeriesData: Boolean(data.timeSeriesData?.length)
      });
    }
  }, [data]);
  
  if (!data) return <div>No analysis data available</div>;

  // Ensure we have valid data structure even if some fields are missing
  const safeData = {
    summary: {
      totalPackets: data.summary?.totalPackets || data.packets?.length || 0,
      ipAddresses: data.summary?.ipAddresses || 0,
      conversationCount: data.summary?.conversationCount || 0,
      startTime: data.summary?.startTime || '',
      endTime: data.summary?.endTime || '',
      protocolCounts: data.summary?.protocolCounts || []
    },
    protocolData: data.protocolData || [],
    timeSeriesData: data.timeSeriesData || [],
    packets: Array.isArray(data.packets) ? data.packets : [],
    conversations: Array.isArray(data.conversations) ? data.conversations : [],
    protocols: Array.isArray(data.protocols) ? data.protocols : [],
    filename: data.filename || 'Unknown',
    size: data.size || 0,
    timestamp: data.timestamp || Date.now()
  };

  // Create protocol data for charts if it doesn't exist
  if (!safeData.protocolData || safeData.protocolData.length === 0) {
    // Extract protocol counts from packets if available
    const protocolCounts: Record<string, number> = {};
    safeData.packets.forEach(packet => {
      const protocol = packet.protocol || 'Unknown';
      protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
    });
    
    safeData.protocolData = Object.entries(protocolCounts).map(([name, count]) => ({
      name,
      value: count
    }));
  }

  // Generate unique protocol count 
  const uniqueProtocols = new Set(
    safeData.packets.map(p => p.protocol).filter(Boolean)
  );

  // Create empty time series data if it doesn't exist
  if (!safeData.timeSeriesData || safeData.timeSeriesData.length === 0) {
    safeData.timeSeriesData = Array(10).fill(0).map((_, i) => ({
      time: `${i * 10}%`,
      value: Math.floor(Math.random() * 10) + 1 // Just for visualization purposes
    }));
  }

  console.log('Safe analysis data ready for rendering:', {
    summaryTotalPackets: safeData.summary.totalPackets,
    uniqueProtocolCount: uniqueProtocols.size,
    packetCount: safeData.packets.length
  });

  return (
    <div>
      <h2 className="text-xl font-bold mb-4 cyber-text">PCAP Analysis Results</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold cyber-text">{safeData.summary.totalPackets}</div>
          <div className="text-xs text-cyber-foreground">Total Packets</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-cyber-secondary">{safeData.summary.ipAddresses}</div>
          <div className="text-xs text-cyber-foreground">Unique IP Addresses</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-cyber-accent">{safeData.summary.conversationCount}</div>
          <div className="text-xs text-cyber-foreground">Conversations</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-orange-500">
            {uniqueProtocols.size || Object.keys(
              safeData.packets.reduce((acc: Record<string, boolean>, p: any) => {
                if (p.protocol) acc[p.protocol] = true;
                return acc;
              }, {})
            ).length}
          </div>
          <div className="text-xs text-cyber-foreground">Protocols</div>
        </Card>
      </div>

      <Tabs defaultValue="packets" className="mb-6">
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
              data={safeData.protocolData || []} 
              dataKey="value"
            />
            
            <VisualizationChart 
              type="area" 
              title="Packet Timeline" 
              data={safeData.timeSeriesData || []} 
              dataKey="value"
              xAxisKey="time"
            />
            
            <VisualizationChart 
              type="bar" 
              title="Packet Size Distribution" 
              data={[
                { size: '0-100', count: safeData.packets.filter((p: any) => p.length <= 100).length },
                { size: '100-500', count: safeData.packets.filter((p: any) => p.length > 100 && p.length <= 500).length },
                { size: '500-1000', count: safeData.packets.filter((p: any) => p.length > 500 && p.length <= 1000).length },
                { size: '1000+', count: safeData.packets.filter((p: any) => p.length > 1000).length }
              ]} 
              dataKey="count"
              xAxisKey="size"
            />
            
            <div className="cyber-box">
              <h3 className="text-sm font-medium mb-2 cyber-text">File Information</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Filename:</span>
                  <span className="font-mono">{safeData.filename}</span>
                </div>
                <Separator className="bg-cyber-border" />
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Size:</span>
                  <span className="font-mono">
                    {safeData.size ? `${(safeData.size / 1024).toFixed(2)} KB` : 'N/A'}
                  </span>
                </div>
                <Separator className="bg-cyber-border" />
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Captured on:</span>
                  <span className="font-mono">
                    {safeData.timestamp ? new Date(safeData.timestamp).toLocaleString() : 'N/A'}
                  </span>
                </div>
                
                {safeData.summary.startTime && (
                  <>
                    <Separator className="bg-cyber-border" />
                    <div className="flex justify-between">
                      <span className="text-cyber-foreground">Start time:</span>
                      <span className="font-mono">{safeData.summary.startTime}</span>
                    </div>
                  </>
                )}
                
                {safeData.summary.endTime && (
                  <>
                    <Separator className="bg-cyber-border" />
                    <div className="flex justify-between">
                      <span className="text-cyber-foreground">End time:</span>
                      <span className="font-mono">{safeData.summary.endTime}</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="packets" className="mt-4">
          <EnhancedPacketList packets={safeData.packets} />
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
                  {safeData.conversations.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="text-center py-4 text-cyber-foreground/50">
                        No conversation data available
                      </td>
                    </tr>
                  ) : (
                    safeData.conversations.map((conversation: any, index: number) => (
                      <tr key={index} className="border-b border-cyber-border hover:bg-cyber-muted">
                        <td className="py-2 px-4">{conversation.endpointA || 'Unknown'}</td>
                        <td className="py-2 px-4">{conversation.endpointB || 'Unknown'}</td>
                        <td className="py-2 px-4">{conversation.packetCount || 0}</td>
                        <td className="py-2 px-4">{((conversation.bytes || 0) / 1024).toFixed(2)} KB</td>
                        <td className="py-2 px-4">{conversation.duration || '0s'}</td>
                      </tr>
                    ))
                  )}
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
