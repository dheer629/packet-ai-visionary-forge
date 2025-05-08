
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import VisualizationChart from './VisualizationChart';
import { Card } from '@/components/ui/card';

interface AnalysisPanelProps {
  data: any;
}

const AnalysisPanel: React.FC<AnalysisPanelProps> = ({ data }) => {
  // Mock packet data for visualization
  const protocolData = [
    { name: 'TCP', value: 55 },
    { name: 'UDP', value: 25 },
    { name: 'HTTP', value: 15 },
    { name: 'DNS', value: 5 }
  ];

  const timeSeriesData = [
    { time: '00:00', value: 42 },
    { time: '01:00', value: 35 },
    { time: '02:00', value: 20 },
    { time: '03:00', value: 25 },
    { time: '04:00', value: 55 },
    { time: '05:00', value: 65 },
    { time: '06:00', value: 40 }
  ];

  const packetSizeData = [
    { size: '0-100', count: 110 },
    { size: '100-500', count: 65 },
    { size: '500-1000', count: 40 },
    { size: '1000+', count: 15 }
  ];

  return (
    <div>
      <h2 className="text-xl font-bold mb-4 cyber-text">PCAP Analysis Results</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold cyber-text">{data?.summary?.totalPackets || 0}</div>
          <div className="text-xs text-cyber-foreground">Total Packets</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-cyber-secondary">{data?.summary?.ipAddresses || 0}</div>
          <div className="text-xs text-cyber-foreground">Unique IP Addresses</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-cyber-accent">{data?.summary?.conversationCount || 0}</div>
          <div className="text-xs text-cyber-foreground">Conversations</div>
        </Card>
        
        <Card className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted">
          <div className="text-3xl font-bold text-orange-500">{data?.protocols?.length || 0}</div>
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
              data={protocolData} 
              dataKey="value"
            />
            
            <VisualizationChart 
              type="area" 
              title="Packet Timeline" 
              data={timeSeriesData} 
              dataKey="value"
              xAxisKey="time"
            />
            
            <VisualizationChart 
              type="bar" 
              title="Packet Size Distribution" 
              data={packetSizeData} 
              dataKey="count"
              xAxisKey="size"
            />
            
            <div className="cyber-box">
              <h3 className="text-sm font-medium mb-2 cyber-text">File Information</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Filename:</span>
                  <span className="font-mono">{data?.filename || 'N/A'}</span>
                </div>
                <Separator className="bg-cyber-border" />
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Size:</span>
                  <span className="font-mono">
                    {data?.size ? `${(data.size / 1024).toFixed(2)} KB` : 'N/A'}
                  </span>
                </div>
                <Separator className="bg-cyber-border" />
                <div className="flex justify-between">
                  <span className="text-cyber-foreground">Captured on:</span>
                  <span className="font-mono">
                    {data?.timestamp ? new Date(data.timestamp).toLocaleString() : 'N/A'}
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
                  {/* Mock data for demo */}
                  <tr className="border-b border-cyber-border hover:bg-cyber-muted">
                    <td className="py-2 px-4">1</td>
                    <td className="py-2 px-4">0.000000</td>
                    <td className="py-2 px-4">192.168.1.5</td>
                    <td className="py-2 px-4">192.168.1.1</td>
                    <td className="py-2 px-4 text-cyber-primary">TCP</td>
                    <td className="py-2 px-4">74</td>
                  </tr>
                  <tr className="border-b border-cyber-border hover:bg-cyber-muted">
                    <td className="py-2 px-4">2</td>
                    <td className="py-2 px-4">0.000234</td>
                    <td className="py-2 px-4">192.168.1.1</td>
                    <td className="py-2 px-4">192.168.1.5</td>
                    <td className="py-2 px-4 text-cyber-primary">TCP</td>
                    <td className="py-2 px-4">66</td>
                  </tr>
                  <tr className="border-b border-cyber-border hover:bg-cyber-muted">
                    <td className="py-2 px-4">3</td>
                    <td className="py-2 px-4">0.000456</td>
                    <td className="py-2 px-4">192.168.1.5</td>
                    <td className="py-2 px-4">8.8.8.8</td>
                    <td className="py-2 px-4 text-cyber-secondary">DNS</td>
                    <td className="py-2 px-4">86</td>
                  </tr>
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
                  {/* Mock data for demo */}
                  <tr className="border-b border-cyber-border hover:bg-cyber-muted">
                    <td className="py-2 px-4">192.168.1.5</td>
                    <td className="py-2 px-4">192.168.1.1</td>
                    <td className="py-2 px-4">42</td>
                    <td className="py-2 px-4">5832</td>
                    <td className="py-2 px-4">0.0354 sec</td>
                  </tr>
                  <tr className="border-b border-cyber-border hover:bg-cyber-muted">
                    <td className="py-2 px-4">192.168.1.5</td>
                    <td className="py-2 px-4">8.8.8.8</td>
                    <td className="py-2 px-4">12</td>
                    <td className="py-2 px-4">1248</td>
                    <td className="py-2 px-4">0.0128 sec</td>
                  </tr>
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
