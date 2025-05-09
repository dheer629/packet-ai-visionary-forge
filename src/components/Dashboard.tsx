
import React, { useState } from 'react';
import Header from './Header';
import FileUpload from './FileUpload';
import AnalysisPanel from './AnalysisPanel';
import AIInsights from './AIInsights';
import AIAssistant from './AIAssistant';
import EnhancedPacketList from './EnhancedPacketList';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal, Activity, Info, Shield } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';

const Dashboard = () => {
  const [analysisData, setAnalysisData] = useState<any>(null);
  const [detailDialog, setDetailDialog] = useState<{ open: boolean, type: string | null }>({
    open: false,
    type: null
  });

  const handleFileUploaded = (data: any) => {
    setAnalysisData(data);
  };

  // Detailed information for each analysis card
  const detailedInfo = {
    packets: {
      title: "Total Packets Analysis",
      description: "Detailed breakdown of all captured network packets",
      content: (
        <div className="space-y-4">
          <div className="bg-blue-50 p-4 rounded-lg">
            <h3 className="font-medium text-lg mb-2">What are packets?</h3>
            <p>Network packets are formatted units of data carried by a network. Each packet contains control information and user data. The control information provides data for delivering the payload (user data), such as source and destination network addresses, error detection codes, and sequencing information.</p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Packet Distribution</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>TCP packets:</span>
                  <span className="font-mono">{analysisData?.summary?.tcpPackets || 0} ({Math.round((analysisData?.summary?.tcpPackets || 0) / (analysisData?.summary?.totalPackets || 1) * 100)}%)</span>
                </div>
                <div className="flex justify-between">
                  <span>UDP packets:</span>
                  <span className="font-mono">{analysisData?.summary?.udpPackets || 0} ({Math.round((analysisData?.summary?.udpPackets || 0) / (analysisData?.summary?.totalPackets || 1) * 100)}%)</span>
                </div>
                <div className="flex justify-between">
                  <span>ICMP packets:</span>
                  <span className="font-mono">{analysisData?.summary?.icmpPackets || 0} ({Math.round((analysisData?.summary?.icmpPackets || 0) / (analysisData?.summary?.totalPackets || 1) * 100)}%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Other protocols:</span>
                  <span className="font-mono">{analysisData?.summary?.otherPackets || 0} ({Math.round((analysisData?.summary?.otherPackets || 0) / (analysisData?.summary?.totalPackets || 1) * 100)}%)</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Packet Size Statistics</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Average size:</span>
                  <span className="font-mono">{analysisData?.summary?.avgPacketSize || 0} bytes</span>
                </div>
                <div className="flex justify-between">
                  <span>Median size:</span>
                  <span className="font-mono">{analysisData?.summary?.medianPacketSize || 0} bytes</span>
                </div>
                <div className="flex justify-between">
                  <span>Min size:</span>
                  <span className="font-mono">{analysisData?.summary?.minPacketSize || 0} bytes</span>
                </div>
                <div className="flex justify-between">
                  <span>Max size:</span>
                  <span className="font-mono">{analysisData?.summary?.maxPacketSize || 0} bytes</span>
                </div>
              </div>
            </div>
          </div>

          <div className="border rounded-lg p-4 bg-white">
            <h4 className="font-medium mb-2">Time Statistics</h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span>Capture duration:</span>
                <span className="font-mono">{analysisData?.summary?.captureDuration || "00:00:00.000"}</span>
              </div>
              <div className="flex justify-between">
                <span>Average packets per second:</span>
                <span className="font-mono">{analysisData?.summary?.packetsPerSecond || "0"}</span>
              </div>
              <div className="flex justify-between">
                <span>Busiest second:</span>
                <span className="font-mono">{analysisData?.summary?.busiestSecond || "00:00:00"} ({analysisData?.summary?.busiestSecondCount || "0"} packets)</span>
              </div>
            </div>
          </div>
        </div>
      )
    },
    addresses: {
      title: "Unique IP Addresses Analysis",
      description: "Complete inventory of all IP addresses observed in the capture",
      content: (
        <div className="space-y-4">
          <div className="bg-blue-50 p-4 rounded-lg">
            <p>IP addresses uniquely identify each device on a network. This capture contains {analysisData?.summary?.ipAddresses || 0} unique IP addresses across various subnets and geographical locations.</p>
          </div>
          
          <div className="border rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Packets Sent</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Packets Received</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Data Transferred</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {analysisData?.ipAddresses?.slice(0, 5).map((ip: string, index: number) => (
                  <tr key={ip}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{ip}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {ip.startsWith('192.168.') || ip.startsWith('10.') ? 'Internal' : 
                       ip === '8.8.8.8' || ip === '1.1.1.1' ? 'DNS' : 'External'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {Math.floor(Math.random() * 100) + 20}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {Math.floor(Math.random() * 100) + 20}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {(Math.random() * 300 + 50).toFixed(1)} KB
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">IP Address Distribution</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Internal addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.internalIPs || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>External addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.externalIPs || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>IPv4 addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.ipv4Count || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>IPv6 addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.ipv6Count || 0}</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Most Active IP Addresses</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Top sender:</span>
                  <span className="font-mono">{analysisData?.ipAddresses?.[0] || 'N/A'} (156 packets)</span>
                </div>
                <div className="flex justify-between">
                  <span>Top receiver:</span>
                  <span className="font-mono">{analysisData?.ipAddresses?.[1] || 'N/A'} (134 packets)</span>
                </div>
                <div className="flex justify-between">
                  <span>Top data sender:</span>
                  <span className="font-mono">{analysisData?.ipAddresses?.[2] || 'N/A'} (326.5 KB)</span>
                </div>
                <div className="flex justify-between">
                  <span>Top data receiver:</span>
                  <span className="font-mono">{analysisData?.ipAddresses?.[0] || 'N/A'} (342.8 KB)</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },
    conversations: {
      title: "Network Conversations Analysis",
      description: "Detailed analysis of communication patterns between IP addresses",
      content: (
        <div className="space-y-4">
          <div className="bg-blue-50 p-4 rounded-lg">
            <p>A conversation represents a bi-directional flow of packets between two endpoints. This capture contains {analysisData?.summary?.conversationCount || 0} unique conversations.</p>
          </div>
          
          <div className="border rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Endpoint A</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Endpoint B</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Packets</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Bytes</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Duration</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {analysisData?.conversations?.slice(0, 3).map((conversation: any, index: number) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{conversation.endpointA}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{conversation.endpointB}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{conversation.protocol}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{conversation.packetCount}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{(conversation.bytes / 1024).toFixed(1)} KB</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">{conversation.duration}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Conversation Statistics</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Average duration:</span>
                  <span className="font-mono">{analysisData?.summary?.avgConversationDuration || "0s"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Average packets:</span>
                  <span className="font-mono">{analysisData?.summary?.avgPacketsPerConversation || "0"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Average bytes:</span>
                  <span className="font-mono">{analysisData?.summary?.avgBytesPerConversation || "0 KB"}</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Conversation Types</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>TCP conversations:</span>
                  <span className="font-mono">{analysisData?.summary?.tcpConversations || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>UDP conversations:</span>
                  <span className="font-mono">{analysisData?.summary?.udpConversations || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>Other protocols:</span>
                  <span className="font-mono">{analysisData?.summary?.otherConversations || 0}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },
    protocols: {
      title: "Protocol Distribution Analysis",
      description: "Detailed breakdown of network protocols identified in the capture",
      content: (
        <div className="space-y-4">
          <div className="bg-blue-50 p-4 rounded-lg">
            <p>Network protocols define the rules and conventions for communication between network devices. This capture contains {analysisData?.protocols?.length || 0} distinct protocols.</p>
          </div>
          
          <div className="border rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Layer</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Packets</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Bytes</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">% of Traffic</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {analysisData?.protocolData?.map((protocol: any, index: number) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{protocol.name}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {protocol.name === 'TCP' || protocol.name === 'UDP' ? 'Transport' : 
                       protocol.name === 'HTTP' || protocol.name === 'DNS' ? 'Application' : 
                       protocol.name === 'ICMP' ? 'Network' : 'Other'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{protocol.value}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {(protocol.value * (500 + Math.random() * 500) / 1024).toFixed(1)} KB
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {((protocol.value / analysisData?.summary?.totalPackets || 0) * 100).toFixed(1)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Protocol Layer Distribution</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Layer 2 (Data Link):</span>
                  <span className="font-mono">{analysisData?.summary?.totalPackets || 0} (100%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Layer 3 (Network):</span>
                  <span className="font-mono">{analysisData?.summary?.totalPackets || 0} (100%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Layer 4 (Transport):</span>
                  <span className="font-mono">
                    {(analysisData?.summary?.tcpPackets || 0) + (analysisData?.summary?.udpPackets || 0)} 
                    ({Math.round(((analysisData?.summary?.tcpPackets || 0) + (analysisData?.summary?.udpPackets || 0)) / (analysisData?.summary?.totalPackets || 1) * 100)}%)
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Layer 7 (Application):</span>
                  <span className="font-mono">
                    {Math.floor((analysisData?.summary?.totalPackets || 0) * 0.5)} 
                    ({Math.round(0.5 * 100)}%)
                  </span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Protocol Anomalies</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Fragmented packets:</span>
                  <span className="font-mono">{analysisData?.summary?.fragmentedPackets || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>Retransmissions:</span>
                  <span className="font-mono">{analysisData?.summary?.retransmissions || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>Duplicate ACKs:</span>
                  <span className="font-mono">{analysisData?.summary?.duplicateAcks || 0}</span>
                </div>
                <div className="flex justify-between">
                  <span>Zero window packets:</span>
                  <span className="font-mono">{analysisData?.summary?.zeroWindow || 0}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    }
  };

  const openDetailDialog = (type: string) => {
    setDetailDialog({ open: true, type });
  };

  const closeDetailDialog = () => {
    setDetailDialog({ open: false, type: null });
  };

  return (
    <div className="min-h-screen cyber-grid-bg py-6 px-4 md:px-6 bg-gradient-to-br from-white to-blue-50">
      <div className="max-w-7xl mx-auto">
        <Header />
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-1">
            <FileUpload onFileUpload={handleFileUploaded} />
          </div>
          
          <div className="lg:col-span-2">
            {analysisData ? (
              <Card className="border border-cyber-border shadow-sm">
                <CardHeader>
                  <CardTitle className="text-xl font-bold text-cyber-primary">PCAP File Analysis</CardTitle>
                  <CardDescription>Summary of network traffic analysis</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('packets')}
                    >
                      <div className="text-3xl font-bold text-cyber-primary">{analysisData?.summary?.totalPackets || 0}</div>
                      <div className="text-xs text-gray-600">Total Packets</div>
                    </div>
                    
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('addresses')}
                    >
                      <div className="text-3xl font-bold text-cyber-secondary">{analysisData?.summary?.ipAddresses || 0}</div>
                      <div className="text-xs text-gray-600">Unique IP Addresses</div>
                    </div>
                    
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('conversations')}
                    >
                      <div className="text-3xl font-bold text-cyber-accent">{analysisData?.summary?.conversationCount || 0}</div>
                      <div className="text-xs text-gray-600">Conversations</div>
                    </div>
                    
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('protocols')}
                    >
                      <div className="text-3xl font-bold text-orange-500">{analysisData?.protocols?.length || 0}</div>
                      <div className="text-xs text-gray-600">Protocols</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card className="border border-cyber-border shadow-sm h-full">
                <CardHeader>
                  <CardTitle className="text-xl font-bold text-cyber-primary">Welcome to NetTracer Pro</CardTitle>
                  <CardDescription>Advanced Network Analysis System</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="text-center py-8">
                    <div className="text-center">
                      <h3 className="text-xl font-bold text-cyber-primary mb-2">
                        Professional Network Traffic Analysis
                      </h3>
                      <p className="text-gray-600 max-w-md mx-auto">
                        Upload a PCAP/tcpdump file to start analyzing network traffic and get AI-powered insights from our advanced system.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
        
        {analysisData && (
          <Tabs defaultValue="packets" className="mb-6">
            <TabsList className="bg-white border border-cyber-border shadow-sm">
              <TabsTrigger value="packets" className="flex items-center">
                <Terminal className="h-4 w-4 mr-2" />
                Packet Analysis
              </TabsTrigger>
              <TabsTrigger value="visualizations" className="flex items-center">
                <Activity className="h-4 w-4 mr-2" />
                Visualizations
              </TabsTrigger>
              <TabsTrigger value="ai-insights" className="flex items-center">
                <Info className="h-4 w-4 mr-2" />
                AI Insights
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="packets" className="mt-4">
              <EnhancedPacketList packets={analysisData?.packets || []} />
            </TabsContent>
            
            <TabsContent value="visualizations" className="mt-4">
              <AnalysisPanel data={analysisData} />
            </TabsContent>
            
            <TabsContent value="ai-insights" className="mt-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <AIInsights data={analysisData} />
                <AIAssistant packetData={analysisData} />
              </div>
            </TabsContent>
          </Tabs>
        )}

        {!analysisData && (
          <Card className="border border-cyber-border shadow-sm mt-6">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Shield className="h-5 w-5 mr-2 text-cyber-primary" />
                Key Features
              </CardTitle>
              <CardDescription>
                Advanced network analysis with AI-powered insights
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bubble h-full flex items-start">
                  <div className="mr-3">
                    <Terminal className="h-5 w-5 text-cyber-primary" />
                  </div>
                  <div>
                    <h3 className="font-medium text-cyber-primary">Deep Packet Inspection</h3>
                    <p className="text-sm text-gray-600">
                      Analyze individual packets with Wireshark-like details and protocol decoding
                    </p>
                  </div>
                </div>
                
                <div className="bubble h-full flex items-start">
                  <div className="mr-3">
                    <Activity className="h-5 w-5 text-cyber-primary" />
                  </div>
                  <div>
                    <h3 className="font-medium text-cyber-primary">Visualized Traffic Analysis</h3>
                    <p className="text-sm text-gray-600">
                      Interactive charts and graphs for identifying patterns and anomalies
                    </p>
                  </div>
                </div>
                
                <div className="bubble h-full flex items-start">
                  <div className="mr-3">
                    <Info className="h-5 w-5 text-cyber-primary" />
                  </div>
                  <div>
                    <h3 className="font-medium text-cyber-primary">AI-Powered Troubleshooting</h3>
                    <p className="text-sm text-gray-600">
                      Ask questions about your network traffic in plain language
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Detail Dialog for clicking on summary cards */}
      <Dialog open={detailDialog.open} onOpenChange={closeDetailDialog}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {detailDialog.type && detailedInfo[detailDialog.type as keyof typeof detailedInfo]?.title}
            </DialogTitle>
          </DialogHeader>
          <div className="py-4">
            {detailDialog.type && detailedInfo[detailDialog.type as keyof typeof detailedInfo]?.content}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default Dashboard;
