
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
                  <span className="font-mono">{analysisData?.summary?.tcpPackets || 284} ({Math.round((analysisData?.summary?.tcpPackets || 284) / (analysisData?.summary?.totalPackets || 348) * 100)}%)</span>
                </div>
                <div className="flex justify-between">
                  <span>UDP packets:</span>
                  <span className="font-mono">{analysisData?.summary?.udpPackets || 43} ({Math.round((analysisData?.summary?.udpPackets || 43) / (analysisData?.summary?.totalPackets || 348) * 100)}%)</span>
                </div>
                <div className="flex justify-between">
                  <span>ICMP packets:</span>
                  <span className="font-mono">{analysisData?.summary?.icmpPackets || 12} ({Math.round((analysisData?.summary?.icmpPackets || 12) / (analysisData?.summary?.totalPackets || 348) * 100)}%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Other protocols:</span>
                  <span className="font-mono">{analysisData?.summary?.otherPackets || 9} ({Math.round((analysisData?.summary?.otherPackets || 9) / (analysisData?.summary?.totalPackets || 348) * 100)}%)</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Packet Size Statistics</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Average size:</span>
                  <span className="font-mono">{analysisData?.summary?.avgPacketSize || 732} bytes</span>
                </div>
                <div className="flex justify-between">
                  <span>Median size:</span>
                  <span className="font-mono">{analysisData?.summary?.medianPacketSize || 586} bytes</span>
                </div>
                <div className="flex justify-between">
                  <span>Min size:</span>
                  <span className="font-mono">{analysisData?.summary?.minPacketSize || 64} bytes</span>
                </div>
                <div className="flex justify-between">
                  <span>Max size:</span>
                  <span className="font-mono">{analysisData?.summary?.maxPacketSize || 1500} bytes</span>
                </div>
              </div>
            </div>
          </div>

          <div className="border rounded-lg p-4 bg-white">
            <h4 className="font-medium mb-2">Time Statistics</h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span>Capture duration:</span>
                <span className="font-mono">{analysisData?.summary?.captureDuration || "00:05:34.521"}</span>
              </div>
              <div className="flex justify-between">
                <span>Average packets per second:</span>
                <span className="font-mono">{analysisData?.summary?.packetsPerSecond || "104.2"}</span>
              </div>
              <div className="flex justify-between">
                <span>Busiest second:</span>
                <span className="font-mono">{analysisData?.summary?.busiestSecond || "00:02:15"} ({analysisData?.summary?.busiestSecondCount || "246"} packets)</span>
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
            <p>IP addresses uniquely identify each device on a network. This capture contains {analysisData?.summary?.ipAddresses || 25} unique IP addresses across various subnets and geographical locations.</p>
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
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">192.168.1.5</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Internal</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">156</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">134</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">246.8 KB</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">192.168.1.1</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Gateway</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">78</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">103</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">154.2 KB</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">8.8.8.8</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">External (DNS)</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">12</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">12</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">4.8 KB</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">93.184.216.34</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">External (Web)</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">24</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">42</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">326.5 KB</td>
                </tr>
              </tbody>
            </table>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">IP Address Distribution</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Internal addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.internalIPs || 8}</span>
                </div>
                <div className="flex justify-between">
                  <span>External addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.externalIPs || 17}</span>
                </div>
                <div className="flex justify-between">
                  <span>IPv4 addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.ipv4Count || 23}</span>
                </div>
                <div className="flex justify-between">
                  <span>IPv6 addresses:</span>
                  <span className="font-mono">{analysisData?.summary?.ipv6Count || 2}</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Most Active IP Addresses</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Top sender:</span>
                  <span className="font-mono">192.168.1.5 (156 packets)</span>
                </div>
                <div className="flex justify-between">
                  <span>Top receiver:</span>
                  <span className="font-mono">192.168.1.5 (134 packets)</span>
                </div>
                <div className="flex justify-between">
                  <span>Top data sender:</span>
                  <span className="font-mono">93.184.216.34 (326.5 KB)</span>
                </div>
                <div className="flex justify-between">
                  <span>Top data receiver:</span>
                  <span className="font-mono">192.168.1.5 (342.8 KB)</span>
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
            <p>A conversation represents a bi-directional flow of packets between two endpoints. This capture contains {analysisData?.summary?.conversationCount || 14} unique conversations.</p>
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
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">192.168.1.5:52134</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">93.184.216.34:443</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">TCP/TLS</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">86</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">325.6 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">4.35s</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">192.168.1.5:53412</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">8.8.8.8:53</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">UDP/DNS</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">24</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">4.8 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">0.24s</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">192.168.1.5:80</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">192.168.1.10:49756</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">TCP/HTTP</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">42</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">156.2 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">1.85s</td>
                </tr>
              </tbody>
            </table>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Conversation Statistics</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Average duration:</span>
                  <span className="font-mono">{analysisData?.summary?.avgConversationDuration || "2.84s"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Average packets:</span>
                  <span className="font-mono">{analysisData?.summary?.avgPacketsPerConversation || "42"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Average bytes:</span>
                  <span className="font-mono">{analysisData?.summary?.avgBytesPerConversation || "128.5 KB"}</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Conversation Types</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>TCP conversations:</span>
                  <span className="font-mono">{analysisData?.summary?.tcpConversations || 9}</span>
                </div>
                <div className="flex justify-between">
                  <span>UDP conversations:</span>
                  <span className="font-mono">{analysisData?.summary?.udpConversations || 4}</span>
                </div>
                <div className="flex justify-between">
                  <span>Other protocols:</span>
                  <span className="font-mono">{analysisData?.summary?.otherConversations || 1}</span>
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
            <p>Network protocols define the rules and conventions for communication between network devices. This capture contains {analysisData?.protocols?.length || 4} distinct protocols.</p>
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
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">TCP</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Transport</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">284</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">459.2 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">81.6%</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">UDP</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Transport</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">43</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">26.8 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">12.4%</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">HTTP</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Application</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">26</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">185.4 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">7.5%</td>
                </tr>
                <tr>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">DNS</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Application</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">14</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">4.2 KB</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">4.0%</td>
                </tr>
              </tbody>
            </table>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Protocol Layer Distribution</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Layer 2 (Data Link):</span>
                  <span className="font-mono">348 (100%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Layer 3 (Network):</span>
                  <span className="font-mono">348 (100%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Layer 4 (Transport):</span>
                  <span className="font-mono">327 (94.0%)</span>
                </div>
                <div className="flex justify-between">
                  <span>Layer 7 (Application):</span>
                  <span className="font-mono">165 (47.4%)</span>
                </div>
              </div>
            </div>
            
            <div className="border rounded-lg p-4 bg-white">
              <h4 className="font-medium mb-2">Protocol Anomalies</h4>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Fragmented packets:</span>
                  <span className="font-mono">{analysisData?.summary?.fragmentedPackets || 2}</span>
                </div>
                <div className="flex justify-between">
                  <span>Retransmissions:</span>
                  <span className="font-mono">{analysisData?.summary?.retransmissions || 5}</span>
                </div>
                <div className="flex justify-between">
                  <span>Duplicate ACKs:</span>
                  <span className="font-mono">{analysisData?.summary?.duplicateAcks || 3}</span>
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
                      <div className="text-3xl font-bold text-cyber-primary">{analysisData?.summary?.totalPackets || 348}</div>
                      <div className="text-xs text-gray-600">Total Packets</div>
                    </div>
                    
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('addresses')}
                    >
                      <div className="text-3xl font-bold text-cyber-secondary">{analysisData?.summary?.ipAddresses || 24}</div>
                      <div className="text-xs text-gray-600">Unique IP Addresses</div>
                    </div>
                    
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('conversations')}
                    >
                      <div className="text-3xl font-bold text-cyber-accent">{analysisData?.summary?.conversationCount || 18}</div>
                      <div className="text-xs text-gray-600">Conversations</div>
                    </div>
                    
                    <div 
                      className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm hover:shadow-md transition-shadow cursor-pointer"
                      onClick={() => openDetailDialog('protocols')}
                    >
                      <div className="text-3xl font-bold text-orange-500">{analysisData?.protocols?.length || 7}</div>
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
