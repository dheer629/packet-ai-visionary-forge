
import React, { useState } from 'react';
import Header from './Header';
import FileUpload from './FileUpload';
import AnalysisPanel from './AnalysisPanel';
import AIInsights from './AIInsights';
import AIAssistant from './AIAssistant';
import EnhancedPacketList from './EnhancedPacketList';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal, Activity, Info, User, MessageSquare, Shield } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

const Dashboard = () => {
  const [analysisData, setAnalysisData] = useState<any>(null);
  const authorProfile = {
    name: "Dheeraj Vishwakarma",
    role: "Senior Machine Learning Engineer",
    expertise: ["Network Security", "TCPDUMP Analysis", "Machine Learning", "AI Engineering"],
    experience: "10+ years",
    education: "Ph.D. in Machine Learning"
  };

  const handleFileUploaded = (data: any) => {
    setAnalysisData(data);
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
                    <div className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm">
                      <div className="text-3xl font-bold text-cyber-primary">{analysisData?.summary?.totalPackets || 348}</div>
                      <div className="text-xs text-gray-600">Total Packets</div>
                    </div>
                    
                    <div className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm">
                      <div className="text-3xl font-bold text-cyber-secondary">{analysisData?.summary?.ipAddresses || 24}</div>
                      <div className="text-xs text-gray-600">Unique IP Addresses</div>
                    </div>
                    
                    <div className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm">
                      <div className="text-3xl font-bold text-cyber-accent">{analysisData?.summary?.conversationCount || 18}</div>
                      <div className="text-xs text-gray-600">Conversations</div>
                    </div>
                    
                    <div className="bg-white p-4 rounded-lg border border-cyber-border flex flex-col items-center justify-center shadow-sm">
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
                    
                    <div className="mt-8 bubble mx-auto max-w-md">
                      <div className="flex items-start">
                        <div className="mr-3">
                          <User className="h-5 w-5 text-cyber-primary" />
                        </div>
                        <div>
                          <h4 className="font-medium text-cyber-primary">Developed by {authorProfile.name}</h4>
                          <p className="text-sm text-gray-600">{authorProfile.role} with {authorProfile.experience} experience</p>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {authorProfile.expertise.map((skill, i) => (
                              <span key={i} className="text-xs bg-blue-50 text-cyber-primary px-2 py-0.5 rounded-full">
                                {skill}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
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
                    <MessageSquare className="h-5 w-5 text-cyber-primary" />
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
    </div>
  );
};

export default Dashboard;
