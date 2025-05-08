
import React, { useState } from 'react';
import Header from './Header';
import FileUpload from './FileUpload';
import AnalysisPanel from './AnalysisPanel';
import AIInsights from './AIInsights';
import AIAssistant from './AIAssistant';
import EnhancedPacketList from './EnhancedPacketList';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Terminal, Activity, Info } from 'lucide-react';

const Dashboard = () => {
  const [analysisData, setAnalysisData] = useState<any>(null);

  const handleFileUploaded = (data: any) => {
    setAnalysisData(data);
  };

  return (
    <div className="min-h-screen cyber-grid-bg py-6 px-4 md:px-6">
      <div className="max-w-7xl mx-auto">
        <Header />
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-1">
            <FileUpload onFileUpload={handleFileUploaded} />
          </div>
          
          <div className="lg:col-span-2">
            {analysisData ? (
              <div className="cyber-box">
                <h2 className="text-xl font-bold cyber-text mb-4">PCAP File Analysis</h2>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                  <div className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted bg-opacity-60">
                    <div className="text-3xl font-bold cyber-text">{analysisData?.summary?.totalPackets || 348}</div>
                    <div className="text-xs text-cyber-foreground">Total Packets</div>
                  </div>
                  
                  <div className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted bg-opacity-60">
                    <div className="text-3xl font-bold text-cyber-secondary">{analysisData?.summary?.ipAddresses || 24}</div>
                    <div className="text-xs text-cyber-foreground">Unique IP Addresses</div>
                  </div>
                  
                  <div className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted bg-opacity-60">
                    <div className="text-3xl font-bold text-cyber-accent">{analysisData?.summary?.conversationCount || 18}</div>
                    <div className="text-xs text-cyber-foreground">Conversations</div>
                  </div>
                  
                  <div className="cyber-box p-4 flex flex-col items-center justify-center bg-cyber-muted bg-opacity-60">
                    <div className="text-3xl font-bold text-orange-500">{analysisData?.protocols?.length || 7}</div>
                    <div className="text-xs text-cyber-foreground">Protocols</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="cyber-box h-full flex items-center justify-center">
                <div className="text-center">
                  <h3 className="text-xl font-bold cyber-text cyber-glow mb-2">
                    Network Traffic Analysis System
                  </h3>
                  <p className="text-cyber-foreground/70 max-w-md mx-auto">
                    Upload a PCAP/tcpdump file to start analyzing network traffic and get AI-powered insights.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
        
        {analysisData && (
          <Tabs defaultValue="packets" className="mb-6">
            <TabsList className="bg-cyber-muted border border-cyber-border">
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
      </div>
    </div>
  );
};

export default Dashboard;
