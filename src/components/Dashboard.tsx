
import React, { useState } from 'react';
import Header from './Header';
import FileUpload from './FileUpload';
import AnalysisPanel from './AnalysisPanel';
import AIInsights from './AIInsights';

const Dashboard = () => {
  const [analysisData, setAnalysisData] = useState<any>(null);

  const handleFileUploaded = (data: any) => {
    setAnalysisData(data);
  };

  return (
    <div className="min-h-screen cyber-grid-bg py-6 px-4 md:px-6">
      <div className="max-w-7xl mx-auto">
        <Header />
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <FileUpload onFileUpload={handleFileUploaded} />
            <AIInsights data={analysisData} />
          </div>
          
          <div className="lg:col-span-2">
            {analysisData ? (
              <AnalysisPanel data={analysisData} />
            ) : (
              <div className="cyber-box h-full flex items-center justify-center">
                <div className="text-center">
                  <h3 className="text-xl font-bold cyber-text cyber-glow mb-2">
                    Welcome to PCAP Analyzer
                  </h3>
                  <p className="text-cyber-foreground/70 max-w-md mx-auto">
                    Upload a PCAP file to start analyzing network traffic and get AI-powered insights.
                  </p>
                  <div className="mt-4 text-sm">
                    <div className="inline-block border border-cyber-border rounded-md px-4 py-2 bg-cyber-muted bg-opacity-30">
                      <span className="text-cyber-secondary">Based on GitHub:</span> <br />
                      <a 
                        href="https://github.com/paresh2806/PCAP-Analyzer" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-cyber-primary hover:underline"
                      >
                        paresh2806/PCAP-Analyzer
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
