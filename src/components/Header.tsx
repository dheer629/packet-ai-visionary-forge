
import React from 'react';
import { AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';

const Header = () => {
  return (
    <header className="cyber-box flex justify-between items-center mb-6">
      <div className="flex items-center">
        <h1 className="text-2xl font-bold mr-4 cyber-text cyber-glow">AI MCP Server</h1>
        <span className="text-sm text-cyber-secondary">PCAP Analysis System</span>
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center">
          <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse-glow mr-2"></span>
          <span className="text-xs">SYSTEM ONLINE</span>
        </div>
        <Button variant="outline" size="sm" className="border-cyber-primary text-cyber-primary hover:bg-cyber-primary hover:bg-opacity-20">
          <AlertCircle className="w-4 h-4 mr-2" />
          System Status
        </Button>
      </div>
    </header>
  );
};

export default Header;
