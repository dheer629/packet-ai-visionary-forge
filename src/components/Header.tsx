
import React from 'react';
import { AlertCircle, Server, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';

const Header = () => {
  return (
    <header className="cyber-box flex justify-between items-center mb-6">
      <div className="flex items-center">
        <Server className="h-6 w-6 mr-3 text-cyber-primary" />
        <div>
          <h1 className="text-2xl font-bold mr-4 cyber-text cyber-glow">NetTracer Pro</h1>
          <span className="text-sm text-cyber-secondary">Advanced Network Analysis System</span>
        </div>
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center">
          <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse-glow mr-2"></span>
          <span className="text-xs">SYSTEM ONLINE</span>
        </div>
        <Button variant="outline" size="sm" className="border-cyber-primary text-cyber-primary hover:bg-cyber-primary hover:bg-opacity-20">
          <Activity className="w-4 h-4 mr-2" />
          System Status
        </Button>
        <Button variant="outline" size="sm" className="border-cyber-secondary text-cyber-secondary hover:bg-cyber-secondary hover:bg-opacity-20">
          <AlertCircle className="w-4 h-4 mr-2" />
          Network Health
        </Button>
      </div>
    </header>
  );
};

export default Header;
