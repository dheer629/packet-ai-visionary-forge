
import React from 'react';
import { Server, Activity, User, HelpCircle, MessageCircle, Linkedin } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';

const Header = () => {
  const authorDetails = {
    name: "Dheeraj Vishwakarma",
    title: "Senior Architect",
    avatar: "https://aimldheeraj.netlify.app/assets/img/hero-img.jpg",
    linkedin: "https://www.linkedin.com/in/dheeraj-vishwakarma-61350918/"
  };

  return (
    <header className="flex justify-between items-center mb-6 p-4 bg-white rounded-lg shadow-sm border border-cyber-border">
      <div className="flex items-center">
        <Server className="h-6 w-6 mr-3 text-cyber-primary" />
        <div>
          <h1 className="text-2xl font-bold mr-4 cyber-text cyber-glow">NetTracer Pro ✨</h1>
          <span className="text-sm text-gray-600">Advanced Network Analysis System 🛡️</span>
        </div>
      </div>

      <div className="hidden md:flex items-center space-x-2">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="border-cyber-primary text-cyber-primary hover:bg-cyber-primary hover:bg-opacity-10">
                <Activity className="w-4 h-4 mr-2" />
                System Status
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>View system performance metrics</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="border-cyber-secondary text-cyber-secondary hover:bg-cyber-secondary hover:bg-opacity-10">
                <HelpCircle className="w-4 h-4 mr-2" />
                Support
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Get help with the application</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:bg-opacity-10">
                <MessageCircle className="w-4 h-4 mr-2" />
                Chat
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Chat with AI assistant</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex items-center">
          <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse-glow mr-2"></span>
          <span className="text-xs text-gray-600">SYSTEM ONLINE 🟢</span>
        </div>
        
        <div className="flex items-center space-x-2 border-l pl-4 border-cyber-border">
          <Avatar className="h-9 w-9 ring-2 ring-blue-200">
            <AvatarImage src={authorDetails.avatar} alt={authorDetails.name} />
            <AvatarFallback>DV</AvatarFallback>
          </Avatar>
          <div className="hidden md:block">
            <p className="text-sm font-medium">{authorDetails.name} ✅</p>
            <p className="text-xs text-blue-600 font-medium">{authorDetails.title}</p>
          </div>
          <a href={authorDetails.linkedin} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:text-blue-800 transition-colors">
            <Linkedin className="h-4 w-4" />
          </a>
        </div>
      </div>
    </header>
  );
};

export default Header;
