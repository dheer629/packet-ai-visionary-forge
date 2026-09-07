
import React from 'react';
import { Server, LogIn, LogOut, Linkedin } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { useNavigate } from 'react-router-dom';
import ApiKeySettings from './ApiKeySettings';
import SavedCaptures from './SavedCaptures';
import { useAuth } from '@/hooks/useAuth';

interface HeaderProps {
  analysisData?: any;
  onLoadCapture?: (data: any) => void;
}

const Header: React.FC<HeaderProps> = ({ analysisData, onLoadCapture }) => {
  const navigate = useNavigate();
  const { user, signOut } = useAuth();

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
          <span className="text-sm text-gray-600">Advanced Network Analysis System</span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {user && <SavedCaptures analysisData={analysisData} onLoad={onLoadCapture ?? (() => {})} />}
        <ApiKeySettings />
        <Button variant="ghost" size="sm" onClick={() => navigate('/settings/api-keys')}>
          Key settings page
        </Button>


        {user ? (
          <div className="flex items-center gap-2 border-l pl-3 border-cyber-border">
            <span className="hidden text-sm text-gray-700 md:inline">{user.email}</span>
            <Button variant="ghost" size="sm" className="gap-1" onClick={() => signOut()}>
              <LogOut className="h-4 w-4" /> Sign out
            </Button>
          </div>
        ) : (
          <Button size="sm" className="gap-1" onClick={() => navigate('/auth')}>
            <LogIn className="h-4 w-4" /> Sign in
          </Button>
        )}

        <div className="flex items-center space-x-2 border-l pl-3 border-cyber-border">
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
