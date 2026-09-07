import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Key } from 'lucide-react';
import { Button } from '@/components/ui/button';
import ApiKeySettings from '@/components/ApiKeySettings';

const ApiKeysPage: React.FC = () => (
  <main className="min-h-screen bg-cyber-background p-4 md:p-8">
    <div className="mx-auto max-w-3xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Key className="h-5 w-5 text-cyber-primary" />
          <h1 className="text-2xl font-bold">AI Service Credentials</h1>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back to analyzer
          </Link>
        </Button>
      </div>
      <p className="text-sm text-gray-600">
        Add a key for any provider to unlock its live model list. Keys stay in this browser and are
        relayed to the provider only for the request being made.
      </p>
      <ApiKeySettings inline />
    </div>
  </main>
);

export default ApiKeysPage;
