
import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/components/ui/use-toast';
import { Key, Info } from 'lucide-react';

interface ApiKey {
  id: string;
  name: string;
  value: string;
  lastUsed?: string;
}

const ApiKeySettings = () => {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const [apiKeys, setApiKeys] = useState<ApiKey[]>(() => {
    const savedKeys = localStorage.getItem('nettracer-api-keys');
    return savedKeys ? JSON.parse(savedKeys) : [];
  });
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyValue, setNewKeyValue] = useState('');
  
  useEffect(() => {
    localStorage.setItem('nettracer-api-keys', JSON.stringify(apiKeys));
  }, [apiKeys]);

  const addApiKey = () => {
    if (!newKeyName.trim() || !newKeyValue.trim()) {
      toast({
        title: "Error",
        description: "API key name and value are required",
        variant: "destructive"
      });
      return;
    }
    
    const newKey: ApiKey = {
      id: Date.now().toString(),
      name: newKeyName,
      value: newKeyValue,
      lastUsed: undefined
    };
    
    setApiKeys([...apiKeys, newKey]);
    setNewKeyName('');
    setNewKeyValue('');
    
    toast({
      title: "API Key Added",
      description: `${newKeyName} has been added successfully.`
    });
  };
  
  const deleteApiKey = (id: string) => {
    setApiKeys(apiKeys.filter(key => key.id !== id));
    toast({
      title: "API Key Removed",
      description: "The API key has been removed."
    });
  };
  
  const maskApiKey = (key: string) => {
    if (key.length < 8) return '•'.repeat(key.length);
    return key.substring(0, 4) + '•'.repeat(key.length - 8) + key.substring(key.length - 4);
  };

  return (
    <>
      <Button 
        variant="outline" 
        size="sm" 
        onClick={() => setOpen(true)}
        className="flex items-center gap-2"
      >
        <Key className="h-4 w-4" />
        API Keys
      </Button>
      
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>API Key Management</DialogTitle>
          </DialogHeader>
          
          <div className="py-4 space-y-4">
            <div className="bg-blue-50 p-3 rounded-md text-sm flex items-start gap-2">
              <Info className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
              <p className="text-blue-700">
                Add API keys for external services like OpenAI, Anthropic, Google Vertex AI, or custom API endpoints for network analysis.
              </p>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="api-key-name">Service Name</Label>
                  <Input 
                    id="api-key-name" 
                    value={newKeyName} 
                    onChange={(e) => setNewKeyName(e.target.value)}
                    placeholder="e.g., OpenAI, Anthropic"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="api-key-value">API Key</Label>
                  <Input 
                    id="api-key-value" 
                    value={newKeyValue} 
                    onChange={(e) => setNewKeyValue(e.target.value)} 
                    type="password"
                    placeholder="Enter API key"
                  />
                </div>
              </div>
              
              <Button 
                onClick={addApiKey}
                className="w-full"
              >
                Add API Key
              </Button>
            </div>
            
            <div className="space-y-2">
              <Label>Stored API Keys</Label>
              {apiKeys.length === 0 ? (
                <div className="text-center p-4 border rounded-md text-gray-500 text-sm">
                  No API keys added yet
                </div>
              ) : (
                <div className="border rounded-md overflow-hidden">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="flex justify-between items-center p-3 border-b last:border-b-0">
                      <div>
                        <p className="font-medium text-sm">{key.name}</p>
                        <p className="text-xs text-gray-500 font-mono">{maskApiKey(key.value)}</p>
                      </div>
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        onClick={() => deleteApiKey(key.id)}
                        className="text-red-500 hover:text-red-700 hover:bg-red-50"
                      >
                        Remove
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          
          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => setOpen(false)}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default ApiKeySettings;
