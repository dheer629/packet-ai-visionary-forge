
import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/components/ui/use-toast';
import { Key, Info, Check, X, RefreshCw } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { modelProviders, ModelProvider, fetchAvailableModels, ModelOption } from '../services/modelProviders';

interface ApiKey {
  id: string;
  providerId: string;
  name: string;
  value: string;
  lastUsed?: string;
  models?: ModelOption[];
  selectedModel?: string;
}

const ApiKeySettings = () => {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const [apiKeys, setApiKeys] = useState<ApiKey[]>(() => {
    const savedKeys = localStorage.getItem('nettracer-api-keys');
    return savedKeys ? JSON.parse(savedKeys) : [];
  });
  const [newKeyValue, setNewKeyValue] = useState('');
  const [selectedProvider, setSelectedProvider] = useState<string>('openai');
  const [testingConnection, setTestingConnection] = useState(false);
  const [availableModels, setAvailableModels] = useState<Record<string, ModelOption[]>>({});
  const [isFetchingModels, setIsFetchingModels] = useState<Record<string, boolean>>({});
  
  useEffect(() => {
    localStorage.setItem('nettracer-api-keys', JSON.stringify(apiKeys));
  }, [apiKeys]);

  // Load available models for existing keys on component mount
  useEffect(() => {
    const loadModelsForExistingKeys = async () => {
      const modelsMap: Record<string, ModelOption[]> = {};
      const fetchingMap: Record<string, boolean> = {};
      
      for (const key of apiKeys) {
        fetchingMap[key.id] = true;
        setIsFetchingModels(prev => ({...prev, [key.id]: true}));
      }
      
      for (const key of apiKeys) {
        try {
          const models = await fetchAvailableModels(key.providerId, key.value);
          modelsMap[key.id] = models;
        } catch (error) {
          console.error(`Failed to load models for ${key.name}:`, error);
        } finally {
          fetchingMap[key.id] = false;
          setIsFetchingModels(prev => ({...prev, [key.id]: false}));
        }
      }
      
      setAvailableModels(modelsMap);
    };
    
    if (apiKeys.length > 0) {
      loadModelsForExistingKeys();
    }
  }, []);

  const testApiConnection = async () => {
    if (!selectedProvider || !newKeyValue) {
      toast({
        title: "Missing Information",
        description: "Please select a provider and enter an API key",
        variant: "destructive"
      });
      return false;
    }

    setTestingConnection(true);
    
    try {
      const provider = modelProviders.find(p => p.id === selectedProvider);
      if (!provider) throw new Error("Provider not found");
      
      const isValid = await provider.testConnection(newKeyValue);
      
      if (isValid) {
        toast({
          title: "Connection Successful",
          description: `Successfully connected to ${provider.name} API`,
        });
      } else {
        toast({
          title: "Connection Failed",
          description: `Could not validate the ${provider.name} API key`,
          variant: "destructive"
        });
      }
      
      return isValid;
    } catch (error) {
      console.error("API connection test error:", error);
      toast({
        title: "Connection Error",
        description: `An error occurred while testing the connection: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
      return false;
    } finally {
      setTestingConnection(false);
    }
  };

  const addApiKey = async () => {
    if (!selectedProvider || !newKeyValue.trim()) {
      toast({
        title: "Error",
        description: "Service provider and API key are required",
        variant: "destructive"
      });
      return;
    }
    
    const provider = modelProviders.find(p => p.id === selectedProvider);
    if (!provider) return;
    
    // Test connection before adding
    const isValid = await testApiConnection();
    if (!isValid) return;
    
    // Check if key with this provider already exists
    const existingKey = apiKeys.find(key => key.providerId === selectedProvider);
    if (existingKey) {
      // Update the existing key
      const updatedKeys = apiKeys.map(key => {
        if (key.providerId === selectedProvider) {
          return {
            ...key,
            value: newKeyValue,
            lastUsed: undefined
          };
        }
        return key;
      });
      
      setApiKeys(updatedKeys);
      
      toast({
        title: "API Key Updated",
        description: `${provider.name} API key has been updated.`
      });
      
      // Refresh models for this key
      refreshModels(existingKey.id);
    } else {
      // Add new key
      const newKeyId = Date.now().toString();
      
      setIsFetchingModels(prev => ({...prev, [newKeyId]: true}));
      
      try {
        // Fetch available models
        const models = await fetchAvailableModels(selectedProvider, newKeyValue);
        const defaultModel = models.find(m => m.available)?.id;
        
        const newKey: ApiKey = {
          id: newKeyId,
          providerId: selectedProvider,
          name: provider.name,
          value: newKeyValue,
          models: models,
          selectedModel: defaultModel,
          lastUsed: undefined
        };
        
        setApiKeys([...apiKeys, newKey]);
        setAvailableModels({...availableModels, [newKey.id]: models});
        
        toast({
          title: "API Key Added",
          description: `${provider.name} API key has been added successfully.`
        });
      } catch (error) {
        console.error('Error fetching models:', error);
        toast({
          title: "Warning",
          description: "API key added but failed to fetch available models.",
          variant: "destructive"
        });
      } finally {
        setIsFetchingModels(prev => ({...prev, [newKeyId]: false}));
      }
    }
    
    setNewKeyValue('');
  };
  
  const deleteApiKey = (id: string) => {
    setApiKeys(apiKeys.filter(key => key.id !== id));
    const updatedModels = {...availableModels};
    delete updatedModels[id];
    setAvailableModels(updatedModels);
    
    toast({
      title: "API Key Removed",
      description: "The API key has been removed."
    });
  };

  const refreshModels = async (keyId: string) => {
    const key = apiKeys.find(k => k.id === keyId);
    if (!key) return;
    
    setIsFetchingModels(prev => ({...prev, [keyId]: true}));
    
    try {
      const models = await fetchAvailableModels(key.providerId, key.value);
      setAvailableModels({...availableModels, [keyId]: models});
      
      // Update the API key with new models
      setApiKeys(apiKeys.map(k => {
        if (k.id === keyId) {
          return {
            ...k, 
            models, 
            // If current selected model is not available, select first available
            selectedModel: models.some(m => m.id === k.selectedModel && m.available) 
              ? k.selectedModel 
              : models.find(m => m.available)?.id || k.selectedModel
          };
        }
        return k;
      }));
      
      toast({
        title: "Models Refreshed",
        description: `Available models for ${key.name} have been updated.`
      });
    } catch (error) {
      console.error("Failed to refresh models:", error);
      toast({
        title: "Refresh Failed",
        description: "Could not retrieve available models",
        variant: "destructive"
      });
    } finally {
      setIsFetchingModels(prev => ({...prev, [keyId]: false}));
    }
  };

  const updateSelectedModel = (keyId: string, modelId: string) => {
    setApiKeys(apiKeys.map(key => {
      if (key.id === keyId) {
        return {...key, selectedModel: modelId};
      }
      return key;
    }));
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
        <DialogContent className="max-w-3xl max-h-[90vh]">
          <DialogHeader>
            <DialogTitle>AI Provider API Keys</DialogTitle>
          </DialogHeader>
          
          <ScrollArea className="max-h-[70vh]">
            <div className="py-4 space-y-4">
              <div className="bg-blue-50 p-3 rounded-md text-sm flex items-start gap-2">
                <Info className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
                <p className="text-blue-700">
                  Connect to AI services by adding API keys for various providers. The system will automatically detect available models for each provider.
                  API keys are stored in your browser's local storage and are never sent to our servers.
                </p>
              </div>
              
              <div className="space-y-4">
                <div className="grid grid-cols-12 gap-4">
                  <div className="col-span-4 space-y-2">
                    <Label htmlFor="api-key-provider">Service Provider</Label>
                    <Select value={selectedProvider} onValueChange={setSelectedProvider}>
                      <SelectTrigger id="api-key-provider">
                        <SelectValue placeholder="Select provider" />
                      </SelectTrigger>
                      <SelectContent>
                        {modelProviders.map(provider => (
                          <SelectItem key={provider.id} value={provider.id}>
                            {provider.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      {modelProviders.find(p => p.id === selectedProvider)?.description || ''}
                    </p>
                  </div>
                  
                  <div className="col-span-8 space-y-2">
                    <Label htmlFor="api-key-value">API Key</Label>
                    <div className="flex gap-2">
                      <Input 
                        id="api-key-value" 
                        value={newKeyValue} 
                        onChange={(e) => setNewKeyValue(e.target.value)} 
                        type="password"
                        placeholder="Enter API key"
                        className="flex-grow"
                      />
                      <Button 
                        variant="outline" 
                        onClick={testApiConnection}
                        disabled={testingConnection || !newKeyValue}
                      >
                        {testingConnection ? 'Testing...' : 'Test'}
                      </Button>
                    </div>
                  </div>
                </div>
                
                <Button 
                  onClick={addApiKey}
                  className="w-full"
                  disabled={testingConnection || !selectedProvider || !newKeyValue}
                >
                  {apiKeys.some(key => key.providerId === selectedProvider) ? 'Update API Key' : 'Add API Key'}
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
                      <div key={key.id} className="p-4 border-b last:border-b-0">
                        <div className="flex justify-between items-center mb-3">
                          <div>
                            <p className="font-medium">{key.name}</p>
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
                        
                        <div className="bg-gray-50 p-3 rounded-md">
                          <div className="flex justify-between items-center mb-2">
                            <Label className="text-sm">Available Models</Label>
                            <Button 
                              variant="ghost" 
                              size="sm" 
                              onClick={() => refreshModels(key.id)}
                              className="text-xs flex items-center gap-1"
                              disabled={isFetchingModels[key.id]}
                            >
                              {isFetchingModels[key.id] ? (
                                <>
                                  <RefreshCw className="h-3 w-3 animate-spin mr-1" />
                                  Loading...
                                </>
                              ) : (
                                <>Refresh</>
                              )}
                            </Button>
                          </div>
                          
                          {isFetchingModels[key.id] ? (
                            <div className="text-center py-4 text-sm text-gray-500">
                              <RefreshCw className="h-4 w-4 animate-spin mx-auto mb-2" />
                              Fetching available models...
                            </div>
                          ) : availableModels[key.id]?.length ? (
                            <div className="space-y-3">
                              <Select 
                                value={key.selectedModel || ''} 
                                onValueChange={(value) => updateSelectedModel(key.id, value)}
                              >
                                <SelectTrigger>
                                  <SelectValue placeholder="Select a model" />
                                </SelectTrigger>
                                <SelectContent>
                                  {availableModels[key.id].map((model) => (
                                    <SelectItem 
                                      key={model.id} 
                                      value={model.id}
                                      disabled={!model.available}
                                    >
                                      <div className="flex items-center gap-2">
                                        <span>{model.name}</span>
                                        {model.available ? (
                                          <Check className="h-3 w-3 text-green-500" />
                                        ) : (
                                          <X className="h-3 w-3 text-red-500" />
                                        )}
                                      </div>
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                              
                              {key.selectedModel && (
                                <p className="text-xs text-muted-foreground">
                                  {availableModels[key.id].find(m => m.id === key.selectedModel)?.description || ''}
                                </p>
                              )}
                            </div>
                          ) : (
                            <div className="text-center py-2 text-sm text-gray-500">
                              No models available. Try refreshing.
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </ScrollArea>
          
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
