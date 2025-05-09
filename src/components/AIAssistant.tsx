
import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Send, Terminal, Info, X } from 'lucide-react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/components/ui/use-toast';
import { callAIModel, getProviderSettings } from '../services/aiService';
import { modelProviders } from '../services/modelProviders';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface AIAssistantProps {
  packetData?: any;
}

interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

const AIAssistant: React.FC<AIAssistantProps> = ({ packetData }) => {
  const [messages, setMessages] = useState<Message[]>([
    { role: 'system', content: 'Welcome to the AI Network Analyst. How can I assist you with packet analysis?' }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState<string>('');
  const [availableProviders, setAvailableProviders] = useState<Array<{id: string, name: string}>>([]);
  const { toast } = useToast();

  // Load available API keys on mount
  useEffect(() => {
    loadAvailableProviders();
  }, []);

  const loadAvailableProviders = () => {
    const savedKeys = localStorage.getItem('nettracer-api-keys');
    if (!savedKeys) {
      setAvailableProviders([]);
      return;
    }

    const apiKeys = JSON.parse(savedKeys);
    const providers = apiKeys.map((key: any) => ({
      id: key.providerId,
      name: key.name,
      keyId: key.id
    }));

    setAvailableProviders(providers);
    
    if (providers.length > 0 && !selectedProvider) {
      setSelectedProvider(providers[0].id);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMessage.trim()) return;
    
    // Add user message
    const userMessage: Message = { role: 'user', content: inputMessage };
    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);
    
    try {
      // Get provider settings
      const providerSettings = getProviderSettings(selectedProvider);
      
      if (!providerSettings) {
        throw new Error("No API key found for the selected provider");
      }
      
      // Create context from packet data
      let context = "";
      if (packetData) {
        context = `
          Network capture summary:
          - Total packets: ${packetData.summary?.totalPackets || 'Unknown'}
          - Unique IP addresses: ${packetData.summary?.ipAddresses || 'Unknown'}
          - Conversations: ${packetData.summary?.conversationCount || 'Unknown'}
          - Protocols: ${packetData.protocols?.length || 'Unknown'}
          - Capture duration: ${packetData.summary?.captureDuration || 'Unknown'}
          
          User query: ${inputMessage}
        `;
      } else {
        context = `The user hasn't uploaded any packet capture data yet. User query: ${inputMessage}`;
      }
      
      // Call AI model
      const aiResponse = await callAIModel({
        providerId: selectedProvider,
        apiKey: providerSettings.value,
        modelId: providerSettings.selectedModel || "",
        prompt: context,
        maxTokens: 1000,
        temperature: 0.7
      });
      
      if (aiResponse.error) {
        throw new Error(aiResponse.error);
      }
      
      const aiMessage: Message = { role: 'assistant', content: aiResponse.text };
      setMessages(prev => [...prev, aiMessage]);
    } catch (error) {
      console.error("AI Assistant error:", error);
      toast({
        title: "AI Request Failed",
        description: error instanceof Error ? error.message : "Unknown error occurred",
        variant: "destructive"
      });
      
      // Add error message
      const errorMessage: Message = { 
        role: 'assistant', 
        content: "I apologize, but I encountered an error processing your request. Please check your API key settings or try again later."
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickQuestion = async (question: string) => {
    const userMessage: Message = { role: 'user', content: question };
    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);
    
    try {
      // Get provider settings
      const providerSettings = getProviderSettings(selectedProvider);
      
      if (!providerSettings) {
        throw new Error("No API key found for the selected provider");
      }
      
      // Create context from packet data
      let context = "";
      if (packetData) {
        context = `
          Network capture summary:
          - Total packets: ${packetData.summary?.totalPackets || 'Unknown'}
          - Unique IP addresses: ${packetData.summary?.ipAddresses || 'Unknown'}
          - Conversations: ${packetData.summary?.conversationCount || 'Unknown'}
          - Protocols: ${packetData.protocols?.length || 'Unknown'}
          - Capture duration: ${packetData.summary?.captureDuration || 'Unknown'}
          
          Please analyze this PCAP data in response to: ${question}
        `;
      } else {
        context = `The user hasn't uploaded any packet capture data yet. Please respond to: ${question}`;
      }
      
      // Call AI model
      const aiResponse = await callAIModel({
        providerId: selectedProvider,
        apiKey: providerSettings.value,
        modelId: providerSettings.selectedModel || "",
        prompt: context,
        maxTokens: 1000,
        temperature: 0.7
      });
      
      if (aiResponse.error) {
        throw new Error(aiResponse.error);
      }
      
      const aiMessage: Message = { role: 'assistant', content: aiResponse.text };
      setMessages(prev => [...prev, aiMessage]);
    } catch (error) {
      console.error("AI Assistant error:", error);
      
      // Add error message
      const errorMessage: Message = { 
        role: 'assistant', 
        content: "I apologize, but I encountered an error processing your request. Please check your API key settings or try again later." 
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="cyber-box h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <Terminal className="w-5 h-5 mr-2 text-cyber-primary" />
          <h2 className="text-lg font-medium cyber-text">Network Analyst AI</h2>
        </div>
        <div className="text-xs text-cyber-foreground/60 flex items-center">
          <span className="h-2 w-2 rounded-full bg-cyber-accent mr-1"></span>
          Active
        </div>
      </div>
      
      {availableProviders.length === 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">No AI Service Connected</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-start gap-2 mb-4 text-sm">
              <Info className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
              <p className="text-gray-600">
                You need to add an API key for at least one AI service provider to use the AI assistant.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="mb-4">
            <Label htmlFor="ai-provider">AI Service</Label>
            <Select value={selectedProvider} onValueChange={setSelectedProvider}>
              <SelectTrigger id="ai-provider">
                <SelectValue placeholder="Select AI provider" />
              </SelectTrigger>
              <SelectContent>
                {availableProviders.map((provider) => (
                  <SelectItem key={provider.id} value={provider.id}>
                    {provider.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          
          <ScrollArea className="flex-grow mb-4">
            <div className="space-y-4 pr-4">
              {messages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] p-3 rounded-lg ${
                    msg.role === 'user' 
                      ? 'bg-cyber-secondary bg-opacity-20 text-white' 
                      : msg.role === 'system'
                      ? 'bg-cyber-muted bg-opacity-30 border border-cyber-border'
                      : 'bg-cyber-primary bg-opacity-20 border border-cyber-border'
                  }`}>
                    <p className="text-sm">{msg.content}</p>
                  </div>
                </div>
              ))}
              
              {isLoading && (
                <div className="flex justify-start">
                  <div className="max-w-[85%] p-3 rounded-lg bg-cyber-primary bg-opacity-10 border border-cyber-border">
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 rounded-full bg-cyber-primary animate-pulse"></div>
                      <div className="w-2 h-2 rounded-full bg-cyber-primary animate-pulse delay-75"></div>
                      <div className="w-2 h-2 rounded-full bg-cyber-primary animate-pulse delay-150"></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>
          
          <div className="space-x-2 space-y-2 mb-4">
            <Button 
              variant="outline" 
              size="sm" 
              className="text-xs border-cyber-border"
              onClick={() => handleQuickQuestion("What are the common protocols in this capture?")}
              disabled={isLoading || !selectedProvider}
            >
              Protocol Analysis
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              className="text-xs border-cyber-border"
              onClick={() => handleQuickQuestion("Is there any suspicious traffic?")}
              disabled={isLoading || !selectedProvider}
            >
              Security Check
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              className="text-xs border-cyber-border"
              onClick={() => handleQuickQuestion("Why is the network slow?")}
              disabled={isLoading || !selectedProvider}
            >
              Performance Issues
            </Button>
            <Button 
              variant="outline" 
              size="sm" 
              className="text-xs border-cyber-border"
              onClick={() => handleQuickQuestion("What DNS issues are present?")}
              disabled={isLoading || !selectedProvider}
            >
              DNS Problems
            </Button>
          </div>
          
          <form onSubmit={handleSubmit} className="flex space-x-2">
            <Input
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Ask a question about the network capture..."
              className="bg-cyber-muted border-cyber-border"
              disabled={isLoading || !selectedProvider}
            />
            <Button 
              type="submit" 
              disabled={isLoading || !inputMessage || !selectedProvider} 
              className="bg-cyber-primary hover:bg-cyber-primary/80"
            >
              <Send className="h-4 w-4" />
            </Button>
          </form>
        </>
      )}
    </div>
  );
};

// Add Label component since we're using it
const Label = ({ htmlFor, children, className = "" }: { htmlFor?: string, children: React.ReactNode, className?: string }) => {
  return (
    <label htmlFor={htmlFor} className={`text-sm font-medium mb-1 block ${className}`}>
      {children}
    </label>
  );
};

export default AIAssistant;
