
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Send, Terminal, Info } from 'lucide-react';

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

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMessage.trim()) return;
    
    // Add user message
    const userMessage: Message = { role: 'user', content: inputMessage };
    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);
    
    // Simulate AI response
    setTimeout(() => {
      const aiResponse = generateAIResponse(inputMessage, packetData);
      const aiMessage: Message = { role: 'assistant', content: aiResponse };
      setMessages(prev => [...prev, aiMessage]);
      setIsLoading(false);
    }, 1000);
  };

  // Mock AI responses based on user questions and packet data
  const generateAIResponse = (userQuery: string, packets?: any): string => {
    const query = userQuery.toLowerCase();
    
    if (query.includes('retransmission') || query.includes('packet loss')) {
      return "I've analyzed the packet capture and found several TCP retransmissions occurring between IP addresses 192.168.1.5 and 74.125.24.100. This indicates potential network congestion or packet loss. The retransmission rate is approximately 3.5%, which is above the recommended threshold of 1%. Consider checking for physical connectivity issues or bandwidth constraints.";
    }
    
    if (query.includes('dns') || query.includes('domain')) {
      return "The capture shows multiple DNS queries to the server 8.8.8.8. Several NXDOMAIN responses were received for queries to 'service-update.example.com', which may indicate a misconfiguration or outdated DNS records. The average DNS response time is 54ms, which is within normal parameters.";
    }
    
    if (query.includes('latency') || query.includes('slow')) {
      return "Network latency analysis indicates average round-trip times of 120ms to external servers, with occasional spikes up to 350ms. These spikes correlate with periods of high throughput, suggesting possible bandwidth saturation. TCP handshakes are taking longer than expected (averaging 210ms versus typical 45-75ms), which may be affecting application performance.";
    }
    
    if (query.includes('suspicious') || query.includes('malware') || query.includes('threat')) {
      return "I've identified potentially suspicious patterns in the traffic. There are repeated connections to uncommon ports (8108, 31337) from the internal host 192.168.1.102. Additionally, several DNS queries for algorithmically-generated domain names were observed, which is a common characteristic of command and control traffic. I recommend further investigation of host 192.168.1.102.";
    }
    
    if (query.includes('tls') || query.includes('ssl') || query.includes('certificate')) {
      return "The capture contains TLS traffic using TLSv1.2 and TLSv1.3. I detected 3 different certificates in use, with one showing an expired validation date (expired 15 days ago). Several TLS handshakes failed with 'unknown_ca' alerts, suggesting a certificate trust issue. The most common cipher suite in use is TLS_AES_256_GCM_SHA384.";
    }
    
    // Default response
    return "Based on my analysis of this PCAP file, I see " + (packets ? packets.summary?.totalPackets || "multiple" : "multiple") + " packets with a mixture of TCP, UDP, and ICMP traffic. To provide more specific insights, could you ask about a particular aspect you're interested in? For example, I can analyze connection issues, identify potential security threats, examine DNS problems, or investigate performance bottlenecks.";
  };

  const handleQuickQuestion = (question: string) => {
    const userMessage: Message = { role: 'user', content: question };
    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);
    
    setTimeout(() => {
      const aiResponse = generateAIResponse(question, packetData);
      const aiMessage: Message = { role: 'assistant', content: aiResponse };
      setMessages(prev => [...prev, aiMessage]);
      setIsLoading(false);
    }, 1000);
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
        >
          Protocol Analysis
        </Button>
        <Button 
          variant="outline" 
          size="sm" 
          className="text-xs border-cyber-border"
          onClick={() => handleQuickQuestion("Is there any suspicious traffic?")}
        >
          Security Check
        </Button>
        <Button 
          variant="outline" 
          size="sm" 
          className="text-xs border-cyber-border"
          onClick={() => handleQuickQuestion("Why is the network slow?")}
        >
          Performance Issues
        </Button>
        <Button 
          variant="outline" 
          size="sm" 
          className="text-xs border-cyber-border"
          onClick={() => handleQuickQuestion("What DNS issues are present?")}
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
        />
        <Button type="submit" disabled={isLoading} className="bg-cyber-primary hover:bg-cyber-primary/80">
          <Send className="h-4 w-4" />
        </Button>
      </form>
    </div>
  );
};

export default AIAssistant;
