
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Upload } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';
import { processPcapFile } from '../utils/pcapProcessor';
import { getProviderSettings, callAIModel } from '../services/aiService';

const FileUpload = ({ onFileUpload }: { onFileUpload: (data: any) => void }) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [dataFormat, setDataFormat] = useState<string | null>(null);
  const [aiEnrichment, setAiEnrichment] = useState<boolean>(false);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
      toast({
        title: "Invalid File",
        description: "Please upload a valid PCAP or PCAPNG file",
        variant: "destructive"
      });
      return;
    }

    setFileName(file.name);
    setIsUploading(true);
    setProcessingProgress(0);
    setDataFormat(file.name.endsWith('.pcapng') ? 'PCAPNG' : 'PCAP');
    
    try {
      console.log(`Processing file: ${file.name}, size: ${file.size} bytes`);
      
      // Start processing the file with progress tracking
      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };
      
      const analysisData = await processPcapFile(file, progressCallback);
      console.log('PCAP processing complete:', analysisData.summary);
      
      // Check if we have API keys available for AI enhancement
      const apiKeys = JSON.parse(localStorage.getItem('nettracer-api-keys') || '[]');
      let aiProviderKey = null;
      let aiProvider = null;
      
      // Check for available AI providers in this order of preference
      const preferredProviders = ['openai', 'anthropic', 'cohere', 'groq', 'google', 'deepseek'];
      
      for (const providerId of preferredProviders) {
        const providerKey = apiKeys.find((key: any) => key.providerId === providerId && key.value);
        if (providerKey) {
          aiProviderKey = providerKey;
          aiProvider = providerId;
          break;
        }
      }
      
      if (aiProviderKey && aiProviderKey.value && aiProviderKey.selectedModel) {
        try {
          setAiEnrichment(true);
          toast({
            title: "AI Enhancement Started",
            description: `Using ${aiProviderKey.name} to enhance analysis`,
          });
          
          // Generate a summary of the packet capture using the selected model
          const packetSummary = `${analysisData.summary.totalPackets} packets captured between ${analysisData.summary.startTime} and ${analysisData.summary.endTime}. 
          ${analysisData.summary.protocolCounts?.map((p: any) => `${p.protocol}: ${p.count}`).join(', ') || ''}. 
          IP addresses involved: ${analysisData.summary.topIPs?.slice(0, 5).map((ip: any) => ip.address).join(', ') || ''}`;
          
          const aiResponse = await callAIModel({
            providerId: aiProvider!,
            apiKey: aiProviderKey.value,
            modelId: aiProviderKey.selectedModel,
            prompt: `Analyze this network capture summary and provide insights: ${packetSummary}. Identify any potential security concerns, unusual patterns, or notable traffic characteristics.`,
            maxTokens: 500,
            temperature: 0.3
          });
          
          if (aiResponse.error) {
            console.error('AI enrichment error:', aiResponse.error);
            toast({
              title: "AI Enhancement Failed",
              description: aiResponse.error,
              variant: "destructive"
            });
          } else {
            // Add AI insights to the analysis data
            analysisData.aiEnriched = true;
            analysisData.aiProvider = aiProviderKey.name;
            analysisData.aiInsights = aiResponse.text;
            console.log('Analysis enriched with AI from provider:', aiProviderKey.name);
            
            toast({
              title: "AI Enhancement Complete",
              description: `Analysis enhanced with ${aiProviderKey.name}`,
            });
          }
        } catch (error) {
          console.error('Error processing with AI:', error);
          toast({
            title: "AI Enhancement Failed",
            description: error instanceof Error ? error.message : 'Unknown error',
            variant: "destructive"
          });
        } finally {
          setAiEnrichment(false);
        }
      }
      
      onFileUpload(analysisData);
      
      toast({
        title: "Analysis Complete",
        description: `Successfully processed ${file.name} (${analysisData.summary.totalPackets} packets)`,
      });
    } catch (error) {
      console.error('Error processing PCAP file:', error);
      toast({
        title: "Processing Error",
        description: `Failed to process the PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="cyber-box mb-6">
      <h2 className="text-lg font-medium mb-4 cyber-text">Upload PCAP File</h2>
      <div className="flex flex-col items-center justify-center border-2 border-dashed border-cyber-border rounded-md p-6 bg-cyber-muted bg-opacity-30 transition-all hover:border-cyber-primary cursor-pointer">
        <input
          type="file"
          id="pcap-upload"
          className="hidden"
          accept=".pcap,.pcapng"
          onChange={handleFileChange}
        />
        <label htmlFor="pcap-upload" className="w-full flex flex-col items-center cursor-pointer">
          <Upload className="h-10 w-10 text-cyber-primary mb-2" />
          <p className="mb-2 text-center">
            <span className="font-semibold">Click to upload</span> or drag and drop
          </p>
          <p className="text-xs text-cyber-secondary">.pcap or .pcapng files only</p>
          
          {fileName && (
            <div className="mt-4 text-sm text-cyber-accent">
              {isUploading ? (
                <div className="w-full">
                  <p>
                    {aiEnrichment 
                      ? `Processing ${dataFormat} file (${processingProgress}%) - AI enhancement in progress...` 
                      : `Processing ${dataFormat} file... ${processingProgress}%`}
                  </p>
                  <div className="w-full bg-gray-200 rounded-full h-2.5 my-2">
                    <div className="bg-cyber-primary h-2.5 rounded-full" style={{ width: `${processingProgress}%` }}></div>
                  </div>
                </div>
              ) : `Selected: ${fileName}`}
            </div>
          )}
        </label>
      </div>
      
      <div className="mt-4 flex justify-end">
        <Button 
          disabled={isUploading || !fileName} 
          className="bg-cyber-primary text-cyber-foreground hover:bg-cyber-primary/80"
          onClick={() => document.getElementById('pcap-upload')?.click()}
        >
          {isUploading ? `Processing (${processingProgress}%)` : "Analyze PCAP"}
        </Button>
      </div>
    </div>
  );
};

export default FileUpload;
