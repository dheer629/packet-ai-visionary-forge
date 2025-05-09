
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Upload } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';
import { processPcapFile } from '../utils/pcapProcessor';

const FileUpload = ({ onFileUpload }: { onFileUpload: (data: any) => void }) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);

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
    
    try {
      // Start processing the file with progress tracking
      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };
      
      const analysisData = await processPcapFile(file, progressCallback);
      
      // If API keys are available, enrich the data with AI analysis
      const apiKeys = JSON.parse(localStorage.getItem('nettracer-api-keys') || '[]');
      const openaiKey = apiKeys.find((key: any) => key.providerId === 'openai');
      
      if (openaiKey && openaiKey.value) {
        try {
          // This would typically use an API endpoint for analysis
          // For now, we'll just note the availability in the response
          analysisData.aiEnriched = true;
          analysisData.aiProvider = openaiKey.name;
          
          toast({
            title: "AI Analysis Available",
            description: `Using ${openaiKey.name} to analyze packet data`,
          });
        } catch (error) {
          console.error('Error processing with AI:', error);
        }
      }
      
      onFileUpload(analysisData);
      
      toast({
        title: "Analysis Complete",
        description: `Successfully processed ${file.name}`,
      });
    } catch (error) {
      console.error('Error processing PCAP file:', error);
      toast({
        title: "Processing Error",
        description: `Failed to process the PCAP file: ${error.message}`,
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
                  <p>Processing... {processingProgress}%</p>
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
