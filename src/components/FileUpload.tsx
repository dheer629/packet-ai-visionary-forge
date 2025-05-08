
import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Upload } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';

const FileUpload = ({ onFileUpload }: { onFileUpload: (data: any) => void }) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.pcap')) {
      toast({
        title: "Invalid File",
        description: "Please upload a valid PCAP file",
        variant: "destructive"
      });
      return;
    }

    setFileName(file.name);
    setIsUploading(true);
    
    // Simulate processing for demo purposes
    // In a real app, we'd send this to a backend API
    setTimeout(() => {
      setIsUploading(false);
      
      // Generate mock data for demonstration
      const mockData = {
        filename: file.name,
        size: file.size,
        packets: Math.floor(Math.random() * 1000) + 100,
        protocols: ['TCP', 'UDP', 'HTTP', 'DNS'],
        timestamp: new Date().toISOString(),
        summary: {
          totalPackets: Math.floor(Math.random() * 1000) + 100,
          ipAddresses: Math.floor(Math.random() * 50) + 10,
          conversationCount: Math.floor(Math.random() * 30) + 5
        }
      };
      
      onFileUpload(mockData);
      
      toast({
        title: "Analysis Complete",
        description: `Successfully processed ${file.name}`,
      });
    }, 2000);
  };

  return (
    <div className="cyber-box mb-6">
      <h2 className="text-lg font-medium mb-4 cyber-text">Upload PCAP File</h2>
      <div className="flex flex-col items-center justify-center border-2 border-dashed border-cyber-border rounded-md p-6 bg-cyber-muted bg-opacity-30 transition-all hover:border-cyber-primary cursor-pointer">
        <input
          type="file"
          id="pcap-upload"
          className="hidden"
          accept=".pcap"
          onChange={handleFileChange}
        />
        <label htmlFor="pcap-upload" className="w-full flex flex-col items-center cursor-pointer">
          <Upload className="h-10 w-10 text-cyber-primary mb-2" />
          <p className="mb-2 text-center">
            <span className="font-semibold">Click to upload</span> or drag and drop
          </p>
          <p className="text-xs text-cyber-secondary">.pcap files only</p>
          
          {fileName && (
            <div className="mt-4 text-sm text-cyber-accent">
              {isUploading ? "Processing..." : `Selected: ${fileName}`}
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
          {isUploading ? "Processing..." : "Analyze PCAP"}
        </Button>
      </div>
    </div>
  );
};

export default FileUpload;
