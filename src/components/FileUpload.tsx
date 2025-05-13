
import React from 'react';
import { Button } from '@/components/ui/button';
import { useFileProcessor } from '../hooks/useFileProcessor';
import FileUploadBox from './FileUploadBox';

const FileUpload = ({ onFileUpload }: { onFileUpload: (data: any) => void }) => {
  const { 
    isUploading, 
    fileName, 
    processingProgress, 
    dataFormat, 
    aiEnrichment,
    processFile 
  } = useFileProcessor(onFileUpload);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      await processFile(file);
    }
  };

  return (
    <div className="cyber-box mb-6">
      <h2 className="text-lg font-medium mb-4 cyber-text">Upload PCAP File</h2>
      
      <FileUploadBox 
        isUploading={isUploading}
        fileName={fileName}
        processingProgress={processingProgress}
        dataFormat={dataFormat}
        aiEnrichment={aiEnrichment}
        onFileChange={handleFileChange}
      />
      
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
