import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { useFileProcessor } from '../hooks/useFileProcessor';
import FileUploadBox from './FileUploadBox';

const FileUpload = ({ onFileUpload }: { onFileUpload: (data: any) => void }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const {
    isUploading,
    isPaused,
    fileName,
    processingProgress,
    dataFormat,
    processingError,
    processFile,
    pauseDecode,
    resumeDecode,
    cancelDecode,
    checkpoint,
    discardCheckpoint,
  } = useFileProcessor(onFileUpload);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(e.target.files?.[0] ?? null);
    e.target.value = '';
  };

  return (
    <div className="cyber-box mb-6">
      <h2 className="text-lg font-medium mb-4 cyber-text">Upload PCAP File</h2>

      <FileUploadBox
        isUploading={isUploading}
        isPaused={isPaused}
        fileName={selectedFile?.name ?? fileName}
        processingProgress={processingProgress}
        dataFormat={dataFormat}
        aiEnrichment={false}
        onFileChange={handleFileChange}
        onFileDrop={setSelectedFile}
        onPause={pauseDecode}
        onResume={resumeDecode}
        onCancel={cancelDecode}
        checkpoint={
          checkpoint
            ? {
                fileName: checkpoint.fileName,
                packetCount: checkpoint.packetCount,
                offset: checkpoint.offset,
                fileSize: checkpoint.fileSize,
              }
            : null
        }
        onDiscardCheckpoint={discardCheckpoint}
      />

      {processingError && <p role="alert" className="mt-3 break-words text-sm text-destructive">{processingError}</p>}

      <div className="mt-4 flex justify-end">
        <Button
          disabled={isUploading || !selectedFile}
          className="bg-cyber-primary text-cyber-foreground hover:bg-cyber-primary/80"
          onClick={() => { if (selectedFile) void processFile(selectedFile); }}
        >
          {isUploading ? `Processing (${processingProgress}%)` : 'Analyze PCAP'}
        </Button>
      </div>
    </div>
  );
};

export default FileUpload;
