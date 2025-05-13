
import React from 'react';
import { Upload } from 'lucide-react';

interface FileUploadBoxProps {
  isUploading: boolean;
  fileName: string | null;
  processingProgress: number;
  dataFormat: string | null;
  aiEnrichment: boolean;
  onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

const FileUploadBox: React.FC<FileUploadBoxProps> = ({
  isUploading,
  fileName,
  processingProgress,
  dataFormat,
  aiEnrichment,
  onFileChange
}) => {
  return (
    <div className="flex flex-col items-center justify-center border-2 border-dashed border-cyber-border rounded-md p-6 bg-cyber-muted bg-opacity-30 transition-all hover:border-cyber-primary cursor-pointer">
      <input
        type="file"
        id="pcap-upload"
        className="hidden"
        accept=".pcap,.pcapng"
        onChange={onFileChange}
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
  );
};

export default FileUploadBox;
