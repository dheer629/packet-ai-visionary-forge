import React from 'react';
import { Upload, Pause, Play, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';

export interface DecodeCheckpointInfo {
  fileName: string;
  packetCount: number;
  offset: number;
  fileSize: number;
}

interface FileUploadBoxProps {
  isUploading: boolean;
  isPaused: boolean;
  fileName: string | null;
  processingProgress: number;
  dataFormat: string | null;
  aiEnrichment: boolean;
  onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onPause: () => void;
  onResume: () => void;
  onCancel: () => void;
  checkpoint?: DecodeCheckpointInfo | null;
  onDiscardCheckpoint?: () => void;
}

const FileUploadBox: React.FC<FileUploadBoxProps> = ({
  isUploading,
  isPaused,
  fileName,
  processingProgress,
  dataFormat,
  aiEnrichment,
  onFileChange,
  onPause,
  onResume,
  onCancel,
  checkpoint,
  onDiscardCheckpoint,
}) => {
  const checkpointPercent = checkpoint && checkpoint.fileSize
    ? Math.min(100, Math.round((checkpoint.offset / checkpoint.fileSize) * 100))
    : 0;

  return (
    <div className="flex flex-col items-center justify-center border-2 border-dashed border-cyber-border rounded-md p-6 bg-cyber-muted bg-opacity-30 transition-all hover:border-cyber-primary">
      {checkpoint && !isUploading && (
        <div className="mb-4 w-full rounded-md border border-cyber-border bg-cyber-muted/50 p-3 text-xs">
          <p className="font-medium text-cyber-accent">Unfinished decode found</p>
          <p className="mt-1 text-cyber-foreground">
            {checkpoint.fileName} — {checkpoint.packetCount.toLocaleString()} packets decoded ({checkpointPercent}%).
            Select the same file again to continue from where it stopped.
          </p>
          {onDiscardCheckpoint && (
            <Button type="button" size="sm" variant="ghost" className="mt-2 text-xs" onClick={onDiscardCheckpoint}>
              Discard saved progress
            </Button>
          )}
        </div>
      )}

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
      </label>

      {fileName && (
        <div className="mt-4 w-full text-sm text-cyber-accent">
          {isUploading ? (
            <div className="w-full space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate">
                  {isPaused
                    ? `Paused — ${dataFormat} decode at ${processingProgress}%`
                    : aiEnrichment
                      ? `Decoding ${dataFormat} (${processingProgress}%) — AI enhancement in progress`
                      : `Decoding ${dataFormat}… ${processingProgress}%`}
                </span>
                <span className="font-mono text-xs">{processingProgress}%</span>
              </div>

              <Progress value={processingProgress} className="h-2" />

              <div className="flex gap-2 justify-end">
                {isPaused ? (
                  <Button type="button" size="sm" variant="outline" className="text-xs" onClick={onResume}>
                    <Play className="h-3 w-3 mr-1" /> Resume
                  </Button>
                ) : (
                  <Button type="button" size="sm" variant="outline" className="text-xs" onClick={onPause}>
                    <Pause className="h-3 w-3 mr-1" /> Pause
                  </Button>
                )}
                <Button type="button" size="sm" variant="destructive" className="text-xs" onClick={onCancel}>
                  <X className="h-3 w-3 mr-1" /> Cancel
                </Button>
              </div>
            </div>
          ) : (
            <p className="text-center">Selected: {fileName}</p>
          )}
        </div>
      )}
    </div>
  );
};

export default FileUploadBox;
