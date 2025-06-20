
import { useState } from 'react';
import { processPcapFile } from '../utils/pcapProcessor';
import { useToast } from '@/components/ui/use-toast';
import { enhancePacketData, ProcessedData } from '../utils/packetEnhancer';
import { applyAIEnhancement, createFallbackData } from '../utils/aiEnhancement';

export type { ProcessedData } from '../utils/packetEnhancer';

export const useFileProcessor = (onFileUpload: (data: ProcessedData) => void) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [dataFormat, setDataFormat] = useState<string | null>(null);
  const [aiEnrichment, setAiEnrichment] = useState<boolean>(false);

  const processFile = async (file: File) => {
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
      
      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };
      
      let analysisData = await processPcapFile(file, progressCallback);
      
      console.log('PCAP processing complete. First few packets:', 
        analysisData?.packets?.slice(0, 3).map((p: any) => ({
          number: p.number,
          time: p.time,
          source: p.source,
          destination: p.destination,
          protocol: p.protocol
        }))
      );
      console.log('Total packet count:', analysisData?.packets?.length || 0);
      
      if (!analysisData) {
        console.warn('No analysis data returned from processor');
        analysisData = { packets: [], summary: {} };
      }
      
      const enhancedData = enhancePacketData(analysisData, file);
      const aiEnhancedData = await applyAIEnhancement(enhancedData, setAiEnrichment, toast);

      onFileUpload(aiEnhancedData);
      
      toast({
        title: "Analysis Complete",
        description: `Successfully processed ${file.name} (${aiEnhancedData.summary.totalPackets} packets)`,
      });
    } catch (error) {
      console.error('Error processing PCAP file:', error);
      toast({
        title: "Processing Error",
        description: `Failed to process the PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive"
      });
      
      const fallbackData = createFallbackData(file);
      onFileUpload(fallbackData);
    } finally {
      setIsUploading(false);
    }
  };

  return {
    isUploading,
    fileName,
    processingProgress,
    dataFormat,
    aiEnrichment,
    processFile
  };
};
