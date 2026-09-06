import { useCallback, useRef, useState } from 'react';
import { processPcapFile } from '../utils/pcapProcessor';
import { useToast } from '@/components/ui/use-toast';
import { enhancePacketData, ProcessedData } from '../utils/packetEnhancer';
import { applyAIEnhancement, createFallbackData } from '../utils/aiEnhancement';
import { DecodeController, isDecodeCancelled } from '../utils/decodeControl';

export type { ProcessedData } from '../utils/packetEnhancer';

export const useFileProcessor = (onFileUpload: (data: ProcessedData) => void) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [dataFormat, setDataFormat] = useState<string | null>(null);
  const [aiEnrichment, setAiEnrichment] = useState<boolean>(false);
  const controllerRef = useRef<DecodeController | null>(null);

  const pauseDecode = useCallback(() => {
    controllerRef.current?.pause();
    setIsPaused(true);
  }, []);

  const resumeDecode = useCallback(() => {
    controllerRef.current?.resume();
    setIsPaused(false);
  }, []);

  const cancelDecode = useCallback(() => {
    controllerRef.current?.cancel();
    setIsPaused(false);
  }, []);

  const processFile = async (file: File) => {
    if (!file) return;

    if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
      toast({
        title: 'Invalid File',
        description: 'Please upload a valid PCAP or PCAPNG file',
        variant: 'destructive',
      });
      return;
    }

    const controller = new DecodeController();
    controllerRef.current = controller;

    setFileName(file.name);
    setIsUploading(true);
    setIsPaused(false);
    setProcessingProgress(0);
    setDataFormat(file.name.endsWith('.pcapng') ? 'PCAPNG' : 'PCAP');

    try {
      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };

      let analysisData = await processPcapFile(file, progressCallback, controller);

      if (!analysisData) {
        analysisData = { packets: [], summary: {} };
      }

      const enhancedData = enhancePacketData(analysisData, file);
      const aiEnhancedData = await applyAIEnhancement(enhancedData, setAiEnrichment, toast);

      onFileUpload(aiEnhancedData);

      toast({
        title: 'Analysis Complete',
        description: `Successfully processed ${file.name} (${aiEnhancedData.summary.totalPackets} packets)`,
      });
    } catch (error) {
      if (isDecodeCancelled(error)) {
        toast({
          title: 'Decode Cancelled',
          description: `Stopped decoding ${file.name}. No results were kept.`,
        });
        setProcessingProgress(0);
        return;
      }

      console.error('Error processing PCAP file:', error);
      toast({
        title: 'Processing Error',
        description: `Failed to process the PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: 'destructive',
      });

      onFileUpload(createFallbackData(file));
    } finally {
      controllerRef.current = null;
      setIsPaused(false);
      setIsUploading(false);
    }
  };

  return {
    isUploading,
    isPaused,
    fileName,
    processingProgress,
    dataFormat,
    aiEnrichment,
    processFile,
    pauseDecode,
    resumeDecode,
    cancelDecode,
  };
};
