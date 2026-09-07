import { useCallback, useEffect, useRef, useState } from 'react';
import { processPcapFile } from '../utils/pcapProcessor';
import { useToast } from '@/components/ui/use-toast';
import { enhancePacketData, ProcessedData } from '../utils/packetEnhancer';
import { applyAIEnhancement, createFallbackData } from '../utils/aiEnhancement';
import { DecodeController, isDecodeCancelled } from '../utils/decodeControl';
import {
  CheckpointMeta,
  CheckpointWriter,
  checkpointMatchesFile,
  clearCheckpoint,
  loadCheckpointMeta,
  loadCheckpointPackets,
} from '../utils/decodeCheckpoint';

export type { ProcessedData } from '../utils/packetEnhancer';

export const useFileProcessor = (onFileUpload: (data: ProcessedData) => void) => {
  const { toast } = useToast();
  const [isUploading, setIsUploading] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [dataFormat, setDataFormat] = useState<string | null>(null);
  const [aiEnrichment, setAiEnrichment] = useState<boolean>(false);
  const [checkpoint, setCheckpoint] = useState<CheckpointMeta | null>(null);
  const controllerRef = useRef<DecodeController | null>(null);

  // Surface an unfinished decode from a previous session (refresh / crash).
  useEffect(() => {
    let active = true;
    loadCheckpointMeta().then((meta) => {
      if (active && meta && meta.packetCount > 0) setCheckpoint(meta);
    });
    return () => {
      active = false;
    };
  }, []);

  const discardCheckpoint = useCallback(async () => {
    await clearCheckpoint();
    setCheckpoint(null);
  }, []);

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

    const isNg = file.name.endsWith('.pcapng');
    setFileName(file.name);
    setIsUploading(true);
    setIsPaused(false);
    setProcessingProgress(0);
    setDataFormat(isNg ? 'PCAPNG' : 'PCAP');

    // Resume from a stored checkpoint when the same file is selected again.
    const storedMeta = checkpoint ?? (await loadCheckpointMeta());
    let resume: { offset: number; packets: any[]; interfaces?: any[] } | undefined;
    let startChunks = 0;

    if (checkpointMatchesFile(storedMeta, file) && storedMeta) {
      try {
        const packets = await loadCheckpointPackets(storedMeta);
        if (packets.length > 0) {
          resume = { offset: storedMeta.offset, packets, interfaces: storedMeta.interfaces };
          startChunks = storedMeta.chunks;
          toast({
            title: 'Resuming decode',
            description: `Continuing ${file.name} from packet ${packets.length.toLocaleString()} (byte ${storedMeta.offset.toLocaleString()}).`,
          });
        }
      } catch (error) {
        console.warn('Could not restore decode checkpoint:', error);
      }
    } else if (storedMeta) {
      await clearCheckpoint();
    }
    setCheckpoint(null);

    const writer = new CheckpointWriter(
      { name: file.name, size: file.size, lastModified: file.lastModified },
      isNg ? 'pcapng' : 'pcap',
      startChunks
    );

    try {
      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };

      let analysisData = await processPcapFile(file, progressCallback, controller, {
        resume,
        checkpoint: writer,
      });

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
        await clearCheckpoint();
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
      loadCheckpointMeta().then((meta) => setCheckpoint(meta && meta.packetCount > 0 ? meta : null));
    }
  };

  return {
    isUploading,
    isPaused,
    fileName,
    processingProgress,
    dataFormat,
    aiEnrichment,
    checkpoint,
    processFile,
    pauseDecode,
    resumeDecode,
    cancelDecode,
    discardCheckpoint,
  };
};
