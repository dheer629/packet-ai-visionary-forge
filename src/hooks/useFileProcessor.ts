import { useCallback, useEffect, useRef, useState } from 'react';
import { processPcapFile } from '../utils/pcapProcessor';
import { useToast } from '@/components/ui/use-toast';
import { enhancePacketData, ProcessedData } from '../utils/packetEnhancer';
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
  const [processingError, setProcessingError] = useState<string | null>(null);
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
    if (!file || controllerRef.current) return;
    setProcessingError(null);

    const normalizedName = file.name.toLowerCase();
    if (!normalizedName.endsWith('.pcap') && !normalizedName.endsWith('.pcapng') && !normalizedName.endsWith('.cap')) {
      toast({
        title: 'Invalid File',
        description: 'Please upload a valid PCAP, PCAPNG, or CAP file',
        variant: 'destructive',
      });
      return;
    }

    if (file.size > 500 * 1024 * 1024) {
      toast({
        title: 'Capture too large',
        description: 'Please select a capture up to 500 MB.',
        variant: 'destructive',
      });
      return;
    }

    const controller = new DecodeController();
    controllerRef.current = controller;
    const isNg = normalizedName.endsWith('.pcapng');
    setFileName(file.name);
    setIsUploading(true);
    setIsPaused(false);
    setProcessingProgress(0);
    setDataFormat(isNg ? 'PCAPNG' : 'PCAP');

    try {
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

      const progressCallback = (progress: number) => {
        setProcessingProgress(Math.round(progress * 100));
      };

      const analysisData = await processPcapFile(file, progressCallback, controller, {
        resume,
        checkpoint: writer,
      });

      if (!analysisData || !Array.isArray(analysisData.packets)) {
        throw new Error('The capture parser did not return packet records.');
      }

      const enhancedData = enhancePacketData(analysisData, file);
      // Offline decoding must never depend on credentials, network access or AI.
      onFileUpload(enhancedData);

      toast({
        title: 'Analysis Complete',
        description: enhancedData.packets.length === 0
          ? `${file.name} contains no decoded packet records.`
          : `Successfully processed ${file.name} (${enhancedData.summary.totalPackets} packets)`,
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
      setProcessingError(error instanceof Error ? error.message : 'Unknown processing error');
      toast({
        title: 'Processing Error',
        description: `Failed to process the PCAP file: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: 'destructive',
      });

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
    processingError,
    checkpoint,
    processFile,
    pauseDecode,
    resumeDecode,
    cancelDecode,
    discardCheckpoint,
  };
};
