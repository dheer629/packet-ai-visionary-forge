import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useFileProcessor } from './useFileProcessor';

const mocks = vi.hoisted(() => ({
  parse: vi.fn(), enhance: vi.fn((data) => data), ai: vi.fn(), toast: vi.fn(),
}));
vi.mock('../utils/pcapProcessor', () => ({ processPcapFile: mocks.parse }));
vi.mock('../utils/packetEnhancer', () => ({ enhancePacketData: mocks.enhance }));
vi.mock('../utils/aiEnhancement', () => ({ applyAIEnhancement: mocks.ai }));
vi.mock('@/components/ui/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));

describe('offline packet publication', () => {
  it('publishes captured packets without waiting for or invoking AI', async () => {
    const data = { packets: [{ number: 1, protocol: 'UDP' }], summary: { totalPackets: 1 } };
    mocks.parse.mockResolvedValue(data);
    mocks.ai.mockImplementation(() => new Promise(() => {}));
    const onUpload = vi.fn();
    const { result } = renderHook(() => useFileProcessor(onUpload));
    await act(async () => { await result.current.processFile(new File(['bytes'], 'offline.pcap')); });
    expect(onUpload).toHaveBeenCalledWith(data);
    expect(mocks.ai).not.toHaveBeenCalled();
    expect(result.current.isUploading).toBe(false);
  });

  it('retains a processing error and allows retry rather than returning fabricated empty results', async () => {
    mocks.parse.mockRejectedValueOnce(new Error('Invalid capture header'));
    const onUpload = vi.fn();
    const { result } = renderHook(() => useFileProcessor(onUpload));
    const file = new File(['bad'], 'invalid.pcap');
    await act(async () => { await result.current.processFile(file); });
    expect(result.current.processingError).toBe('Invalid capture header');
    expect(onUpload).not.toHaveBeenCalled();
    expect(result.current.isUploading).toBe(false);
    mocks.parse.mockResolvedValueOnce({ packets: [], summary: { totalPackets: 0 } });
    await act(async () => { await result.current.processFile(file); });
    await waitFor(() => expect(result.current.processingError).toBeNull());
    expect(onUpload).toHaveBeenCalledTimes(1);
  });
});