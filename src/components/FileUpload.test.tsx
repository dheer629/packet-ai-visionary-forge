import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import FileUpload from './FileUpload';

const { processFile } = vi.hoisted(() => ({ processFile: vi.fn().mockResolvedValue(undefined) }));
vi.mock('../hooks/useFileProcessor', () => ({
  useFileProcessor: () => ({
    isUploading: false, isPaused: false, fileName: null, processingProgress: 0,
    dataFormat: null, processingError: null, checkpoint: null, processFile,
    pauseDecode: vi.fn(), resumeDecode: vi.fn(), cancelDecode: vi.fn(), discardCheckpoint: vi.fn(),
  }),
}));

afterEach(() => { cleanup(); processFile.mockClear(); });
describe('capture selection and analysis', () => {
  it('analyzes the selected file when Analyze is clicked, including repeat analysis', async () => {
    const { container } = render(<FileUpload onFileUpload={vi.fn()} />);
    const file = new File([new Uint8Array(24)], 'selected.pcap');
    const input = container.querySelector('input[type=file]');
    if (!input) throw new Error('Missing capture input');
    fireEvent.change(input, { target: { files: [file] } });
    expect(processFile).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Analyze PCAP' }));
    await waitFor(() => expect(processFile).toHaveBeenCalledWith(file));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze PCAP' }));
    expect(processFile).toHaveBeenCalledTimes(2);
  });

  it('analyzes the actual dropped file', async () => {
    const { container } = render(<FileUpload onFileUpload={vi.fn()} />);
    const input = container.querySelector('input[type=file]');
    const dropTarget = input?.parentElement;
    if (!dropTarget) throw new Error('Missing drop target');
    const file = new File([new Uint8Array(24)], 'dropped.pcapng');
    fireEvent.drop(dropTarget, { dataTransfer: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze PCAP' }));
    await waitFor(() => expect(processFile).toHaveBeenCalledWith(file));
  });
});