import React, { useMemo, useState } from 'react';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { analyzeTcpFlows, renderStreamText, streamForPacket } from '@/utils/tcpAnalysis';

interface StreamFollowerProps { packets: any[]; packetNumber: number; open: boolean; onOpenChange: (open: boolean) => void; }

const StreamFollower: React.FC<StreamFollowerProps> = ({ packets, packetNumber, open, onOpenChange }) => {
  const [direction, setDirection] = useState<'both' | 0 | 1>('both');
  const flow = useMemo(() => streamForPacket(analyzeTcpFlows(packets), packetNumber), [packets, packetNumber]);
  const text = useMemo(() => flow ? renderStreamText(flow, direction) : '', [flow, direction]);

  const download = () => {
    if (!flow) return;
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url; link.download = `tcp-stream-${packetNumber}.txt`; link.click(); URL.revokeObjectURL(url);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader><DialogTitle>Follow TCP Stream</DialogTitle><DialogDescription>{flow?.key ?? 'No TCP stream is available for this frame.'}</DialogDescription></DialogHeader>
        {flow && <>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant={direction === 'both' ? 'default' : 'outline'} onClick={() => setDirection('both')}>Both directions</Button>
            <Button size="sm" variant={direction === 0 ? 'default' : 'outline'} onClick={() => setDirection(0)}>{flow.endpoints[0]} →</Button>
            <Button size="sm" variant={direction === 1 ? 'default' : 'outline'} onClick={() => setDirection(1)}>{flow.endpoints[1]} →</Button>
            <Button size="sm" variant="outline" onClick={download}><Download className="mr-1 h-4 w-4" />Download</Button>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-5">
            <span>Chunks: {flow.chunks.length}</span><span>Gaps: {flow.gaps}</span><span>Retransmissions: {flow.retransmissions}</span><span>Dup ACKs: {flow.duplicateAcks}</span><span>Zero windows: {flow.zeroWindows}</span>
          </div>
          <pre className="max-h-[55vh] overflow-auto whitespace-pre-wrap break-all border border-cyber-border bg-cyber-muted p-3 font-mono text-xs">{text || 'This flow contains no captured TCP payload bytes.'}</pre>
        </>}
      </DialogContent>
    </Dialog>
  );
};

export default StreamFollower;