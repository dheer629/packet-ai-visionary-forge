import React, { useMemo } from 'react';
import { AlertTriangle, CircleAlert, Info } from 'lucide-react';
import { analyzeTcpFlows } from '@/utils/tcpAnalysis';

const ExpertInfo: React.FC<{ packets: any[] }> = ({ packets }) => {
  const flows = useMemo(() => analyzeTcpFlows(packets), [packets]);
  const events = useMemo(() => flows.flatMap((flow) => flow.events).sort((a, b) => a.packetNumber - b.packetNumber), [flows]);

  if (events.length === 0) {
    return <div className="cyber-box text-sm text-cyber-foreground/70">No TCP expert events were derived from this capture.</div>;
  }

  return (
    <div className="cyber-box">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-medium cyber-text">Expert Info</h3>
        <span className="text-xs text-cyber-foreground/60">{events.length} evidence-linked events</span>
      </div>
      <div className="max-h-[520px] overflow-auto border border-cyber-border">
        {events.map((event, index) => {
          const Icon = event.severity === 'error' ? CircleAlert : event.severity === 'warning' ? AlertTriangle : Info;
          return (
            <div key={`${event.packetNumber}-${event.kind}-${index}`} className="grid grid-cols-[32px_90px_1fr] gap-2 border-b border-cyber-border p-2 text-xs last:border-b-0">
              <Icon className="h-4 w-4 text-cyber-accent" aria-label={event.severity} />
              <span className="font-mono">Frame {event.packetNumber}</span>
              <div><p className="font-medium">{event.summary}</p><p className="font-mono text-cyber-foreground/50">{event.flowKey}</p></div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ExpertInfo;