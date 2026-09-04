import React, { useMemo, useState } from 'react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { decoderCapabilities, capabilitySummary, CapabilityLevel } from '@/utils/decoders/capabilities';

const levelClass: Record<CapabilityLevel, string> = {
  Available: 'bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/40',
  Partial: 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/40',
  Unavailable: 'bg-muted text-muted-foreground border border-border',
};

const DecoderCapabilities: React.FC = () => {
  const [query, setQuery] = useState('');
  const summary = useMemo(() => capabilitySummary(), []);

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = decoderCapabilities.filter(
      c => !q || c.name.toLowerCase().includes(q) || c.notes.toLowerCase().includes(q) || c.layer.toLowerCase().includes(q),
    );
    return filtered.reduce<Record<string, typeof decoderCapabilities>>((acc, c) => {
      (acc[c.layer] ||= []).push(c);
      return acc;
    }, {});
  }, [query]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Badge className={levelClass.Available}>{summary.available} fully decoded</Badge>
        <Badge className={levelClass.Partial}>{summary.partial} partial</Badge>
        <Badge className={levelClass.Unavailable}>{summary.unavailable} not decoded</Badge>
        <span className="text-xs text-muted-foreground">
          Levels describe what this decoder actually reads from the captured bytes.
        </span>
      </div>

      <Input
        value={query}
        onChange={e => setQuery(e.target.value)}
        placeholder="Filter protocols (e.g. GTP, VLAN, TLS)"
        className="max-w-sm"
      />

      <div className="space-y-5">
        {Object.entries(groups).map(([layer, items]) => (
          <div key={layer}>
            <h4 className="mb-2 text-sm font-semibold cyber-text">{layer}</h4>
            <div className="grid gap-2 md:grid-cols-2">
              {items.map(cap => (
                <div key={cap.id} className="rounded-md border border-cyber-border bg-cyber-muted/30 p-3">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-sm font-medium">{cap.name}</span>
                    <Badge className={`${levelClass[cap.level]} shrink-0 text-[10px]`}>{cap.level}</Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{cap.notes}</p>
                </div>
              ))}
            </div>
          </div>
        ))}
        {Object.keys(groups).length === 0 && (
          <p className="text-sm text-muted-foreground">No protocol matches that filter.</p>
        )}
      </div>
    </div>
  );
};

export default DecoderCapabilities;
