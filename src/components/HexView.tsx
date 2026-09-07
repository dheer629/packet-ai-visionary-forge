import React, { useMemo, useState } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';

interface HexViewProps {
  packet: any;
}

interface Range {
  key: string;
  label: string;
  layer: string;
  offset: number;
  length: number;
}

/** Rebuilds the raw bytes from the stored hex dump (no extra memory per packet). */
const parseHexDump = (dump: string): Uint8Array => {
  if (!dump) return new Uint8Array(0);
  const out: number[] = [];
  for (const line of dump.split('\n')) {
    const m = line.match(/^([0-9a-fA-F]+):\s(.*)$/);
    if (!m) continue;
    const hexPart = m[2].slice(0, 48);
    for (const pair of hexPart.match(/[0-9a-fA-F]{2}/g) || []) {
      out.push(parseInt(pair, 16));
    }
  }
  return Uint8Array.from(out);
};

const HexView: React.FC<HexViewProps> = ({ packet }) => {
  const bytes = useMemo(() => parseHexDump(packet?.hexDump || ''), [packet?.hexDump]);
  const [active, setActive] = useState<string | null>(null);

  const layers = (packet?.decodedLayers || []) as any[];

  // Field-level ranges, falling back to the layer range when a decoder does not
  // record per-field offsets for that header.
  const ranges = useMemo<Range[]>(() => {
    const list: Range[] = [];
    layers.forEach((layer, li) => {
      const fieldOffsets = layer.fieldOffsets || {};
      Object.entries(layer.fields || {}).forEach(([name, value]) => {
        const fo = fieldOffsets[name];
        list.push({
          key: `${li}:${name}`,
          label: `${name}: ${String(value)}`,
          layer: layer.name,
          offset: fo ? fo[0] : layer.offset,
          length: fo ? fo[1] : (layer.length ?? 0),
        });
      });
    });
    return list;
  }, [layers]);

  const byField = useMemo(() => {
    const map = new Map<number, Range>();
    ranges.forEach(r => {
      for (let i = r.offset; i < r.offset + r.length; i++) if (!map.has(i)) map.set(i, r);
    });
    return map;
  }, [ranges]);

  const activeRange = ranges.find(r => r.key === active) || null;
  const isHighlighted = (idx: number) =>
    activeRange ? idx >= activeRange.offset && idx < activeRange.offset + activeRange.length : false;

  if (!bytes.length) {
    return <p className="p-2 text-xs">No hex bytes captured for this packet.</p>;
  }

  const rows: number[][] = [];
  for (let i = 0; i < bytes.length; i += 16) rows.push(Array.from(bytes.slice(i, i + 16)));

  return (
    <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_240px]">
      <ScrollArea className="h-72 rounded border border-cyber-border">
        <div className="p-2 font-mono text-xs leading-6">
          {rows.map((row, ri) => (
            <div key={ri} className="flex whitespace-pre">
              <span className="mr-3 text-cyber-foreground/50">
                {(ri * 16).toString(16).padStart(4, '0')}
              </span>
              <span>
                {row.map((b, bi) => {
                  const idx = ri * 16 + bi;
                  const mapped = byField.get(idx);
                  return (
                    <span
                      key={bi}
                      title={mapped ? `${mapped.layer} — ${mapped.label}` : undefined}
                      onClick={() => mapped && setActive(mapped.key)}
                      className={`cursor-pointer rounded px-[1px] ${
                        isHighlighted(idx)
                          ? 'bg-cyber-primary text-white'
                          : mapped
                          ? 'hover:bg-cyber-muted'
                          : 'text-cyber-foreground/50'
                      }`}
                    >
                      {b.toString(16).padStart(2, '0')}
                    </span>
                  );
                }).reduce<React.ReactNode[]>((acc, el, i) => (i ? [...acc, ' ', el] : [el]), [])}
              </span>
              <span className="ml-4 text-cyber-foreground/70">
                {row.map((b, bi) => {
                  const idx = ri * 16 + bi;
                  return (
                    <span key={bi} className={isHighlighted(idx) ? 'bg-cyber-primary text-white' : ''}>
                      {b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'}
                    </span>
                  );
                })}
              </span>
            </div>
          ))}
        </div>
      </ScrollArea>

      <ScrollArea className="h-72 rounded border border-cyber-border">
        <div className="p-2 text-xs">
          {ranges.length === 0 && (
            <p className="text-cyber-foreground/70">No decoded fields for this packet.</p>
          )}
          {layers.map((layer, li) => (
            <div key={li} className="mb-2">
              <p className="font-mono text-cyber-accent">{layer.name}</p>
              {Object.keys(layer.fields || {}).map(name => {
                const key = `${li}:${name}`;
                const r = ranges.find(x => x.key === key);
                return (
                  <button
                    key={key}
                    onMouseEnter={() => setActive(key)}
                    onClick={() => setActive(key)}
                    className={`block w-full truncate rounded px-1 text-left ${
                      active === key ? 'bg-cyber-primary text-white' : 'hover:bg-cyber-muted'
                    }`}
                    title={r ? `${r.label} · offset ${r.offset}, ${r.length} bytes` : name}
                  >
                    {name}
                    {r && !layer.fieldOffsets?.[name] && (
                      <span className="ml-1 text-[10px] opacity-60">(layer range)</span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </ScrollArea>

      {activeRange && (
        <p className="md:col-span-2 text-xs text-cyber-foreground/80">
          <span className="font-mono text-cyber-accent">{activeRange.layer}</span> · {activeRange.label} ·
          bytes {activeRange.offset}–{activeRange.offset + Math.max(activeRange.length, 1) - 1}
        </p>
      )}
    </div>
  );
};

export default HexView;
