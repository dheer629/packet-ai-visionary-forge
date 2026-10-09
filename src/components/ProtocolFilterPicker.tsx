import { useMemo, useState } from 'react';
import { Check, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { ProtocolChoice } from '@/utils/protocolFilters';

interface Props { choices: ProtocolChoice[]; selected: string[]; onToggle: (name: string) => void; }

export default function ProtocolFilterPicker({ choices, selected, onToggle }: Props) {
  const [search, setSearch] = useState('');
  const matches = useMemo(() => choices.filter((choice) => choice.name.toLowerCase().includes(search.toLowerCase())), [choices, search]);
  return <details className="mb-3 border border-border rounded-md bg-background">
    <summary className="cursor-pointer p-3 text-sm font-medium">All protocols <span className="text-muted-foreground">({choices.length})</span></summary>
    <div className="px-3 pb-3">
      <div className="relative mb-2">
        <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input aria-label="Search protocols" placeholder="Search protocols" className="pl-8" value={search} onChange={(event) => setSearch(event.target.value)} />
      </div>
      <div className="max-h-64 overflow-y-auto grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1">
        {matches.map((choice) => <Button key={choice.name} variant={selected.includes(choice.name) ? 'secondary' : 'ghost'}
          className="h-auto min-h-10 justify-between gap-2 text-left whitespace-normal" title={choice.notes}
          aria-pressed={selected.includes(choice.name)} disabled={!choice.count} onClick={() => onToggle(choice.name)}>
          <span className="flex items-center gap-1 min-w-0 break-words">{selected.includes(choice.name) && <Check className="h-3 w-3 shrink-0" />}{choice.name}</span>
          <span className="text-[10px] text-muted-foreground shrink-0 text-right">{choice.level === 'Available' ? 'Full' : choice.level === 'Unregistered' ? 'Not declared' : choice.level}<br />{choice.count ? `${choice.count} frames` : 'Not observed'}</span>
        </Button>)}
      </div>
      {!matches.length && <p className="py-3 text-sm text-muted-foreground">No matching protocols</p>}
    </div>
  </details>;
}