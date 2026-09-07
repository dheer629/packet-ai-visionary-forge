import React, { useCallback, useEffect, useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useToast } from '@/components/ui/use-toast';
import { Cloud, Loader2, Trash2, Save } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { deleteCapture, listCaptures, loadCapture, saveCapture, SavedCapture } from '@/services/captureStore';

interface SavedCapturesProps {
  analysisData: any;
  onLoad: (data: any) => void;
}

const formatSize = (bytes: number) =>
  bytes > 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;

const SavedCaptures: React.FC<SavedCapturesProps> = ({ analysisData, onLoad }) => {
  const { user } = useAuth();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<SavedCapture[]>([]);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!user) return;
    setBusy(true);
    try {
      setItems(await listCaptures());
    } catch (err: any) {
      toast({ title: 'Could not load your captures', description: err.message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  }, [user, toast]);

  useEffect(() => {
    if (open) void refresh();
  }, [open, refresh]);

  if (!user) return null;

  const handleSave = async () => {
    if (!analysisData) {
      toast({ title: 'Nothing to save', description: 'Upload and decode a capture first.' });
      return;
    }
    setBusy(true);
    try {
      await saveCapture(analysisData);
      toast({ title: 'Capture saved', description: `${analysisData.filename} is available on your other devices.` });
      await refresh();
    } catch (err: any) {
      toast({ title: 'Save failed', description: err.message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const handleLoad = async (item: SavedCapture) => {
    setBusy(true);
    try {
      onLoad(await loadCapture(item));
      setOpen(false);
      toast({ title: 'Capture loaded', description: item.filename });
    } catch (err: any) {
      toast({ title: 'Load failed', description: err.message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (item: SavedCapture) => {
    setBusy(true);
    try {
      await deleteCapture(item);
      await refresh();
    } catch (err: any) {
      toast({ title: 'Delete failed', description: err.message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          <Cloud className="h-4 w-4" /> My captures
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Saved captures</DialogTitle>
          <DialogDescription>
            Decoded results stored privately in your account — only you can open them.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center justify-between">
          <Button onClick={handleSave} disabled={busy || !analysisData} size="sm" className="gap-2">
            <Save className="h-4 w-4" /> Save current capture
          </Button>
          {busy && <Loader2 className="h-4 w-4 animate-spin text-cyber-primary" />}
        </div>

        <ScrollArea className="h-80 rounded border">
          {items.length === 0 && !busy && (
            <p className="p-4 text-sm text-gray-500">No captures saved yet.</p>
          )}
          <ul className="divide-y">
            {items.map(item => (
              <li key={item.id} className="flex items-center justify-between gap-3 p-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{item.filename}</p>
                  <p className="text-xs text-gray-500">
                    {item.packet_count.toLocaleString()} packets · {formatSize(item.file_size)} ·{' '}
                    {new Date(item.created_at).toLocaleString()}
                  </p>
                </div>
                <div className="flex shrink-0 gap-2">
                  <Button size="sm" variant="secondary" onClick={() => handleLoad(item)} disabled={busy}>
                    Open
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => handleDelete(item)} disabled={busy}>
                    <Trash2 className="h-4 w-4 text-red-500" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
};

export default SavedCaptures;
