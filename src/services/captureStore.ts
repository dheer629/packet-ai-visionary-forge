import { supabase } from '@/integrations/supabase/client';

const BUCKET = 'captures';

export interface SavedCapture {
  id: string;
  filename: string;
  file_size: number;
  packet_count: number;
  protocol_summary: any;
  storage_path: string;
  created_at: string;
}

/** Saves the full decoded analysis for the signed-in user (file + metadata row). */
export const saveCapture = async (analysis: any): Promise<SavedCapture> => {
  const { data: userData } = await supabase.auth.getUser();
  const user = userData.user;
  if (!user) throw new Error('Sign in to save captures.');

  const id = crypto.randomUUID();
  const storagePath = `${user.id}/${id}.json`;
  const blob = new Blob([JSON.stringify(analysis)], { type: 'application/json' });

  const { error: uploadError } = await supabase.storage
    .from(BUCKET)
    .upload(storagePath, blob, { contentType: 'application/json', upsert: false });
  if (uploadError) throw new Error(uploadError.message);

  const { data, error } = await supabase
    .from('captures')
    .insert({
      id,
      user_id: user.id,
      filename: analysis?.filename || 'capture',
      file_size: analysis?.size || 0,
      packet_count: analysis?.summary?.totalPackets || analysis?.packets?.length || 0,
      protocol_summary: analysis?.summary?.protocolCounts ?? null,
      storage_path: storagePath,
    })
    .select()
    .single();

  if (error) {
    await supabase.storage.from(BUCKET).remove([storagePath]);
    throw new Error(error.message);
  }
  return data as SavedCapture;
};

export const listCaptures = async (): Promise<SavedCapture[]> => {
  const { data, error } = await supabase
    .from('captures')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) throw new Error(error.message);
  return (data ?? []) as SavedCapture[];
};

export const loadCapture = async (capture: SavedCapture): Promise<any> => {
  const { data, error } = await supabase.storage.from(BUCKET).download(capture.storage_path);
  if (error) throw new Error(error.message);
  const analysis = JSON.parse(await data.text());
  // Captures saved by older versions keep working: their view is migrated.
  if (analysis && typeof analysis === 'object' && analysis.viewState) {
    analysis.viewState = migrateViewState(analysis.viewState);
  }
  return analysis;
};


export const deleteCapture = async (capture: SavedCapture): Promise<void> => {
  await supabase.storage.from(BUCKET).remove([capture.storage_path]);
  const { error } = await supabase.from('captures').delete().eq('id', capture.id);
  if (error) throw new Error(error.message);
};
