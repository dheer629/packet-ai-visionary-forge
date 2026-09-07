/**
 * Decode checkpointing.
 *
 * Long decodes periodically persist their real progress (byte offset in the
 * capture + the packets decoded so far) into IndexedDB. If the tab is
 * refreshed, crashes or the network drops, the next session can continue from
 * the last checkpoint instead of decoding the file again from byte 0.
 *
 * The capture bytes themselves are never stored — the browser cannot keep a
 * File handle across reloads — so the user re-selects the same file and we
 * verify name + size + lastModified before resuming.
 */

const DB_NAME = 'pcap-decode-checkpoints';
const DB_VERSION = 1;
const META_STORE = 'meta';
const CHUNK_STORE = 'chunks';
const META_KEY = 'current';

export interface CheckpointMeta {
  fileName: string;
  fileSize: number;
  lastModified: number;
  format: 'pcap' | 'pcapng';
  offset: number;
  packetCount: number;
  chunks: number;
  interfaces?: any[];
  updatedAt: number;
}

const openDb = (): Promise<IDBDatabase> =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) db.createObjectStore(META_STORE);
      if (!db.objectStoreNames.contains(CHUNK_STORE)) db.createObjectStore(CHUNK_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

const tx = <T>(store: string, mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> =>
  openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(store, mode);
        const request = run(transaction.objectStore(store));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        transaction.oncomplete = () => db.close();
      })
  );

export const isCheckpointSupported = () => typeof indexedDB !== 'undefined';

export const loadCheckpointMeta = async (): Promise<CheckpointMeta | null> => {
  if (!isCheckpointSupported()) return null;
  try {
    return (await tx<CheckpointMeta | undefined>(META_STORE, 'readonly', (s) => s.get(META_KEY))) ?? null;
  } catch {
    return null;
  }
};

export const loadCheckpointPackets = async (meta: CheckpointMeta): Promise<any[]> => {
  const packets: any[] = [];
  for (let i = 0; i < meta.chunks; i++) {
    const chunk = await tx<any[] | undefined>(CHUNK_STORE, 'readonly', (s) => s.get(i));
    if (Array.isArray(chunk)) packets.push(...chunk);
  }
  return packets;
};

export const clearCheckpoint = async () => {
  if (!isCheckpointSupported()) return;
  try {
    await tx(META_STORE, 'readwrite', (s) => s.delete(META_KEY));
    await tx(CHUNK_STORE, 'readwrite', (s) => s.clear());
  } catch {
    /* storage unavailable — decoding still works, just without resume */
  }
};

/** Does this file match the stored checkpoint? */
export const checkpointMatchesFile = (meta: CheckpointMeta | null, file: File) =>
  Boolean(
    meta &&
      meta.fileName === file.name &&
      meta.fileSize === file.size &&
      meta.lastModified === file.lastModified &&
      meta.packetCount > 0
  );

/** Writer used by the parser while decoding one specific file. */
export class CheckpointWriter {
  private chunks = 0;
  private failed = false;

  constructor(
    private readonly file: { name: string; size: number; lastModified: number },
    private readonly format: 'pcap' | 'pcapng',
    startChunks = 0
  ) {
    this.chunks = startChunks;
  }

  async save(state: { offset: number; packetCount: number; newPackets: any[]; interfaces?: any[] }) {
    if (this.failed || !isCheckpointSupported()) return;
    try {
      if (state.newPackets.length > 0) {
        const index = this.chunks;
        await tx(CHUNK_STORE, 'readwrite', (s) => s.put(state.newPackets, index));
        this.chunks += 1;
      }
      const meta: CheckpointMeta = {
        fileName: this.file.name,
        fileSize: this.file.size,
        lastModified: this.file.lastModified,
        format: this.format,
        offset: state.offset,
        packetCount: state.packetCount,
        chunks: this.chunks,
        interfaces: state.interfaces,
        updatedAt: Date.now(),
      };
      await tx(META_STORE, 'readwrite', (s) => s.put(meta, META_KEY));
    } catch (error) {
      // Quota or private-mode failure: stop checkpointing, keep decoding.
      console.warn('Decode checkpoint could not be saved:', error);
      this.failed = true;
    }
  }

  async clear() {
    await clearCheckpoint();
  }
}
