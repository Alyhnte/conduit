/**
 * In-process checkpoints for one debug session.
 *
 * A checkpoint is the active thread's general registers, its instruction
 * pointer, the thread list, and one memory window. It is not a full-process
 * image and not an instruction trace of every core.
 */

export interface CheckpointThread {
  id: number;
  current: boolean;
  state: string | null;
  entry: string | null;
}

export interface Checkpoint {
  id: string;
  sessionId: string;
  at: string;
  engine: string;
  address: string;
  threadId: number | null;
  registers: Record<string, string>;
  threads: CheckpointThread[];
  memoryAddress: string;
  memoryHex: string;
  limits: string;
}

export const CHECKPOINT_LIMITS =
  "Each checkpoint stores the active thread's general registers, its instruction pointer, the thread list, and one memory window. " +
  "Rewind writes that window back and, on cdb and x64dbg, those registers. The timeline lists these checkpoints.";

const bySession = new Map<string, Checkpoint[]>();
let seq = 0;
const MAX_PER_SESSION = 32;

export function addCheckpoint(checkpoint: Omit<Checkpoint, "id" | "at" | "limits">): Checkpoint {
  const stored: Checkpoint = {
    ...checkpoint,
    id: `cp-${Date.now().toString(36)}-${(seq += 1)}`,
    at: new Date().toISOString(),
    limits: CHECKPOINT_LIMITS,
  };
  const list = bySession.get(checkpoint.sessionId) ?? [];
  list.push(stored);
  while (list.length > MAX_PER_SESSION) {
    list.shift();
  }
  bySession.set(checkpoint.sessionId, list);
  return stored;
}

export function listCheckpoints(sessionId: string): Checkpoint[] {
  return [...(bySession.get(sessionId) ?? [])];
}

export function getCheckpoint(sessionId: string, id: string): Checkpoint | undefined {
  return (bySession.get(sessionId) ?? []).find((row) => row.id === id);
}

export function clearCheckpoints(sessionId: string): void {
  bySession.delete(sessionId);
}
