import { randomUUID } from "node:crypto";

import type { EngineId } from "./engines/types.js";

export interface BridgeEvent {
  seq: number;
  at: string;
  kind: string;
  data: unknown;
}

/**
 * Fixed-capacity ring of events for one application session.
 * Overflow drops the oldest event. Clients pull; nothing is pushed.
 * A gap between `after` and `retainedFrom` means those events are gone.
 */
export class EventBuffer {
  private readonly slots: Array<BridgeEvent | undefined>;
  private head = 0;
  private size = 0;
  private nextSeq = 1;

  constructor(readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new Error("EventBuffer capacity must be a positive integer");
    }
    this.slots = new Array<BridgeEvent | undefined>(capacity);
  }

  push(kind: string, data: unknown = null): BridgeEvent {
    const event: BridgeEvent = {
      seq: this.nextSeq,
      at: new Date().toISOString(),
      kind,
      data,
    };
    this.nextSeq += 1;
    this.slots[this.head] = event;
    this.head = (this.head + 1) % this.capacity;
    if (this.size < this.capacity) {
      this.size += 1;
    }
    return event;
  }

  /** Smallest sequence still stored, or null when the buffer is empty. */
  retainedFrom(): number | null {
    if (this.size === 0) {
      return null;
    }
    const start = (this.head - this.size + this.capacity) % this.capacity;
    return this.slots[start]?.seq ?? null;
  }

  /** Events with `seq > after`, oldest first, capped by `limit`. */
  pull(after = 0, limit = 100): BridgeEvent[] {
    const out: BridgeEvent[] = [];
    if (this.size === 0 || limit < 1) {
      return out;
    }
    const start = (this.head - this.size + this.capacity) % this.capacity;
    for (let i = 0; i < this.size && out.length < limit; i += 1) {
      const event = this.slots[(start + i) % this.capacity];
      if (event !== undefined && event.seq > after) {
        out.push(event);
      }
    }
    return out;
  }
}

export interface DebugSession {
  id: string;
  engine: EngineId;
  createdAt: string;
  events: EventBuffer;
}

export class SessionNotFoundError extends Error {
  readonly sessionId: string;

  constructor(sessionId: string) {
    super(`session not found: ${sessionId}`);
    this.name = "SessionNotFoundError";
    this.sessionId = sessionId;
  }
}

/**
 * In-process application sessions. The MCP transport stays stateless:
 * callers pass `session_id` on each tool call. There is no Mcp-Session-Id.
 */
export class SessionRegistry {
  private readonly sessions = new Map<string, DebugSession>();

  constructor(private readonly eventCapacity = 256) {}

  open(engine: EngineId): DebugSession {
    const session: DebugSession = {
      id: randomUUID(),
      engine,
      createdAt: new Date().toISOString(),
      events: new EventBuffer(this.eventCapacity),
    };
    session.events.push("session.opened", { engine });
    this.sessions.set(session.id, session);
    return session;
  }

  get(sessionId: string): DebugSession | undefined {
    return this.sessions.get(sessionId);
  }

  require(sessionId: string): DebugSession {
    const session = this.sessions.get(sessionId);
    if (session === undefined) {
      throw new SessionNotFoundError(sessionId);
    }
    return session;
  }

  close(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  list(): DebugSession[] {
    return [...this.sessions.values()];
  }

  get size(): number {
    return this.sessions.size;
  }
}

/** Process-wide registry shared by stdio and every stateless HTTP request. */
export const registry = new SessionRegistry();
