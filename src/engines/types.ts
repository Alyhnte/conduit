/** Engine identity stored on an application session. Not an MCP protocol session. */
export const ENGINE_IDS = ["radare2", "x64dbg", "cdb", "frida"] as const;

export type EngineId = (typeof ENGINE_IDS)[number];

/** Live-debug engines. Static analysis stays on radare2. */
export const DEBUG_ENGINE_IDS = ["x64dbg", "cdb", "frida"] as const;

export type DebugEngineId = (typeof DEBUG_ENGINE_IDS)[number];

export type EngineKind = "static" | "debug";

/**
 * Kind is a property of the engine id. Sessions do not store it separately.
 * cdb and frida are debug ids even before an implementation is registered.
 */
export function isDebugEngineId(id: EngineId): id is DebugEngineId {
  switch (id) {
    case "x64dbg":
    case "cdb":
    case "frida":
      return true;
    case "radare2":
      return false;
    default: {
      const unreachable: never = id;
      return unreachable;
    }
  }
}

export function engineKind(id: EngineId): EngineKind {
  return isDebugEngineId(id) ? "debug" : "static";
}

/**
 * What a concrete engine can do. Flags stay false until that engine is filled in.
 * Callers must not assume a flag implies a working implementation.
 */
export interface Capabilities {
  kind: EngineKind;
  disassembly: boolean;
  symbols: boolean;
  readMemory: boolean;
  writeMemory: boolean;
  breakpoints: boolean;
  registers: boolean;
  modules: boolean;
  threads: boolean;
}

/** Static analysis engine (radare2). Transport and session policy live outside the engine. */
export interface StaticEngine {
  readonly id: "radare2";
  readonly capabilities: Capabilities;
  open(sessionId: string, targetPath: string): Promise<void>;
  close(sessionId: string): Promise<void>;
}

/** Live debugger engine. Transport and session policy live outside the engine. */
export interface DebugEngine {
  readonly id: DebugEngineId;
  readonly capabilities: Capabilities;
  open(sessionId: string, target: string, opts?: unknown): Promise<unknown>;
  close(sessionId: string): Promise<void>;
}
