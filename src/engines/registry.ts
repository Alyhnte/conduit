import { cdbEngine, type CdbEngine } from "./cdb.js";
import { fridaEngine, type FridaEngine } from "./frida.js";
import { x64dbgEngine, type X64dbgEngine } from "./x64dbg.js";
import type { DebugEngineId } from "./types.js";

/** Registered debug-engine instances, keyed by id. */
export type LiveDebugEngine = X64dbgEngine | CdbEngine | FridaEngine;

const debugEngines = {
  x64dbg: x64dbgEngine,
  cdb: cdbEngine,
  frida: fridaEngine,
} as const satisfies Record<DebugEngineId, LiveDebugEngine>;

export function getDebugEngine(id: DebugEngineId): LiveDebugEngine {
  switch (id) {
    case "x64dbg":
      return debugEngines.x64dbg;
    case "cdb":
      return debugEngines.cdb;
    case "frida":
      return debugEngines.frida;
    default: {
      const unreachable: never = id;
      return unreachable;
    }
  }
}

/** Best-effort teardown of every registered debug engine for one session. */
export async function closeRegisteredDebugEngines(sessionId: string): Promise<void> {
  let firstError: unknown;
  for (const engine of Object.values(debugEngines)) {
    try {
      await engine.close(sessionId);
    } catch (error) {
      if (firstError === undefined) {
        firstError = error;
      }
    }
  }
  if (firstError !== undefined) {
    throw firstError;
  }
}
