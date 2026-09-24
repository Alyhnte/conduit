"use strict";

/**
 * Guest script for one Frida session. The host loads this source and talks
 * JSON over send/recv plus rpc.exports.
 *
 * Hardware execute breakpoints use thread slots 0..3. Slot 4 does not throw
 * and does not trap, so the slot count lives here. Continuing from a hit
 * disarms that slot: Frida's CpuContext has no rflags/eflags to set the
 * resume flag, and returning with the breakpoint still armed re-traps the
 * same instruction.
 *
 * Registers and the call stack are captured only inside the exception
 * handler (last hit). There is no thread suspend or single-step API.
 */

const SLOT_COUNT = 4;
const slots = new Array(SLOT_COUNT).fill(null);
let armedThread = null;

function mainThread() {
  if (armedThread === null) {
    armedThread = Process.enumerateThreads()[0];
  }
  return armedThread;
}

function canonical(address) {
  return ptr(address).toString();
}

function moduleLabel(address) {
  const mod = Process.findModuleByAddress(address);
  if (mod === null) {
    return null;
  }
  return mod.name.replace(/\.(exe|dll)$/i, "");
}

function mainModule() {
  const mods = Process.enumerateModules();
  const want = typeof TARGET_NAME === "string" ? TARGET_NAME.toLowerCase() : "";
  for (let i = 0; i < mods.length; i += 1) {
    if (mods[i].name.toLowerCase() === want) {
      return mods[i];
    }
  }
  for (let i = 0; i < mods.length; i += 1) {
    if (/\.exe$/i.test(mods[i].name)) {
      return mods[i];
    }
  }
  return mods[0];
}

function hexOf(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const value = bytes[i];
    hex += (value < 16 ? "0" : "") + value.toString(16);
  }
  return hex;
}

function threadIp(thread) {
  try {
    const ctx = thread.context;
    return Process.arch === "ia32" ? ctx.eip : ctx.rip;
  } catch (error) {
    return null;
  }
}

function readEntry(mod) {
  const base = mod.base;
  const pe = base.add(base.add(0x3c).readU32());
  const entryRva = pe.add(40).readU32();
  return base.add(entryRva);
}

function findSlot(address) {
  const want = canonical(address);
  for (let i = 0; i < slots.length; i += 1) {
    if (slots[i] === want) {
      return i;
    }
  }
  return -1;
}

function freeSlot() {
  for (let i = 0; i < slots.length; i += 1) {
    if (slots[i] === null) {
      return i;
    }
  }
  return -1;
}

function generalRegisters(ctx) {
  const names = Process.arch === "ia32"
    ? ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
    : ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
  const general = {};
  for (let i = 0; i < names.length; i += 1) {
    const name = names[i];
    try {
      const value = ctx[name];
      if (value !== undefined && value !== null) {
        general[name] = value.toString();
      }
    } catch (error) {
      // Missing names stay absent. Do not invent a value.
    }
  }
  return general;
}

function captureHit(details) {
  const frames = [{
    index: 0,
    address: details.address.toString(),
    module: moduleLabel(details.address),
  }];
  let callers = [];
  try {
    callers = Thread.backtrace(details.context, Backtracer.ACCURATE);
  } catch (error) {
    callers = [];
  }
  for (let i = 0; i < callers.length && frames.length < 64; i += 1) {
    const addr = callers[i];
    frames.push({
      index: frames.length,
      address: addr.toString(),
      module: moduleLabel(addr),
    });
  }
  let threadId = 0;
  try {
    threadId = typeof Process.getCurrentThreadId === "function" ? Process.getCurrentThreadId() : mainThread().id;
  } catch (error) {
    threadId = mainThread().id;
  }
  return {
    type: "breakpoint_hit",
    exception: details.type,
    address: details.address.toString(),
    threadId: threadId,
    arch: Process.arch === "ia32" ? "x86" : Process.arch,
    general: generalRegisters(details.context),
    frames: frames,
  };
}

function disarm(address) {
  const index = findSlot(address);
  if (index < 0) {
    return false;
  }
  try {
    mainThread().unsetHardwareBreakpoint(index);
  } catch (error) {
    // The slot is still dropped locally so a later continue cannot spin.
  }
  slots[index] = null;
  return true;
}

rpc.exports = {
  describe: function describe() {
    const mod = mainModule();
    const arch = Process.arch === "ia32" ? "x86" : Process.arch;
    return {
      arch: arch,
      moduleBase: mod.base.toString(),
      entry: readEntry(mod).toString(),
      module: mod.name.replace(/\.(exe|dll)$/i, ""),
      path: mod.path,
    };
  },
  setBreakpoint: function setBreakpoint(address) {
    const want = canonical(address);
    const existing = findSlot(want);
    if (existing >= 0) {
      return { address: want, slot: existing };
    }
    const index = freeSlot();
    if (index < 0) {
      throw new Error("no_breakpoint_slot");
    }
    mainThread().setHardwareBreakpoint(index, ptr(want));
    slots[index] = want;
    return { address: want, slot: index };
  },
  removeBreakpoint: function removeBreakpoint(address) {
    const want = canonical(address);
    if (!disarm(want)) {
      throw new Error("missing breakpoint");
    }
    return { removed: true, address: want };
  },
  listBreakpoints: function listBreakpoints() {
    const out = [];
    for (let i = 0; i < slots.length; i += 1) {
      if (slots[i] !== null) {
        out.push({ slot: i, address: slots[i], type: "hardware_execute", enabled: true });
      }
    }
    return out;
  },
  readMemory: function readMemory(address, size) {
    const n = Math.min(Math.max(size, 1), 65536);
    const raw = ptr(address).readByteArray(n);
    if (raw === null) {
      throw new Error("unmapped");
    }
    const hex = hexOf(raw);
    let ascii = "";
    for (let i = 0; i < hex.length; i += 2) {
      const value = parseInt(hex.substr(i, 2), 16);
      ascii += value >= 32 && value < 127 ? String.fromCharCode(value) : ".";
    }
    return { address: ptr(address).toString(), size: hex.length / 2, hex: hex, ascii: ascii };
  },
  writeMemory: function writeMemory(address, hex) {
    const clean = String(hex).replace(/\s+/g, "");
    if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
      throw new Error("hex bytes rejected");
    }
    const bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    const target = ptr(address);
    const previous = Memory.protect(target, bytes.length, "rwx");
    target.writeByteArray(bytes);
    if (typeof previous === "string" && previous !== "") {
      try {
        Memory.protect(target, bytes.length, previous);
      } catch (error) {
        // The captured bytes are already written.
      }
    }
    return { address: target.toString(), bytesWritten: bytes.length };
  },
  searchMemory: function searchMemory(start, size, pattern, maxResults) {
    const cap = Math.min(size, 0x100000);
    const matches = Memory.scanSync(ptr(start), cap, pattern);
    const limited = [];
    const n = Math.min(matches.length, maxResults);
    for (let i = 0; i < n; i += 1) {
      limited.push({ address: matches[i].address.toString() });
    }
    return { matches: limited, totalFound: matches.length, truncated: matches.length > maxResults, scanned: cap };
  },
  disassemble: function disassemble(address, count) {
    let cur = ptr(address);
    const instructions = [];
    const n = Math.min(count, 64);
    for (let i = 0; i < n; i += 1) {
      let ins;
      try {
        ins = Instruction.parse(cur);
      } catch (error) {
        break;
      }
      const raw = ins.address.readByteArray(ins.size);
      instructions.push({
        address: ins.address.toString(),
        bytes: raw === null ? "" : hexOf(raw),
        mnemonic: ins.mnemonic,
        operands: ins.opStr,
      });
      cur = ins.next;
    }
    return { startAddress: ptr(address).toString(), instructions: instructions };
  },
  instructionPointer: function instructionPointer() {
    const mod = mainModule();
    const threads = Process.enumerateThreads();
    for (let i = 0; i < threads.length; i += 1) {
      const ip = threadIp(threads[i]);
      if (ip !== null && ip.compare(mod.base) >= 0 && ip.compare(mod.base.add(mod.size)) < 0) {
        return ip.toString();
      }
    }
    if (threads.length === 0) {
      throw new Error("no threads");
    }
    const ip = threadIp(threads[0]);
    if (ip === null) {
      throw new Error("no instruction pointer");
    }
    return ip.toString();
  },
  moduleRange: function moduleRange() {
    const mod = mainModule();
    return { base: mod.base.toString(), size: mod.size };
  },
  listThreads: function listThreads() {
    const threads = Process.enumerateThreads();
    let activeId = threads.length > 0 ? threads[0].id : 0;
    const mod = mainModule();
    const rows = [];
    for (let i = 0; i < threads.length; i += 1) {
      const thread = threads[i];
      const ip = threadIp(thread);
      const inside = ip !== null && ip.compare(mod.base) >= 0 && ip.compare(mod.base.add(mod.size)) < 0;
      if (inside) {
        activeId = thread.id;
      }
      rows.push({
        id: thread.id,
        state: thread.state,
        entry: thread.entrypoint ? thread.entrypoint.toString() : null,
        current: false,
      });
    }
    for (let i = 0; i < rows.length; i += 1) {
      rows[i].current = rows[i].id === activeId;
    }
    return { activeThreadId: activeId, threads: rows };
  },
  threadContext: function threadContext(id) {
    const threads = Process.enumerateThreads();
    let thread = null;
    for (let i = 0; i < threads.length; i += 1) {
      if (threads[i].id === id) {
        thread = threads[i];
      }
    }
    if (thread === null) {
      throw new Error("missing thread");
    }
    return { threadId: id, general: generalRegisters(thread.context) };
  },
  applyRegisters: function applyRegisters(id, general) {
    const threads = Process.enumerateThreads();
    let thread = null;
    for (let i = 0; i < threads.length; i += 1) {
      if (threads[i].id === id) {
        thread = threads[i];
      }
    }
    if (thread === null) {
      throw new Error("missing thread");
    }
    try {
      const ctx = thread.context;
      const names = Object.keys(general);
      for (let i = 0; i < names.length; i += 1) {
        const name = names[i];
        if (ctx[name] === undefined || ctx[name] === null) {
          continue;
        }
        ctx[name] = ptr(general[name]);
      }
      thread.context = ctx;
    } catch (error) {
      throw new Error("capability_unsupported");
    }
    return { applied: true };
  },
};

Process.setExceptionHandler(function onException(details) {
  const index = findSlot(details.address);
  send(captureHit(details));
  recv("resume", function onResume() {}).wait();
  // Unset by the index captured at the hit. A remove() during the wait
  // clears the slot map, but the debug register can still be armed until
  // this thread object clears it. Returning while it is armed re-traps.
  if (index >= 0) {
    try {
      mainThread().unsetHardwareBreakpoint(index);
    } catch (error) {
      send({ type: "breakpoint_consumed", address: details.address.toString(), slot: index, error: String(error) });
      slots[index] = null;
      return true;
    }
    slots[index] = null;
    send({ type: "breakpoint_consumed", address: details.address.toString(), slot: index });
  }
  return true;
});
