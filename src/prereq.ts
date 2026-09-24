import { spawnSync } from "node:child_process";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { catalogEntry, type ToolCatalogEntry } from "./catalog.js";
import { resolveCdbExe } from "./engines/cdb.js";
import { x64dbgDirCandidates } from "./engines/x64dbg.js";

export interface ToolStatus {
  id: string;
  ad: string;
  zorunlu: boolean;
  durum: "var" | "yok";
  yol: string | null;
  oneri?: string;
  indir?: string;
  nereye?: string;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

function pathDirs(): string[] {
  return (process.env.PATH ?? "")
    .split(process.platform === "win32" ? ";" : ":")
    .map((part) => part.trim().replace(/^"(.*)"$/, "$1"))
    .filter((part) => part !== "");
}

async function findOnPath(names: readonly string[]): Promise<string | null> {
  for (const dir of pathDirs()) {
    for (const name of names) {
      const candidate = join(dir, name);
      if (await fileExists(candidate)) {
        return candidate;
      }
    }
  }
  return null;
}

async function findRadare2(): Promise<string | null> {
  const override = process.env.DBG_BRIDGE_R2;
  if (override !== undefined && override !== "" && (await fileExists(override))) {
    return override;
  }
  const names =
    process.platform === "win32"
      ? ["radare2.exe", "r2.exe", "radare2.bat", "r2.bat", "radare2.cmd", "r2.cmd"]
      : ["radare2", "r2"];
  return findOnPath(names);
}

async function findX64dbg(): Promise<string | null> {
  const relatives = ["x64/x64dbg.exe", "release/x64/x64dbg.exe", "x32/x32dbg.exe", "release/x32/x32dbg.exe"];
  for (const dir of x64dbgDirCandidates()) {
    for (const rel of relatives) {
      if (await fileExists(join(dir, rel))) {
        return dir;
      }
    }
  }
  return null;
}

async function findPythonDll(dir: string): Promise<boolean> {
  try {
    const names = await readdir(dir);
    return names.some((name) => /^python3\d*\.dll$/i.test(name));
  } catch {
    return false;
  }
}

function pythonBits(executable: string): number | null {
  const res = spawnSync(executable, ["-c", "import sys; print(64 if sys.maxsize>2**32 else 32)"], {
    encoding: "utf8",
    timeout: 8000,
    windowsHide: true,
  });
  const bits = Number((res.stdout ?? "").trim());
  return bits === 32 || bits === 64 ? bits : null;
}

async function findFridaPackage(): Promise<string | null> {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "..", "node_modules", "frida", "package.json"),
    join(here, "..", "..", "node_modules", "frida", "package.json"),
  ];
  for (const candidate of candidates) {
    if (await fileExists(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function findScyllaHide(x64dbgRoot: string | null): Promise<string | null> {
  if (x64dbgRoot === null) {
    return null;
  }
  for (const plugins of [join(x64dbgRoot, "x64", "plugins"), join(x64dbgRoot, "release", "x64", "plugins")]) {
    try {
      const names = await readdir(plugins);
      const hit = names.find((name) => /scyllahide/i.test(name) && /\.dp(32|64)$/i.test(name));
      if (hit !== undefined) {
        return join(plugins, hit);
      }
    } catch {
      // plugins directory missing
    }
  }
  return null;
}

function status(entry: ToolCatalogEntry, yol: string | null): ToolStatus {
  if (yol !== null) {
    return { id: entry.id, ad: entry.ad, zorunlu: entry.zorunlu, durum: "var", yol };
  }
  return {
    id: entry.id,
    ad: entry.ad,
    zorunlu: entry.zorunlu,
    durum: "yok",
    yol: null,
    oneri: entry.oneri,
    indir: entry.url,
    nereye: entry.nereye,
  };
}

function entry(id: string): ToolCatalogEntry {
  const found = catalogEntry(id);
  if (found === undefined) {
    throw new Error(`missing catalog entry ${id}`);
  }
  return found;
}

/** Probe installed programs. Missing ones carry a download suggestion. Nothing is downloaded. */
export async function checkPrerequisites(): Promise<{ ozet: string; araclar: ToolStatus[] }> {
  const r2 = await findRadare2();
  const dot = await findOnPath(process.platform === "win32" ? ["dot.exe", "dot.bat", "dot.cmd"] : ["dot"]);
  const x64dbg = await findX64dbg();
  let cdb: string | null = null;
  try {
    cdb = await resolveCdbExe("x64");
  } catch {
    cdb = null;
  }
  const pyName = process.env.DBG_BRIDGE_PYTHON ?? "python";
  const py64 = pythonBits(pyName) === 64 ? pyName : null;
  let py32: string | null = null;
  const explicit32 = process.env.PYTHON_HOME_X86 ?? process.env.PYTHON_HOME;
  if (explicit32 !== undefined && explicit32 !== "" && (await findPythonDll(explicit32))) {
    py32 = explicit32;
  } else {
    const portable = join(homedir(), "Tools", "python-x86");
    if (await findPythonDll(portable)) {
      py32 = portable;
    }
  }
  const frida = await findFridaPackage();
  const hide = await findScyllaHide(x64dbg);

  const araclar: ToolStatus[] = [
    status(entry("radare2"), r2),
    status(entry("graphviz"), dot),
    status(entry("x64dbg"), x64dbg),
    status(entry("python64"), py64),
    status(entry("python32"), py32),
    status(entry("cdb"), cdb),
    status(entry("frida"), frida),
    status(entry("scyllahide"), hide),
  ];
  const missing = araclar.filter((row) => row.durum === "yok");
  const requiredMissing = missing.filter((row) => row.zorunlu).map((row) => row.ad);
  const optionalMissing = missing.filter((row) => !row.zorunlu).map((row) => row.ad);
  const bits: string[] = [];
  if (requiredMissing.length === 0) {
    bits.push("Eksik zorunlu araç yok.");
  } else {
    bits.push(`Eksik zorunlu: ${requiredMissing.join(", ")}.`);
  }
  if (optionalMissing.length > 0) {
    bits.push(`Eksik isteğe bağlı: ${optionalMissing.join(", ")}.`);
  }
  if (missing.length > 0) {
    bits.push("Eksik olanların indir alanı kurulum adresidir. Köprü dosyayı kendisi indirmez.");
  }
  return { ozet: bits.join(" "), araclar };
}
