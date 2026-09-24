/** Download hints for programs Conduit shells out to. The bridge does not download them. */

export interface ToolCatalogEntry {
  id: string;
  ad: string;
  zorunlu: boolean;
  url: string;
  nereye: string;
  oneri: string;
}

export const TOOL_CATALOG: readonly ToolCatalogEntry[] = [
  {
    id: "radare2",
    ad: "radare2",
    zorunlu: true,
    url: "https://github.com/radareorg/radare2/releases",
    nereye: "Hazır derlenmiş sürümü PATH'e koy (radare2.exe veya r2.exe). İstersen DBG_BRIDGE_R2 ile tam yolu ver.",
    oneri: "Statik analiz (disassembly, CFG, string) için radare2 gerekli. Derleme yok, release paketini indir.",
  },
  {
    id: "graphviz",
    ad: "Graphviz",
    zorunlu: false,
    url: "https://graphviz.org/download/",
    nereye: "dot PATH'te olmalı (dot.exe).",
    oneri: "CFG nokta dosyasını resme çevirmek için Graphviz yeterli. Köprü dotsuz da grafiği JSON verir.",
  },
  {
    id: "x64dbg",
    ad: "x64dbg",
    zorunlu: false,
    url: "https://github.com/x64dbg/x64dbg/releases",
    nereye: "Taşınabilir paketi %USERPROFILE%\\Tools\\x64dbg altına aç (içinde x64\\x64dbg.exe). Başka yerdeyse X64DBG_DIR.",
    oneri: "Canlı x64dbg oturumu için snapshot indir. Kurulum sihirbazı gerekmez.",
  },
  {
    id: "python64",
    ad: "Python 3 (64-bit)",
    zorunlu: false,
    url: "https://www.python.org/downloads/windows/",
    nereye: "64-bit CPython 3.10+. python3.dll olan klasörü PYTHON_HOME_X64 yap.",
    oneri: "x64dbg köprüsü aynı bitlikte Python ister. 64-bit hedef için 64-bit Python kur.",
  },
  {
    id: "python32",
    ad: "Python 3 (32-bit)",
    zorunlu: false,
    url: "https://www.python.org/downloads/windows/",
    nereye: "%USERPROFILE%\\Tools\\python-x86 veya PYTHON_HOME_X86. Klasörde python3.dll olmalı.",
    oneri: "32-bit hedefi x64dbg ile açmak için 32-bit Python 3.10+ gerekir.",
  },
  {
    id: "cdb",
    ad: "cdb (Debugging Tools)",
    zorunlu: false,
    url: "https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/",
    nereye: "SDK kurulumunda Debugging Tools for Windows'u seç. CDB_DIR, Debuggers klasörü olsun (x64\\cdb.exe'nin bir üstü).",
    oneri: "Penceresiz cdb oturumu için Windows SDK içindeki Debugging Tools yeterli.",
  },
  {
    id: "frida",
    ad: "Frida",
    zorunlu: false,
    url: "https://github.com/frida/frida/releases",
    nereye: "Köprü klasöründe npm install. Gadget veya telefon için aynı sürümün frida-gadget / frida-server paketini indir.",
    oneri: "Frida motoru npm paketidir. Gadget, sürece gömülü dinleyici içindir; sürüm köprüdeki frida ile aynı olsun.",
  },
  {
    id: "scyllahide",
    ad: "ScyllaHide",
    zorunlu: false,
    url: "https://github.com/x64dbg/ScyllaHide/releases",
    nereye: "ScyllaHideX64DBGPlugin.dp64 dosyasını x64dbg plugins klasörüne koy. Köprü Scylla penceresini açmaz.",
    oneri: "İsteğe bağlı. Eklenti yoksa debug_plugin hide, plugins yolunu söyleyerek engine_unavailable döner.",
  },
];

export function catalogEntry(id: string): ToolCatalogEntry | undefined {
  return TOOL_CATALOG.find((entry) => entry.id === id);
}

/** One sentence the agent can show when a program is missing. */
export function suggestDownload(id: string): string {
  const entry = catalogEntry(id);
  if (entry === undefined) {
    return "";
  }
  return `İndirme önerisi: ${entry.ad} — ${entry.url} — ${entry.nereye}`;
}
