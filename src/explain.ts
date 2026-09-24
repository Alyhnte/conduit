/** Short Turkish reading of a disassembly window. Facts come from the instructions; nothing is invented. */

export interface ExplainInsn {
  address?: string;
  opcode?: string;
  mnemonic?: string;
  operands?: string;
  type?: string;
  jump?: string;
  fail?: string;
  comment?: string;
}

export interface ExplainLine {
  adres: string;
  kod: string;
  anlam: string;
}

export interface ExplainJump {
  adres: string;
  hedef: string;
  kosul: string;
  anlam: string;
}

export interface ExplainCall {
  adres: string;
  hedef: string;
  anlam: string;
}

export interface ExplainNotice {
  adres: string;
  ad: string;
  anlam: string;
}

export interface ExplainResult {
  dil: "tr";
  ozet: string;
  satirlar: ExplainLine[];
  atlamalar: ExplainJump[];
  cagrilar: ExplainCall[];
  bildirimler: ExplainNotice[];
  komut_sayisi: number;
  gosterilen: number;
}

const MAX_LINES = 24;

const MEANING: Record<string, string> = {
  mov: "değeri hedefe kopyalar",
  lea: "adres hesaplar, belleği okumaz",
  push: "değeri yığına koyar",
  pop: "yığından değeri alır",
  call: "fonksiyon çağırır, dönüş adresini saklar",
  ret: "çağıran yere döner",
  retn: "çağıran yere döner",
  jmp: "koşulsuz atlar",
  nop: "boş işlem",
  int3: "hata ayıklayıcı durağı (tek bayt kesme)",
  cmp: "karşılaştırır, sonraki atlama buna bakar",
  test: "bitleri dener, sonraki atlama buna bakar",
  xor: "bitleri XOR'lar; aynı yazmaçla kullanılış sıfırlar",
  add: "toplar",
  sub: "çıkarır",
  inc: "bir artırır",
  dec: "bir azaltır",
  and: "bit maskesi uygular",
  or: "bitleri birleştirir",
  shl: "sola kaydırır",
  shr: "sağa kaydırır",
  leave: "yığın çerçevesini kapatır",
  syscall: "işletim sistemine çağrı yapar",
  sysenter: "işletim sistemine çağrı yapar",
  int: "kesme çağırır",
};

const COND: Record<string, string> = {
  je: "eşitse",
  jz: "sıfırsa",
  jne: "eşit değilse",
  jnz: "sıfır değilse",
  ja: "büyüktür (işaretsiz)",
  jg: "büyüktür (işaretli)",
  jb: "küçüktür (işaretsiz)",
  jl: "küçüktür (işaretli)",
  jae: "büyük veya eşitse (işaretsiz)",
  jge: "büyük veya eşitse (işaretli)",
  jbe: "küçük veya eşitse (işaretsiz)",
  jle: "küçük veya eşitse (işaretli)",
  js: "işaret biti kuruluyorsa",
  jns: "işaret biti yoksa",
  jo: "taşma varsa",
  jno: "taşma yoksa",
  jp: "eşlik biti kuruluyorsa",
  jnp: "eşlik biti yoksa",
  jcxz: "cx sıfırsa",
  jecxz: "ecx sıfırsa",
  jrcxz: "rcx sıfırsa",
};

const NOTICE =
  /messagebox|sendmessage|postmessage|sendnotifymessage|outputdebugstring|dbgprint|printf|wprintf|\bputs\b|writeconsole|reportevent|shell_notifyicon|notifyicon|messagebeep|\bbeep\b|raiseexception/i;

interface Parsed {
  address: string;
  mnemonic: string;
  operands: string;
  text: string;
  jump: string | null;
  fail: string | null;
  comment: string;
}

function splitOpcode(opcode: string): { mnemonic: string; operands: string } {
  const trimmed = opcode.trim().replace(/\s+/g, " ");
  const space = trimmed.indexOf(" ");
  if (space < 0) {
    return { mnemonic: trimmed.toLowerCase(), operands: "" };
  }
  return { mnemonic: trimmed.slice(0, space).toLowerCase(), operands: trimmed.slice(space + 1).trim() };
}

function parseOne(raw: ExplainInsn, index: number): Parsed {
  const fromOpcode = raw.opcode !== undefined && raw.opcode.trim() !== "" ? splitOpcode(raw.opcode) : null;
  const mnemonic = (raw.mnemonic ?? fromOpcode?.mnemonic ?? "").trim().toLowerCase();
  const operands = (raw.operands ?? fromOpcode?.operands ?? "").trim();
  const text = `${mnemonic}${operands === "" ? "" : ` ${operands}`}`.trim();
  return {
    address: raw.address?.trim() || `#${index}`,
    mnemonic,
    operands,
    text: text === "" ? "(boş)" : text,
    jump: raw.jump?.trim() || null,
    fail: raw.fail?.trim() || null,
    comment: raw.comment?.trim() || "",
  };
}

function hexValue(text: string): bigint | null {
  const match = /0x([0-9a-fA-F]+)/.exec(text);
  const digits = match?.[1];
  if (digits === undefined) {
    return null;
  }
  try {
    return BigInt(`0x${digits}`);
  } catch {
    return null;
  }
}

function jumpTarget(insn: Parsed): string | null {
  if (insn.jump !== null && insn.jump !== "") {
    return insn.jump;
  }
  return insn.operands.match(/0x[0-9a-fA-F]+/)?.[0] ?? null;
}

function noticeName(insn: Parsed): string | null {
  const tokens = `${insn.operands} ${insn.comment}`.split(/[^A-Za-z0-9_@.]+/);
  for (const token of tokens) {
    if (token !== "" && NOTICE.test(token)) {
      return token;
    }
  }
  return null;
}

function lineMeaning(insn: Parsed, previous: Parsed | null): string {
  const cond = COND[insn.mnemonic];
  const target = jumpTarget(insn);
  if (cond !== undefined && target !== null) {
    const basis = previous !== null && (previous.mnemonic === "cmp" || previous.mnemonic === "test")
      ? "Bir önceki karşılaştırmaya göre "
      : "";
    const stay = insn.fail !== null ? `, tutmazsa ${insn.fail} adresinden devam eder` : "";
    return `${basis}${cond} ${target} adresine atlar${stay}.`;
  }
  if (insn.mnemonic === "jmp" && target !== null) {
    const back = goesBack(insn.address, target);
    return back ? `Koşulsuz ${target} adresine geri atlar (döngü).` : `Koşulsuz ${target} adresine atlar.`;
  }
  if (insn.mnemonic === "call") {
    const notice = noticeName(insn);
    const hedef = target ?? (insn.operands === "" ? "hedef" : insn.operands);
    if (notice !== null) {
      return `${hedef} çağrılır. Bu bir bildirim veya kullanıcı mesajı. Dönüşten sonra alt satıra geçer.`;
    }
    return `${hedef} çağrılır. Dönünce bir sonraki komuta geçer.`;
  }
  if (insn.mnemonic === "ret" || insn.mnemonic === "retn") {
    return "Çağıran fonksiyona döner.";
  }
  const known = MEANING[insn.mnemonic];
  if (known !== undefined) {
    return insn.operands === "" ? `${known}.` : `${insn.operands}: ${known}.`;
  }
  if (insn.mnemonic === "") {
    return "Komut metni yok.";
  }
  return `${insn.mnemonic}${insn.operands === "" ? "" : ` ${insn.operands}`}.`;
}

function goesBack(from: string, to: string): boolean {
  const left = hexValue(from);
  const right = hexValue(to);
  if (left === null || right === null) {
    return false;
  }
  return right < left;
}

function regionSentence(insns: Parsed[], jumps: ExplainJump[], notices: ExplainNotice[]): string {
  const roles: string[] = [];
  const first = insns[0];
  const second = insns[1];
  if (first !== undefined && (first.mnemonic === "push" || first.mnemonic === "sub" || first.mnemonic === "endbr64")) {
    roles.push("fonksiyon girişi");
  }
  if (
    first?.mnemonic === "push" &&
    second !== undefined &&
    second.mnemonic === "mov" &&
    /rbp,\s*rsp|ebp,\s*esp/i.test(second.operands)
  ) {
    roles.push("çerçeve kuruluyor");
  }
  if (insns.some((insn) => insn.mnemonic === "ret" || insn.mnemonic === "retn")) {
    roles.push("çıkış var");
  }
  if (jumps.some((jump) => jump.kosul === "döngü")) {
    roles.push("döngü var");
  } else if (jumps.some((jump) => jump.kosul !== "koşulsuz")) {
    roles.push("dallanma var");
  }
  const bits = [`${insns.length} komut.`];
  if (roles.length > 0) {
    bits.push(`${roles.join(", ")}.`);
  }
  const lead = jumps[0];
  if (lead !== undefined) {
    bits.push(lead.anlam);
  }
  if (jumps.length > 1) {
    bits.push(`${jumps.length} atlama var.`);
  }
  if (notices.length > 0) {
    bits.push(`Bildirim: ${notices.map((row) => row.ad).join(", ")}.`);
  } else {
    bits.push("Bildirim API'si bu pencerede yok.");
  }
  return bits.join(" ");
}

export function explainRegion(raw: ExplainInsn[]): ExplainResult {
  const parsed = raw.slice(0, MAX_LINES).map((row, index) => parseOne(row, index));
  const satirlar: ExplainLine[] = [];
  const atlamalar: ExplainJump[] = [];
  const cagrilar: ExplainCall[] = [];
  const bildirimler: ExplainNotice[] = [];

  for (let i = 0; i < parsed.length; i += 1) {
    const insn = parsed[i];
    if (insn === undefined) {
      continue;
    }
    const anlam = lineMeaning(insn, i > 0 ? (parsed[i - 1] ?? null) : null);
    satirlar.push({ adres: insn.address, kod: insn.text, anlam });
    const cond = COND[insn.mnemonic];
    const target = jumpTarget(insn);
    if (cond !== undefined && target !== null) {
      atlamalar.push({ adres: insn.address, hedef: target, kosul: cond, anlam });
    } else if (insn.mnemonic === "jmp" && target !== null) {
      const loop = goesBack(insn.address, target);
      atlamalar.push({
        adres: insn.address,
        hedef: target,
        kosul: loop ? "döngü" : "koşulsuz",
        anlam,
      });
    } else if (insn.mnemonic === "call") {
      const hedef = target ?? insn.operands;
      cagrilar.push({ adres: insn.address, hedef, anlam });
      const ad = noticeName(insn);
      if (ad !== null) {
        bildirimler.push({
          adres: insn.address,
          ad,
          anlam: `${ad} çağrısı kullanıcıya mesaj, günlük veya sistem bildirimi gönderir.`,
        });
      }
    }
  }

  const hidden = raw.length > parsed.length ? ` İlk ${MAX_LINES} komut gösterildi.` : "";
  return {
    dil: "tr",
    ozet: `${regionSentence(parsed, atlamalar, bildirimler)}${hidden}`,
    satirlar,
    atlamalar,
    cagrilar,
    bildirimler,
    komut_sayisi: raw.length,
    gosterilen: parsed.length,
  };
}
