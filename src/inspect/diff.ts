/** Binary diffing: compare two files at the structural level. */

import { analyzeBuffer } from "../core/analyze-buffer.js";

export interface FormatScopedLayout {
  addedSections: string[];
  removedSections: string[];
  addedImports: string[];
  removedImports: string[];
  addedExports: string[];
  removedExports: string[];
}

export interface DiffReport {
  identical: boolean;
  a: { file: string; sizeBytes: number; sha256: string; format: string; entropy: number };
  b: { file: string; sizeBytes: number; sha256: string; format: string; entropy: number };
  sizeDelta: number;
  entropyDelta: number;
  hashesEqual: boolean;
  layout: FormatScopedLayout | null;
  strings: {
    totalDelta: number;
    categoriesOnlyInA: string[];
    categoriesOnlyInB: string[];
  };
  packerSignals: { a: string[]; b: string[] };
  differences: string[];
}

export function diffBuffers(a: Uint8Array, b: Uint8Array, labelA = "a", labelB = "b"): DiffReport {
  const ra = analyzeBuffer(a, labelA);
  const rb = analyzeBuffer(b, labelB);

  const differences: string[] = [];
  if (ra.sizeBytes !== rb.sizeBytes) differences.push(`size changed (${ra.sizeBytes} -> ${rb.sizeBytes} bytes)`);
  if (ra.format.format !== rb.format.format) differences.push(`format changed (${ra.format.format} -> ${rb.format.format})`);
  if (Math.abs(ra.entropy - rb.entropy) >= 0.5) {
    differences.push(`entropy changed significantly (${ra.entropy} -> ${rb.entropy})`);
  }
  const packerOnlyA = ra.packerSignals.filter((s) => !rb.packerSignals.includes(s));
  const packerOnlyB = rb.packerSignals.filter((s) => !ra.packerSignals.includes(s));
  for (const signal of packerOnlyB) differences.push(`packer signal appeared: ${signal}`);
  for (const signal of packerOnlyA) differences.push(`packer signal disappeared: ${signal}`);

  const layout = diffLayout(ra, rb);
  if (layout) {
    for (const s of layout.addedSections) differences.push(`section added: ${s}`);
    for (const s of layout.removedSections) differences.push(`section removed: ${s}`);
    for (const s of layout.addedImports) differences.push(`import appeared: ${s}`);
    for (const s of layout.removedImports) differences.push(`import disappeared: ${s}`);
    for (const s of layout.addedExports) differences.push(`export appeared: ${s}`);
    for (const s of layout.removedExports) differences.push(`export disappeared: ${s}`);
  }
  diffTraits(ra, rb, differences);

  const catsA = new Set(ra.strings.categories.map((c) => c.category));
  const catsB = new Set(rb.strings.categories.map((c) => c.category));
  const categoriesOnlyInA = [...catsA].filter((c) => !catsB.has(c));
  const categoriesOnlyInB = [...catsB].filter((c) => !catsA.has(c));
  for (const c of categoriesOnlyInB) differences.push(`string category appeared: ${c}`);
  for (const c of categoriesOnlyInA) differences.push(`string category disappeared: ${c}`);
  if (ra.strings.total !== rb.strings.total) {
    differences.push(`strings total changed (${ra.strings.total} -> ${rb.strings.total})`);
  }

  return {
    identical: ra.hashes.sha256 === rb.hashes.sha256,
    a: { file: ra.file, sizeBytes: ra.sizeBytes, sha256: ra.hashes.sha256, format: ra.format.format, entropy: ra.entropy },
    b: { file: rb.file, sizeBytes: rb.sizeBytes, sha256: rb.hashes.sha256, format: rb.format.format, entropy: rb.entropy },
    sizeDelta: rb.sizeBytes - ra.sizeBytes,
    entropyDelta: Math.round((rb.entropy - ra.entropy) * 1000) / 1000,
    hashesEqual: ra.hashes.sha256 === rb.hashes.sha256,
    layout,
    strings: {
      totalDelta: rb.strings.total - ra.strings.total,
      categoriesOnlyInA,
      categoriesOnlyInB,
    },
    packerSignals: { a: ra.packerSignals, b: rb.packerSignals },
    differences,
  };
}

function diffLayout(
  ra: ReturnType<typeof analyzeBuffer>,
  rb: ReturnType<typeof analyzeBuffer>,
): FormatScopedLayout | null {
  const empty = (): FormatScopedLayout => ({
    addedSections: [],
    removedSections: [],
    addedImports: [],
    removedImports: [],
    addedExports: [],
    removedExports: [],
  });

  if (ra.layout?.pe && rb.layout?.pe) {
    const out = empty();
    const sectionsA = new Set(ra.layout.pe.sections.map((s) => s.name));
    const sectionsB = new Set(rb.layout.pe.sections.map((s) => s.name));
    out.addedSections = [...sectionsB].filter((s) => !sectionsA.has(s));
    out.removedSections = [...sectionsA].filter((s) => !sectionsB.has(s));
    const importsA = flattenImports(ra.layout.pe.imports);
    const importsB = flattenImports(rb.layout.pe.imports);
    out.addedImports = [...importsB].filter((s) => !importsA.has(s));
    out.removedImports = [...importsA].filter((s) => !importsB.has(s));
    const exportsA = new Set(ra.layout.pe.exports);
    const exportsB = new Set(rb.layout.pe.exports);
    out.addedExports = [...exportsB].filter((s) => !exportsA.has(s));
    out.removedExports = [...exportsA].filter((s) => !exportsB.has(s));
    return out;
  }

  if (ra.layout?.elf && rb.layout?.elf) {
    const out = empty();
    const sectionsA = new Set(ra.layout.elf.sections.map((s) => s.name));
    const sectionsB = new Set(rb.layout.elf.sections.map((s) => s.name));
    out.addedSections = [...sectionsB].filter((s) => !sectionsA.has(s));
    out.removedSections = [...sectionsA].filter((s) => !sectionsB.has(s));
    const importsA = new Set(ra.layout.elf.undefinedSymbols);
    const importsB = new Set(rb.layout.elf.undefinedSymbols);
    out.addedImports = [...importsB].filter((s) => !importsA.has(s));
    out.removedImports = [...importsA].filter((s) => !importsB.has(s));
    const exportsA = new Set(ra.layout.elf.definedSymbols);
    const exportsB = new Set(rb.layout.elf.definedSymbols);
    out.addedExports = [...exportsB].filter((s) => !exportsA.has(s));
    out.removedExports = [...exportsA].filter((s) => !exportsB.has(s));
    return out;
  }

  return null;
}

function diffTraits(
  ra: ReturnType<typeof analyzeBuffer>,
  rb: ReturnType<typeof analyzeBuffer>,
  differences: string[],
): void {
  if (ra.layout?.elf && rb.layout?.elf) {
    const traits: Array<[string, boolean, boolean]> = [
      ["PIE", ra.layout.elf.pie, rb.layout.elf.pie],
      ["NX stack", ra.layout.elf.nxStack, rb.layout.elf.nxStack],
      ["Stack canary", ra.layout.elf.stackCanary, rb.layout.elf.stackCanary],
      ["RELRO", ra.layout.elf.relro, rb.layout.elf.relro],
      ["BIND_NOW", ra.layout.elf.bindNow, rb.layout.elf.bindNow],
      ["Stripped", ra.layout.elf.stripped, rb.layout.elf.stripped],
    ];
    for (const [name, before, after] of traits) {
      if (before !== after) differences.push(`ELF ${name}: ${before} -> ${after}`);
    }
    if (ra.layout.elf.machine !== rb.layout.elf.machine) {
      differences.push(`ELF machine changed (${ra.layout.elf.machineName} -> ${rb.layout.elf.machineName})`);
    }
    if (ra.layout.elf.entry !== rb.layout.elf.entry) differences.push("ELF entry point changed");
    if (ra.layout.elf.buildId !== rb.layout.elf.buildId) {
      differences.push(`ELF build-id changed (${ra.layout.elf.buildId ?? "none"} -> ${rb.layout.elf.buildId ?? "none"})`);
    }
  }

  if (ra.layout?.pe && rb.layout?.pe) {
    const traits: Array<[string, boolean, boolean]> = [
      ["ASLR", ra.layout.pe.aslr, rb.layout.pe.aslr],
      ["NX compat", ra.layout.pe.nxCompat, rb.layout.pe.nxCompat],
      ["Control Flow Guard", ra.layout.pe.cfg, rb.layout.pe.cfg],
      ["High entropy VA", ra.layout.pe.highEntropyVa, rb.layout.pe.highEntropyVa],
      ["No SEH", ra.layout.pe.noSeh, rb.layout.pe.noSeh],
      ["Authenticode signed", ra.layout.pe.hasCertificate, rb.layout.pe.hasCertificate],
      [".NET assembly", ra.layout.pe.isDotNet, rb.layout.pe.isDotNet],
    ];
    for (const [name, before, after] of traits) {
      if (before !== after) differences.push(`PE ${name}: ${before} -> ${after}`);
    }
    if (ra.layout.pe.entryPoint !== rb.layout.pe.entryPoint) differences.push("PE entry point RVA changed");
    if (ra.layout.pe.machine !== rb.layout.pe.machine) {
      differences.push(`PE machine changed (${ra.layout.pe.machineName} -> ${rb.layout.pe.machineName})`);
    }
    if (ra.layout.pe.imphash !== rb.layout.pe.imphash) {
      differences.push(`PE imphash changed (${ra.layout.pe.imphash ?? "none"} -> ${rb.layout.pe.imphash ?? "none"})`);
    }
    if (ra.layout.pe.rich?.richHash !== rb.layout.pe.rich?.richHash) {
      differences.push(`PE Rich hash changed (${ra.layout.pe.rich?.richHash ?? "none"} -> ${rb.layout.pe.rich?.richHash ?? "none"})`);
    }
  }

  if (ra.layout?.macho && rb.layout?.macho) {
    const traits: Array<[string, boolean, boolean]> = [
      ["Encrypted", ra.layout.macho.encrypted, rb.layout.macho.encrypted],
      ["Code signature", ra.layout.macho.hasCodeSignature, rb.layout.macho.hasCodeSignature],
      ["Entry point", ra.layout.macho.hasEntryPoint, rb.layout.macho.hasEntryPoint],
      ["Universal (fat)", ra.layout.macho.isFat, rb.layout.macho.isFat],
    ];
    for (const [name, before, after] of traits) {
      if (before !== after) differences.push(`Mach-O ${name}: ${before} -> ${after}`);
    }
    if (ra.layout.macho.uuid !== rb.layout.macho.uuid) {
      differences.push(`Mach-O UUID changed (${ra.layout.macho.uuid ?? "none"} -> ${rb.layout.macho.uuid ?? "none"})`);
    }
  }
}

function flattenImports(imports: Array<{ dll: string; functions: string[] }>): Set<string> {
  const out = new Set<string>();
  for (const entry of imports) {
    out.add(entry.dll.toLowerCase());
    for (const fn of entry.functions) out.add(`${entry.dll.toLowerCase()}!${fn}`);
  }
  return out;
}

export function diffReportToMarkdown(report: DiffReport): string {
  const lines: string[] = [];
  lines.push(`# Reverso diff: ${report.a.file} -> ${report.b.file}`);
  lines.push("");
  lines.push(`- **Identical:** ${report.identical ? "yes" : "no"}`);
  lines.push(`- **SHA-256:** ${report.hashesEqual ? "equal" : "different"}`);
  lines.push(`- **Size:** ${report.a.sizeBytes} -> ${report.b.sizeBytes} bytes (${report.sizeDelta >= 0 ? "+" : ""}${report.sizeDelta})`);
  lines.push(`- **Format:** ${report.a.format} -> ${report.b.format}`);
  lines.push(`- **Entropy:** ${report.a.entropy} -> ${report.b.entropy} (delta ${report.entropyDelta >= 0 ? "+" : ""}${report.entropyDelta})`);
  lines.push("");
  lines.push("## Differences");
  lines.push("");
  if (report.differences.length === 0) {
    lines.push("- No structural differences detected");
  } else {
    for (const difference of report.differences) lines.push(`- ${difference}`);
  }
  lines.push("");
  return lines.join("\n");
}
