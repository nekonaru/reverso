import type { AnalysisReport } from "./analyze.js";

/** Render an analysis report as Markdown. */
export function reportToMarkdown(report: AnalysisReport): string {
  const lines: string[] = [];
  lines.push(`# Reverso analysis: ${report.file}`);
  lines.push("");
  lines.push(`- **Size:** ${report.sizeBytes} bytes`);
  lines.push(`- **Format:** ${report.format.format} (${report.format.confidence} confidence) - ${report.format.description}`);
  lines.push(`- **SHA-256:** \`${report.hashes.sha256}\``);
  lines.push(`- **SHA-1:** \`${report.hashes.sha1}\``);
  lines.push(`- **MD5:** \`${report.hashes.md5}\``);
  lines.push(`- **Entropy:** ${report.entropy} bits/byte - ${report.entropyInterpretation}`);
  lines.push("");

  if (report.highEntropyRegions.length > 0) {
    lines.push("## High entropy regions");
    lines.push("");
    for (const region of report.highEntropyRegions) {
      lines.push(`- offset ${region.offset}, size ${region.size}, entropy ${region.entropy}`);
    }
    lines.push("");
  }

  if (report.packerSignals.length > 0) {
    lines.push("## Packer signals");
    lines.push("");
    for (const signal of report.packerSignals) lines.push(`- ${signal}`);
    lines.push("");
  }

  if (report.hardening) {
    lines.push("## Hardening");
    lines.push("");
    for (const check of report.hardening.checks) {
      lines.push(`- **${check.name}** (${check.status}): ${check.detail}`);
    }
    lines.push("");
  }

  if (report.layout?.elf) {
    const elf = report.layout.elf;
    lines.push("## ELF layout");
    lines.push("");
    lines.push(`- **Type:** ${elf.typeName}, machine ${elf.machineName}, ${elf.bitness}-bit ${elf.endianness}`);
    lines.push(`- **Entry:** 0x${elf.entry.toString(16)}`);
    lines.push(`- **Sections:** ${elf.sections.length}, program headers: ${elf.programHeaders.length}`);
    if (elf.definedSymbols.length > 0) lines.push(`- **Defined dynamic symbols:** ${elf.definedSymbols.length}`);
    if (elf.undefinedSymbols.length > 0) lines.push(`- **Undefined dynamic symbols:** ${elf.undefinedSymbols.join(", ").slice(0, 400)}`);
    lines.push("");
  }

  if (report.layout?.pe) {
    const pe = report.layout.pe;
    lines.push("## PE layout");
    lines.push("");
    lines.push(`- **Machine:** ${pe.machineName}, ${pe.bitness}-bit, subsystem ${pe.subsystemName}`);
    lines.push(`- **Entry point (RVA):** 0x${pe.entryPoint.toString(16)}, image base 0x${pe.imageBase.toString(16)}`);
    lines.push(`- **Sections:** ${pe.sections.map((s) => s.name).join(", ") || "none"}`);
    if (pe.imports.length > 0) {
      lines.push(`- **Imports:** ${pe.imports.map((i) => i.dll).join(", ")}`);
    }
    if (pe.exports.length > 0) lines.push(`- **Exports:** ${pe.exports.slice(0, 20).join(", ")}${pe.exports.length > 20 ? ", ..." : ""}`);
    lines.push("");
  }

  if (report.layout?.macho) {
    const macho = report.layout.macho;
    lines.push("## Mach-O layout");
    lines.push("");
    lines.push(`- **Type:** ${macho.fileTypeName}, cpu ${macho.cpuName}, ${macho.bitness}-bit`);
    if (macho.isFat) lines.push(`- **Universal slices:** ${macho.fatArchitectures.join(", ")}`);
    lines.push(`- **Segments:** ${macho.segments.map((s) => s.name).join(", ") || "none"}`);
    lines.push(`- **Encrypted:** ${macho.encrypted ? "yes" : "no"}, code signature: ${macho.hasCodeSignature ? "yes" : "no"}`);
    lines.push("");
  }

  if (report.archive) {
    lines.push(`## Archive (${report.archive.kind})`);
    lines.push("");
    lines.push(`- **Entries:** ${report.archive.totalEntries} (showing ${report.archive.entries.length})`);
    lines.push(`- **Total uncompressed size:** ${report.archive.totalUncompressedSize} bytes`);
    if (report.archive.suspiciousEntries.length > 0) {
      lines.push(`- **Suspicious entries:** ${report.archive.suspiciousEntries.join(", ")}`);
    }
    lines.push("");
  }

  if (report.javascript) {
    const js = report.javascript;
    lines.push("## JavaScript bundle");
    lines.push("");
    lines.push(`- **Size:** ${js.bytes} bytes, ${js.lines} lines, minified: ${js.minified ? "yes" : "no"}`);
    lines.push(`- **Frameworks:** ${js.frameworks.join(", ") || "none detected"}`);
    lines.push(`- **Source map:** ${js.sourceMapUrl ?? "none"}`);
    lines.push(`- **Obfuscation score:** ${js.obfuscation.score}/100${js.obfuscation.indicators.length ? ` (${js.obfuscation.indicators.join("; ")})` : ""}`);
    if (js.suspiciousCalls.length > 0) lines.push(`- **Suspicious calls:** ${js.suspiciousCalls.join(", ")}`);
    lines.push(`- **URLs extracted:** ${js.urls.length}, endpoints extracted: ${js.endpoints.length}, secrets found: ${js.secrets.length}`);
    lines.push("");
  }

  lines.push("## Strings");
  lines.push("");
  lines.push(`- **Total extracted:** ${report.strings.total}`);
  for (const category of report.strings.categories) {
    lines.push(`- **${category.category}:** ${category.count}`);
  }
  lines.push("");

  return lines.join("\n");
}
