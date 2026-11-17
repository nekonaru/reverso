import { parseElf } from "./elf.js";
import { parsePe } from "./pe.js";
import { parseMachO } from "./macho.js";

export type HardeningStatus = "pass" | "fail" | "info";

export interface HardeningCheck {
  name: string;
  status: HardeningStatus;
  detail: string;
}

export interface HardeningReport {
  format: string;
  checks: HardeningCheck[];
}

export function hardeningReport(buf: Uint8Array, format: string): HardeningReport {
  try {
    if (format === "elf32" || format === "elf64") return elfHardening(buf, format);
    if (format === "pe") return peHardening(buf);
    if (format === "macho32" || format === "macho64" || format === "macho-fat") return machOHardening(buf, format);
  } catch (error) {
    return {
      format,
      checks: [{ name: "parse", status: "info", detail: `Could not parse binary: ${(error as Error).message}` }],
    };
  }
  return { format, checks: [{ name: "supported", status: "info", detail: "No hardening checks available for this format" }] };
}

function elfHardening(buf: Uint8Array, format: string): HardeningReport {
  const elf = parseElf(buf);
  const checks: HardeningCheck[] = [
    {
      name: "PIE",
      status: elf.pie ? "pass" : "fail",
      detail: elf.pie ? "Position-independent executable (ET_DYN)" : "Not position-independent (ET_EXEC); ASLR cannot randomize the base",
    },
    {
      name: "NX stack",
      status: elf.nxStack ? "pass" : "fail",
      detail: elf.nxStack ? "PT_GNU_STACK is not executable" : "PT_GNU_STACK is executable",
    },
    {
      name: "StackCanary",
      status: elf.stackCanary ? "pass" : "fail",
      detail: elf.stackCanary ? "__stack_chk_fail is referenced" : "No reference to __stack_chk_fail found",
    },
    {
      name: "RELRO",
      status: elf.relro ? (elf.bindNow ? "pass" : "info") : "fail",
      detail: elf.relro
        ? elf.bindNow
          ? "Full RELRO (PT_GNU_RELRO with BIND_NOW)"
          : "Partial RELRO (PT_GNU_RELRO without BIND_NOW)"
        : "No PT_GNU_RELRO segment",
    },
    {
      name: "FORTIFY",
      status: elf.fortifiedFunctions > 0 ? "pass" : "info",
      detail: elf.fortifiedFunctions > 0 ? `${elf.fortifiedFunctions} fortified symbol(s) (*_chk)` : "No fortified (*_chk) symbols found",
    },
    {
      name: "Stripped",
      status: "info",
      detail: elf.stripped ? "No .symtab section (binary is stripped)" : ".symtab present (binary is not stripped)",
    },
  ];
  return { format, checks };
}

function peHardening(buf: Uint8Array): HardeningReport {
  const pe = parsePe(buf);
  const checks: HardeningCheck[] = [
    {
      name: "ASLR",
      status: pe.aslr ? "pass" : "fail",
      detail: pe.aslr ? "DYNAMICBASE DLL characteristic set" : "DYNAMICBASE not set; base address is fixed",
    },
    {
      name: "NX compat",
      status: pe.nxCompat ? "pass" : "fail",
      detail: pe.nxCompat ? "NX_COMPAT DLL characteristic set" : "NX_COMPAT not set; data pages may be executable",
    },
    {
      name: "Control Flow Guard",
      status: pe.cfg ? "pass" : "info",
      detail: pe.cfg ? "GUARD_CF DLL characteristic set" : "GUARD_CF not set",
    },
    {
      name: "High entropy VA",
      status: pe.highEntropyVa ? "pass" : "info",
      detail: pe.highEntropyVa ? "64-bit address space randomization enabled" : "HIGH_ENTROPY_VA not set",
    },
    {
      name: "Signed",
      status: pe.hasCertificate ? "pass" : "info",
      detail: pe.hasCertificate ? "Authenticode certificate table present" : "No Authenticode certificate table",
    },
    {
      name: "Managed (.NET)",
      status: "info",
      detail: pe.isDotNet ? "CLR data directory present; this is a managed assembly" : "Native (unmanaged) PE image",
    },
    {
      name: "No SEH",
      status: pe.noSeh ? "pass" : "info",
      detail: pe.noSeh ? "NO_SEH: no structured exception handling (x64 images)" : "SEH is used",
    },
  ];
  return { format: "pe", checks };
}

function machOHardening(buf: Uint8Array, format: string): HardeningReport {
  const macho = parseMachO(buf);
  const checks: HardeningCheck[] = [
    {
      name: "Encryption (FairPlay)",
      status: "info",
      detail: macho.encrypted ? "LC_ENCRYPTION_INFO indicates FairPlay-encrypted content" : "Not FairPlay-encrypted",
    },
    {
      name: "Code signature",
      status: macho.hasCodeSignature ? "pass" : "info",
      detail: macho.hasCodeSignature ? "LC_CODE_SIGNATURE load command present" : "No code signature load command",
    },
    {
      name: "PIE",
      status: "info",
      detail: macho.flags.includes("pie") ? "MH_PIE flag set" : "MH_PIE flag not set",
    },
  ];
  return { format, checks };
}
