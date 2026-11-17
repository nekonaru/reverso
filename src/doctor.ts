import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { platform, arch, totalmem, cpus, release } from "node:os";

const execFileAsync = promisify(execFile);

export interface DoctorCheck {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

export interface DoctorReport {
  node: string;
  platform: string;
  checks: DoctorCheck[];
  healthy: boolean;
}

export async function runDoctor(): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];

  const major = Number(process.versions.node.split(".")[0]);
  checks.push({
    name: "node version",
    status: major >= 22 ? "ok" : "fail",
    detail: `${process.version} (requires Node 22 or newer)`,
  });

  checks.push({
    name: "platform",
    status: "ok",
    detail: `${platform()} ${arch()} (kernel ${release()}), ${cpus().length} CPU(s), ${Math.round(totalmem() / 1024 / 1024 / 1024)} GiB RAM`,
  });

  checks.push({
    name: "fetch runtime",
    status: typeof fetch === "function" ? "ok" : "fail",
    detail: typeof fetch === "function" ? "global fetch available (undici)" : "global fetch missing",
  });

  try {
    await execFileAsync("git", ["--version"]);
    checks.push({ name: "git", status: "ok", detail: "git is available" });
  } catch {
    checks.push({ name: "git", status: "warn", detail: "git not found on PATH (only needed for repository workflows)" });
  }

  const healthy = checks.every((check) => check.status !== "fail");
  return { node: process.version, platform: `${platform()}/${arch()}`, checks, healthy };
}
