import { createHash } from "node:crypto";

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export function hashBuffer(buf: Uint8Array): FileHashes {
  return {
    md5: createHash("md5").update(buf).digest("hex"),
    sha1: createHash("sha1").update(buf).digest("hex"),
    sha256: createHash("sha256").update(buf).digest("hex"),
  };
}
