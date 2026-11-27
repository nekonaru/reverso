/** Static PDF structure inspector. Never executes or renders the document. */
export interface PdfInfo {
  version: string | null;
  sizeBytes: number;
  objects: number;
  encrypted: boolean;
  javascript: boolean;
  openAction: boolean;
  embeddedFiles: number;
  uris: string[];
  metadata: string[];
}

const MAX_TEXT_BYTES = 16 * 1024 * 1024;

export function parsePdf(buf: Uint8Array): PdfInfo {
  const text = new TextDecoder("latin1").decode(buf.subarray(0, Math.min(buf.length, MAX_TEXT_BYTES)));
  const version = text.match(/%PDF-(\d+\.\d+)/)?.[1] ?? null;
  const objects = (text.match(/\bobj\b/g) ?? []).length;
  const uris = [...text.matchAll(/\/URI\s*\(([^)]{1,512})\)/g)].map((match) => match[1]!).slice(0, 50);

  const metadata: string[] = [];
  for (const key of ["Title", "Author", "Creator", "Producer", "Subject"]) {
    const match = text.match(new RegExp(`/${key}\\s*\\(([^)]{0,256})\\)`));
    if (match) metadata.push(`${key}: ${match[1]}`);
  }

  return {
    version,
    sizeBytes: buf.length,
    objects,
    encrypted: /\/Encrypt\b/.test(text),
    javascript: /\/JavaScript\b/i.test(text),
    openAction: /\/OpenAction\b/.test(text),
    embeddedFiles: (text.match(/\/EmbeddedFile\b/g) ?? []).length,
    uris,
    metadata,
  };
}
