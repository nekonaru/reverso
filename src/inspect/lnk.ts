/** Windows shortcut (.lnk) inspector: paths, arguments and timestamps. */
export interface LnkInfo {
  fileSize: number;
  flags: string[];
  attributes: string[];
  creation: string | null;
  modification: string | null;
  access: string | null;
  targetSize: number;
  iconIndex: number;
  showCommand: number;
  nameString: string | null;
  relativePath: string | null;
  workingDirectory: string | null;
  commandLine: string | null;
  iconName: string | null;
}

const FLAG_NAMES: Array<[number, string]> = [
  [0x00000001, "has-name"],
  [0x00000002, "has-relative-path"],
  [0x00000004, "has-working-dir"],
  [0x00000008, "has-arguments"],
  [0x00000010, "has-icon-name"],
  [0x00000020, "unicode"],
  [0x00000040, "force-no-link-info"],
  [0x00000080, "has-link-id"],
  [0x00000100, "has-link-id-list"],
  [0x00000200, "has-darwin-id"],
  [0x00000400, "has-icon-env"],
];

const ATTRIBUTE_NAMES: Array<[number, string]> = [
  [0x00000001, "readonly"], [0x00000002, "hidden"], [0x00000004, "system"],
  [0x00000010, "directory"], [0x00000020, "archive"], [0x00000040, "device"],
  [0x00000080, "normal"], [0x00000100, "temporary"], [0x00000400, "compressed"],
  [0x00000800, "offline"],
];

export function parseLnk(buf: Uint8Array): LnkInfo {
  if (buf.length < 76) throw new Error("Not a shortcut: file too small");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const headerSize = dv.getUint32(0, true);
  if (headerSize !== 0x4c) throw new Error("Not a shortcut: invalid ShellLinkHeader size");
  const clsid = [...buf.subarray(4, 20)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (!clsid.toLowerCase().startsWith("0114020000000000c000000000000046")) {
    throw new Error("Not a shortcut: invalid CLSID");
  }
  const flagsBits = dv.getUint32(20, true);
  const attrs = dv.getUint32(24, true);
  const creation = fileTime(dv.getBigUint64(28, true));
  const access = fileTime(dv.getBigUint64(36, true));
  const modification = fileTime(dv.getBigUint64(44, true));
  const targetSize = dv.getUint32(52, true);
  const iconIndex = dv.getInt32(56, true);
  const showCommand = dv.getUint32(60, true);

  const flags = FLAG_NAMES.filter(([bit]) => (flagsBits & bit) !== 0).map(([, name]) => name);
  const attributes = ATTRIBUTE_NAMES.filter(([bit]) => (attrs & bit) !== 0).map(([, name]) => name);

  let pos = 76;
  if ((flagsBits & 0x00000080) !== 0) pos += 4; // LinkID
  if ((flagsBits & 0x00000200) !== 0) pos += 8 + 16; // Darwin ID

  const readString = (): string | null => {
    if (pos + 2 > buf.length) return null;
    const count = dv.getUint16(pos, true);
    pos += 2;
    const byteLength = count * (((flagsBits & 0x00000020) !== 0) ? 2 : 1);
    if (pos + byteLength > buf.length) return null;
    let value = "";
    if ((flagsBits & 0x00000020) !== 0) {
      for (let i = 0; i < byteLength; i += 2) value += String.fromCharCode(dv.getUint16(pos + i, true));
    } else {
      for (let i = 0; i < byteLength; i++) value += String.fromCharCode(buf[pos + i]!);
    }
    pos += byteLength;
    return value;
  };

  return {
    fileSize: buf.length,
    flags,
    attributes,
    creation,
    modification,
    access,
    targetSize,
    iconIndex,
    showCommand,
    nameString: (flagsBits & 0x00000001) !== 0 ? readString() : null,
    relativePath: (flagsBits & 0x00000002) !== 0 ? readString() : null,
    workingDirectory: (flagsBits & 0x00000004) !== 0 ? readString() : null,
    commandLine: (flagsBits & 0x00000008) !== 0 ? readString() : null,
    iconName: (flagsBits & 0x00000010) !== 0 ? readString() : null,
  };
}

function fileTime(value: bigint): string | null {
  const ms = Number(value) / 10000 - 11644473600000;
  if (!Number.isFinite(ms)) return null;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
