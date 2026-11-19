import * as fs from 'node:fs';

/** Electron fuse wire format: SENTINEL, u8 version, u8 length, `length` state bytes. */
export const FUSE_SENTINEL = Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX', 'ascii');

/** Fuse order for wire version 1 (matches @electron/fuses FuseV1Options). */
export const FUSE_V1_NAMES = [
  'RunAsNode',
  'EnableCookieEncryption',
  'EnableNodeOptionsEnvironmentVariable',
  'EnableNodeCliInspectArguments',
  'EnableEmbeddedAsarIntegrityValidation',
  'OnlyLoadAppFromAsar',
  'LoadBrowserProcessSpecificV8Snapshot',
  'GrantFileProtocolExtraPrivileges',
  'WasmTrapHandlers',
] as const;

export type FuseState = 'enabled' | 'disabled' | 'removed' | 'unknown';

export interface FuseEntry {
  index: number;
  name: string;
  state: FuseState;
  rawByte: number;
}

export interface FuseReport {
  offset: number;
  version: number;
  fuses: FuseEntry[];
}

function decodeState(b: number): FuseState {
  if (b === 0x31) return 'enabled';
  if (b === 0x30) return 'disabled';
  if (b === 0x72) return 'removed';
  return 'unknown';
}

/** Parse the fuse wire block that starts at `sentinelOffset` inside `buf`. */
export function parseFuseBlock(buf: Buffer, sentinelOffset: number, fileOffset = sentinelOffset): FuseReport | undefined {
  const p = sentinelOffset + FUSE_SENTINEL.length;
  if (p + 2 > buf.length) return undefined;
  const version = buf[p];
  const length = buf[p + 1];
  if (p + 2 + length > buf.length) return undefined;
  const fuses: FuseEntry[] = [];
  for (let i = 0; i < length; i++) {
    const raw = buf[p + 2 + i];
    fuses.push({
      index: i,
      name: version === 1 ? FUSE_V1_NAMES[i] ?? `Fuse${i}` : `Fuse${i}`,
      state: decodeState(raw),
      rawByte: raw,
    });
  }
  return { offset: fileOffset, version, fuses };
}

/** Find the first fuse block in an in-memory buffer. */
export function findFusesInBuffer(buf: Buffer): FuseReport | undefined {
  const at = buf.indexOf(FUSE_SENTINEL);
  return at < 0 ? undefined : parseFuseBlock(buf, at);
}

/** Stream-scan a (large) executable for the fuse block without loading it whole. */
export async function readFusesFromFile(file: string, chunkSize = 4 * 1024 * 1024): Promise<FuseReport | undefined> {
  const fh = await fs.promises.open(file, 'r');
  try {
    const overlap = FUSE_SENTINEL.length + 2 + 255;
    const buf = Buffer.alloc(chunkSize + overlap);
    let filePos = 0;
    let carry = 0;
    for (;;) {
      const { bytesRead } = await fh.read(buf, carry, chunkSize, filePos);
      const total = carry + bytesRead;
      if (total === 0) return undefined;
      const view = buf.subarray(0, total);
      const at = view.indexOf(FUSE_SENTINEL);
      if (at >= 0) {
        // Make sure the full block is in memory; read it directly if it straddles the end.
        const block = Buffer.alloc(overlap);
        const absolute = filePos - carry + at;
        const r = await fh.read(block, 0, overlap, absolute);
        return parseFuseBlock(block.subarray(0, r.bytesRead), 0, absolute);
      }
      if (bytesRead === 0) return undefined;
      carry = Math.min(overlap, total);
      buf.copy(buf, 0, total - carry, total);
      filePos += bytesRead;
    }
  } finally {
    await fh.close();
  }
}

export interface FuseRisk {
  fuse: string;
  expected: FuseState;
  severity: 'info' | 'warning';
  why: string;
  vscodeNeedsIt: boolean;
}

/** Hardening recommendations; VS Code itself depends on some "risky" fuses. */
export const FUSE_RISKS: FuseRisk[] = [
  {
    fuse: 'RunAsNode',
    expected: 'disabled',
    severity: 'info',
    vscodeNeedsIt: true,
    why: 'ELECTRON_RUN_AS_NODE lets any process run arbitrary Node.js code under the signed Code.exe identity. VS Code relies on it for the extension host and CLI, so it cannot be turned off without breaking VS Code.',
  },
  {
    fuse: 'EnableNodeOptionsEnvironmentVariable',
    expected: 'disabled',
    severity: 'warning',
    vscodeNeedsIt: true,
    why: 'NODE_OPTIONS (e.g. --require) can inject code into Code.exe at startup. Mitigation: make sure NODE_OPTIONS is not set globally.',
  },
  {
    fuse: 'EnableNodeCliInspectArguments',
    expected: 'disabled',
    severity: 'info',
    vscodeNeedsIt: true,
    why: '--inspect/--inspect-brk attach a debugger to the main process. Needed for extension debugging workflows.',
  },
  {
    fuse: 'EnableEmbeddedAsarIntegrityValidation',
    expected: 'enabled',
    severity: 'warning',
    vscodeNeedsIt: false,
    why: 'Application JavaScript under resources/app is not integrity-checked, so a user-writable install (per-user install in %LOCALAPPDATA%) can be modified by any local process.',
  },
  {
    fuse: 'OnlyLoadAppFromAsar',
    expected: 'enabled',
    severity: 'info',
    vscodeNeedsIt: true,
    why: 'VS Code ships unpacked out/ JavaScript, so it must load from a folder.',
  },
  {
    fuse: 'EnableCookieEncryption',
    expected: 'enabled',
    severity: 'info',
    vscodeNeedsIt: false,
    why: 'Chromium cookies for webviews/auth flows are stored without OS-level encryption.',
  },
];
