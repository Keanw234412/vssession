import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const WINDOWS_MAX_PATH = 260;

/** ~/.claude/projects (honours CLAUDE_CONFIG_DIR like Claude Code does). */
export function claudeProjectsDir(): string {
  const base = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude');
  return path.join(base, 'projects');
}

/** Claude Code stores a project's sessions under its cwd with every non-alphanumeric char replaced by '-'. */
export function encodeProjectDir(cwd: string): string {
  return cwd.replace(/[^a-zA-Z0-9]/g, '-');
}

/** Use the \\?\ namespace on Windows so >260-char session paths stay readable. */
export function longPath(p: string): string {
  return process.platform === 'win32' ? path.toNamespacedPath(path.resolve(p)) : p;
}

/** Locate the session directory for a workspace folder (case-insensitive match, as drive letters vary). */
export function findProjectDirForCwd(cwd: string, projectsDir = claudeProjectsDir()): string | undefined {
  const want = encodeProjectDir(cwd).toLowerCase();
  let entries: string[];
  try {
    entries = fs.readdirSync(longPath(projectsDir));
  } catch {
    return undefined;
  }
  const hit = entries.find((e) => e.toLowerCase() === want);
  return hit ? path.join(projectsDir, hit) : undefined;
}

export interface LocalSession {
  sessionId: string;
  file: string;
  size: number;
  mtimeMs: number;
}

export function listSessionFiles(projectDir: string): LocalSession[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(longPath(projectDir), { withFileTypes: true });
  } catch {
    return [];
  }
  const out: LocalSession[] = [];
  for (const e of entries) {
    if (!e.isFile() || !e.name.endsWith('.jsonl')) continue;
    const file = path.join(projectDir, e.name);
    try {
      const st = fs.statSync(longPath(file));
      out.push({ sessionId: e.name.slice(0, -'.jsonl'.length), file, size: st.size, mtimeMs: st.mtimeMs });
    } catch {
      /* raced with deletion */
    }
  }
  return out.sort((a, b) => b.mtimeMs - a.mtimeMs);
}

/** Walk ~/.claude/projects and report every path that exceeds Windows MAX_PATH. */
export function findLongPaths(root = claudeProjectsDir(), limit = WINDOWS_MAX_PATH, maxResults = 500): string[] {
  const hits: string[] = [];
  const stack = [root];
  while (stack.length && hits.length < maxResults) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(longPath(dir), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (full.length >= limit) {
        hits.push(full);
        if (hits.length >= maxResults) break;
        continue; // children are necessarily long too
      }
      if (e.isDirectory()) stack.push(full);
    }
  }
  return hits;
}

/** Compare paths the way the host OS does (case-insensitive on Windows, separator-agnostic). */
export function samePath(a: string, b: string): boolean {
  const norm = (p: string) => {
    const r = path.resolve(p).replace(/[\\/]+$/, '');
    return process.platform === 'win32' ? r.toLowerCase() : r;
  };
  return norm(a) === norm(b);
}

/** Read the first `cwd` recorded in a session file (cheap: only scans the head). */
export function readSessionCwd(file: string, maxBytes = 256 * 1024): string | undefined {
  let fd: number | undefined;
  try {
    fd = fs.openSync(longPath(file), 'r');
    const buf = Buffer.alloc(maxBytes);
    const n = fs.readSync(fd, buf, 0, maxBytes, 0);
    for (const line of buf.subarray(0, n).toString('utf8').split(/\r?\n/)) {
      if (!line.includes('"cwd"')) continue;
      try {
        const rec = JSON.parse(line);
        if (typeof rec.cwd === 'string') return rec.cwd;
      } catch {
        /* truncated line at buffer end */
      }
    }
  } catch {
    /* unreadable */
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Transcript parsing
// ---------------------------------------------------------------------------

export type TranscriptItem =
  | { kind: 'user'; text: string; ts?: string }
  | { kind: 'assistant'; text: string; ts?: string; model?: string }
  | { kind: 'tool_use'; name: string; input: string; ts?: string }
  | { kind: 'tool_result'; text: string; isError: boolean; ts?: string }
  | { kind: 'thinking'; text: string; ts?: string }
  | { kind: 'meta'; text: string; ts?: string };

export interface SessionSummary {
  sessionId: string;
  title: string;
  firstTs?: string;
  lastTs?: string;
  userTurns: number;
  assistantTurns: number;
  toolCalls: number;
  gitBranch?: string;
  cwd?: string;
  organizationUuid?: string;
  accountUuid?: string;
}

function blockText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((b) => (b && typeof b === 'object' && 'text' in b && typeof (b as { text: unknown }).text === 'string' ? (b as { text: string }).text : ''))
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

const MAX_TOOL_TEXT = 4000;
function clip(s: string, n = MAX_TOOL_TEXT): string {
  return s.length > n ? `${s.slice(0, n)}\n… [${s.length - n} more chars]` : s;
}

/** Strip harness wrapper tags so titles read like the actual prompt. */
function cleanPrompt(text: string): string {
  return text
    .replace(/<(system-reminder|browser_instruction|ide_selection|ide_opened_file|ide_diagnostics|user-prompt-submit-hook|command-[a-z-]+|local-command-[a-z-]+)[^>]*>[\s\S]*?<\/\1>/g, '')
    .trim();
}

export interface SplitRecords {
  records: Record<string, any>[];
  /** Interior lines that were not valid JSON objects (not counting an unterminated tail). */
  malformed: number;
  /** True when the final line had no newline yet (Claude still writing) and was withheld. */
  droppedTail: boolean;
}

/** Split JSONL into complete records only; an unterminated last line is withheld. */
export function splitCompleteRecords(jsonl: string): SplitRecords {
  const lines = jsonl.split('\n');
  const tail = lines.pop() ?? '';
  const droppedTail = tail.trim().length > 0;
  const records: Record<string, any>[] = [];
  let malformed = 0;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line);
      if (rec && typeof rec === 'object' && !Array.isArray(rec)) records.push(rec);
      else malformed++;
    } catch {
      malformed++;
    }
  }
  return { records, malformed, droppedTail };
}

export function parseTranscript(jsonl: string): { items: TranscriptItem[]; summary: SessionSummary } {
  return parseRecords(splitCompleteRecords(jsonl).records);
}

export function parseRecords(records: Record<string, any>[]): { items: TranscriptItem[]; summary: SessionSummary } {
  const items: TranscriptItem[] = [];
  const summary: SessionSummary = { sessionId: '', title: '', userTurns: 0, assistantTurns: 0, toolCalls: 0 };
  for (const rec of records) {
    const ts: string | undefined = typeof rec.timestamp === 'string' ? rec.timestamp : undefined;
    if (ts) {
      summary.firstTs ??= ts;
      summary.lastTs = ts;
    }
    if (typeof rec.sessionId === 'string' && !summary.sessionId) summary.sessionId = rec.sessionId;
    if (typeof rec.gitBranch === 'string' && rec.gitBranch) summary.gitBranch = rec.gitBranch;
    if (typeof rec.cwd === 'string' && !summary.cwd) summary.cwd = rec.cwd;
    if (rec.type === 'session-owner') {
      summary.organizationUuid = rec.organizationUuid;
      summary.accountUuid = rec.accountUuid;
      continue;
    }
    if (rec.type === 'summary' && typeof rec.summary === 'string') {
      if (!summary.title) summary.title = rec.summary;
      continue;
    }
    if (rec.isMeta) continue;
    const msg = rec.message;
    if (!msg || typeof msg !== 'object') continue;

    if (rec.type === 'user') {
      if (typeof msg.content === 'string') {
        const text = cleanPrompt(msg.content);
        if (text) {
          items.push({ kind: 'user', text, ts });
          summary.userTurns++;
          if (!summary.title) summary.title = text.split('\n')[0].slice(0, 120);
        }
      } else if (Array.isArray(msg.content)) {
        for (const b of msg.content) {
          if (b?.type === 'tool_result') {
            items.push({ kind: 'tool_result', text: clip(blockText(b.content)), isError: !!b.is_error, ts });
          } else if (b?.type === 'text' && typeof b.text === 'string') {
            const text = cleanPrompt(b.text);
            if (!text) continue;
            items.push({ kind: 'user', text, ts });
            summary.userTurns++;
            if (!summary.title) summary.title = text.split('\n')[0].slice(0, 120);
          }
        }
      }
    } else if (rec.type === 'assistant' && Array.isArray(msg.content)) {
      let counted = false;
      for (const b of msg.content) {
        if (b?.type === 'text' && b.text) {
          items.push({ kind: 'assistant', text: b.text, ts, model: msg.model });
          if (!counted) {
            summary.assistantTurns++;
            counted = true;
          }
        } else if (b?.type === 'tool_use') {
          items.push({ kind: 'tool_use', name: String(b.name), input: clip(JSON.stringify(b.input ?? {}, null, 2)), ts });
          summary.toolCalls++;
        } else if (b?.type === 'thinking' && b.thinking) {
          items.push({ kind: 'thinking', text: b.thinking, ts });
        }
      }
    }
  }
  if (!summary.title) summary.title = summary.sessionId || 'Untitled session';
  return { items, summary };
}
