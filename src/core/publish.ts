import * as fs from 'node:fs';
import * as path from 'node:path';
import { longPath, parseRecords, splitCompleteRecords, type SessionSummary, type TranscriptItem } from './claudeSessions';
import type { Redactor } from './redact';
import type { SessionRevision } from './orgStore';

export const MAX_SOURCE_BYTES = 25 * 1024 * 1024;

export class SourceTooLargeError extends Error {}

export interface Eligibility {
  /** Safe to publish without asking: every record's cwd lies inside the linked workspace. */
  autoOk: boolean;
  reasons: string[];
  /** Working directories outside the workspace that appear in the session (shown before manual publish). */
  foreignCwds: string[];
  malformed: number;
  droppedTail: boolean;
}

export interface PreparedSession {
  sessionId: string;
  summary: SessionRevision['summary'];
  items: TranscriptItem[];
  eligibility: Eligibility;
}

/** Read at most maxBytes; the cap is enforced while reading, not only via stat. */
export function readBounded(file: string, maxBytes = MAX_SOURCE_BYTES): string {
  const fd = fs.openSync(longPath(file), 'r');
  try {
    const chunks: Buffer[] = [];
    let total = 0;
    const buf = Buffer.alloc(1024 * 1024);
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) throw new SourceTooLargeError(`Session file exceeds ${Math.round(maxBytes / 1048576)} MB and will not be shared.`);
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    // Decoding only complete lines happens later; a split UTF-8 sequence can only be in the withheld tail.
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function isInside(dir: string, p: string): boolean {
  const norm = (x: string) => (process.platform === 'win32' ? path.resolve(x).toLowerCase() : path.resolve(x));
  const rel = path.relative(norm(dir), norm(p));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export function assessEligibility(records: Record<string, any>[], workspaceDir: string, malformed: number, droppedTail: boolean): Eligibility {
  const reasons: string[] = [];
  const foreign = new Set<string>();
  let withCwd = 0;
  let contentWithoutCwd = 0;
  for (const r of records) {
    // Every exported content record needs provenance; pure metadata records are discarded anyway.
    const isContent = (r.type === 'user' || r.type === 'assistant') && r.message && typeof r.message === 'object';
    if (typeof r.cwd !== 'string') {
      if (isContent) contentWithoutCwd++;
      continue;
    }
    withCwd++;
    if (!isInside(workspaceDir, r.cwd)) foreign.add(r.cwd);
  }
  if (withCwd === 0) reasons.push('No working-directory provenance recorded in this session.');
  else if (contentWithoutCwd) reasons.push(`${contentWithoutCwd} message(s) have no working-directory provenance.`);
  if (foreign.size) reasons.push(`Session also ran in ${foreign.size} folder(s) outside this workspace.`);
  if (malformed) reasons.push(`${malformed} malformed record(s) inside the session file.`);
  return { autoOk: reasons.length === 0, reasons, foreignCwds: [...foreign], malformed, droppedTail };
}

/**
 * Turn a local Claude session file into a shareable, redacted transcript.
 * Redaction runs on the raw parsed records *before* any clipping/summarising.
 */
export function prepareSession(file: string, workspaceDir: string, redactor: Redactor, maxBytes = MAX_SOURCE_BYTES): PreparedSession {
  const text = readBounded(file, maxBytes);
  const { records, malformed, droppedTail } = splitCompleteRecords(text);
  const eligibility = assessEligibility(records, workspaceDir, malformed, droppedTail);
  // Owner identifiers can also appear inside tool output (e.g. a printed session file).
  const ownerIds = records
    .filter((r) => r.type === 'session-owner')
    .flatMap((r) => [r.accountUuid, r.organizationUuid])
    .filter((x): x is string => typeof x === 'string');
  if (ownerIds.length) redactor = redactor.withLiterals(ownerIds);

  // Drop fields that must never leave the machine, then redact every remaining string.
  // One PEM state spans all records, so a key split across records is withheld until its END.
  const pem = { inPem: false };
  const sanitized = records
    // Owner metadata never leaves; harness summaries carry no provenance, so titles come from attributed prompts only.
    .filter((r) => r.type !== 'session-owner' && r.type !== 'summary')
    .map((r) => {
      const { cwd: _cwd, userType: _u, version: _v, requestId: _rq, ...rest } = r;
      if (rest.message && Array.isArray(rest.message.content)) {
        rest.message = {
          ...rest.message,
          content: rest.message.content.map((b: any) => (b && typeof b === 'object' ? (({ signature: _s, ...x }) => x)(b) : b)),
        };
      }
      return redactor.redactDeep(rest, pem);
    });

  const parsed = parseRecords(sanitized);
  const summary = parsed.summary;
  // Limited public schema: internal reasoning blocks are never shared.
  const items = parsed.items.filter((i) => i.kind !== 'thinking');
  const sessionId = path.basename(file, '.jsonl');
  const { accountUuid: _a, organizationUuid: _o, cwd: _c, ...publicSummary } = summary as SessionSummary;
  publicSummary.sessionId = sessionId;
  publicSummary.title = redactor.redact(publicSummary.title);
  return { sessionId, summary: publicSummary, items, eligibility };
}
