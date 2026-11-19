import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SessionSummary, TranscriptItem } from './claudeSessions';

/**
 * Shared-folder layout (every path segment is validated):
 *
 *   <root>/org.json                                   { schema, orgId, name, createdAt }
 *   <root>/projects/<projectId>/project.json          { schema, projectId, orgId, name, createdAt }
 *   <root>/projects/<projectId>/members/<memberId>/member.json      { memberId, displayName }  (self-reported)
 *   <root>/projects/<projectId>/members/<memberId>/devices/<deviceId>/sessions/<sessionId>/rev-<seq>-<rand>.json
 *
 * Each member+device writes only into its own directory. Revisions are immutable and
 * self-contained (summary + items + content hash), written as .tmp-* then renamed, so a
 * reader never needs two files to agree. A partially synced or corrupt revision is ignored
 * and the previous valid one stays visible.
 *
 * Ordering never uses wall clocks: a revision lists the revIds of every head it saw
 * (`parents`). A head named as a parent by another head is superseded; heads that nobody
 * supersedes are competing versions (offline conflict) and are all exposed.
 */

export const SCHEMA = 1;
export const MAX_REVISION_BYTES = 30 * 1024 * 1024;
export const MAX_META_BYTES = 64 * 1024;
export const MAX_ITEMS = 50_000;
export const KEEP_REVISIONS_PER_DEVICE = 3;
export const MAX_ANCESTORS = 256;
const FAILED_READ_TTL_MS = 30_000;

const ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SESSION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const REV_RE = /^rev-(\d{1,12})-([a-z0-9]{6,16})\.json$/;
const REV_ID_RE = /^rev-\d{1,12}-[a-z0-9]{6,16}$/;
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com\d|lpt\d)$/i;

export class OrgStoreError extends Error {}

export function isValidId(id: unknown): id is string {
  return typeof id === 'string' && ID_RE.test(id) && !WINDOWS_RESERVED.test(id);
}
export function isValidSessionId(id: unknown): id is string {
  return typeof id === 'string' && SESSION_ID_RE.test(id) && !WINDOWS_RESERVED.test(id);
}
function assertId(id: unknown, what: string): asserts id is string {
  if (!isValidId(id)) throw new OrgStoreError(`Invalid ${what}: ${String(id)}`);
}

/** Short random ids keep nested shared paths well under Windows MAX_PATH. */
export function newId(): string {
  return crypto.randomBytes(8).toString('hex');
}

export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** Stable JSON so the hash does not depend on key insertion order. */
export function canonicalJson(v: unknown, depth = 0): string {
  if (depth > 32) throw new OrgStoreError('Value nested too deeply');
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map((x) => canonicalJson(x, depth + 1)).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k], depth + 1)}`)
    .join(',')}}`;
}

export interface OrgInfo { schema: number; orgId: string; name: string; createdAt: string }
export interface ProjectInfo { schema: number; projectId: string; orgId: string; name: string; createdAt: string }
export interface MemberInfo { schema: number; memberId: string; displayName: string; updatedAt: string }

export type PublicSummary = Omit<SessionSummary, 'accountUuid' | 'organizationUuid' | 'cwd'>;

export interface SessionRevision {
  schema: number;
  revId: string;
  seq: number;
  /** revIds of every valid head (any device) visible when this revision was written. */
  parents: string[];
  orgId: string;
  projectId: string;
  memberId: string;
  deviceId: string;
  sessionId: string;
  publishedAt: string;
  redaction: 'applied';
  summary: PublicSummary;
  items: TranscriptItem[];
  contentSha256: string;
}

export interface DeviceHead {
  deviceId: string;
  rev: SessionRevision;
  file: string;
}

export interface SessionHead {
  projectId: string;
  memberId: string;
  sessionId: string;
  latest: SessionRevision;
  file: string;
  /** Devices that have a valid copy of this session. */
  deviceHeads: number;
  /** Versions nobody has superseded. More than one = offline conflict. */
  competing: DeviceHead[];
  /** True when shown from this reader's cache because the files are mid-sync. */
  stale?: boolean;
}

// ---------------------------------------------------------------------------
// Public-content schema validation (shared content is untrusted input)
// ---------------------------------------------------------------------------

const isStr = (v: unknown, max = 1_000_000) => typeof v === 'string' && v.length <= max;
const optStr = (v: unknown, max = 200) => v === undefined || isStr(v, max);
const isCount = (v: unknown) => Number.isInteger(v) && (v as number) >= 0 && (v as number) < 1e9;

export function isValidPublicSummary(s: unknown): s is PublicSummary {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return false;
  const o = s as Record<string, unknown>;
  return (
    isStr(o.sessionId, 128) && isStr(o.title, 500) && isCount(o.userTurns) && isCount(o.assistantTurns) && isCount(o.toolCalls) &&
    optStr(o.firstTs, 40) && optStr(o.lastTs, 40) && optStr(o.gitBranch, 300)
  );
}

export function isValidItem(i: unknown): i is TranscriptItem {
  if (!i || typeof i !== 'object' || Array.isArray(i)) return false;
  const o = i as Record<string, unknown>;
  if (!optStr(o.ts, 40)) return false;
  switch (o.kind) {
    case 'user':
    case 'meta':
    case 'thinking':
      return isStr(o.text);
    case 'assistant':
      return isStr(o.text) && optStr(o.model, 200);
    case 'tool_use':
      return isStr(o.name, 300) && isStr(o.input);
    case 'tool_result':
      return isStr(o.text) && typeof o.isError === 'boolean';
    default:
      return false;
  }
}

export function isValidPublicContent(summary: unknown, items: unknown): boolean {
  return isValidPublicSummary(summary) && Array.isArray(items) && items.length <= MAX_ITEMS && items.every(isValidItem);
}

// ---------------------------------------------------------------------------
// Safe filesystem helpers
// ---------------------------------------------------------------------------

function lexicallyInside(root: string, target: string): boolean {
  const rel = path.relative(path.resolve(root), path.resolve(target));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function safeResolve(root: string, ...segments: string[]): string {
  const target = path.resolve(root, ...segments);
  if (!lexicallyInside(root, target)) throw new OrgStoreError(`Path escapes organization root: ${target}`);
  return target;
}

function isPlainDir(p: string): boolean {
  try {
    const st = fs.lstatSync(p);
    return st.isDirectory() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

function realInside(root: string, p: string): boolean {
  try {
    const r = fs.realpathSync.native(root);
    const t = fs.realpathSync.native(p);
    const rel = path.relative(r, t);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  } catch {
    return false;
  }
}

/**
 * Create `segments` below root for writing. Every existing component must be a real
 * directory (no symlink/junction), and the result must resolve inside the root.
 */
function ensureSafeDir(root: string, ...segments: string[]): string {
  let cur = path.resolve(root);
  // The root itself is the user's choice (may be a redirected/linked folder); components below it may not be links.
  try {
    if (!fs.statSync(cur).isDirectory()) throw new Error();
  } catch {
    throw new OrgStoreError(`Organization root is not a directory: ${cur}`);
  }
  for (const seg of segments) {
    if (!seg || seg === '.' || seg === '..' || /[\\/]/.test(seg)) throw new OrgStoreError(`Invalid path segment: ${seg}`);
    cur = path.join(cur, seg);
    let st: fs.Stats | undefined;
    try {
      st = fs.lstatSync(cur);
    } catch {
      st = undefined;
    }
    if (st) {
      if (st.isSymbolicLink() || !st.isDirectory()) throw new OrgStoreError(`Refusing to write through a link or non-directory: ${cur}`);
    } else {
      fs.mkdirSync(cur);
    }
  }
  if (!realInside(root, cur)) throw new OrgStoreError(`Path escapes organization root: ${cur}`);
  return cur;
}

function readJsonBounded<T>(file: string, maxBytes: number): T | undefined {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink() || st.size > maxBytes) return undefined;
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch {
    return undefined; // missing, placeholder not hydrated, partial sync, or malformed
  }
}

function writeAtomic(dir: string, name: string, data: string): string {
  const file = path.join(dir, name);
  try {
    if (fs.lstatSync(file).isSymbolicLink()) throw new OrgStoreError(`Refusing to replace a link: ${file}`);
  } catch (e) {
    if (e instanceof OrgStoreError) throw e;
  }
  const tmp = path.join(dir, `.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  fs.writeFileSync(tmp, data, { encoding: 'utf8', flag: 'wx' });
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    throw e;
  }
  return file;
}

function listDirs(dir: string, validate: (n: string) => boolean): string[] {
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  return names.filter((n) => validate(n) && isPlainDir(path.join(dir, n)));
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

type RevCtx = { projectId: string; memberId: string; deviceId: string; sessionId: string; orgId: string };

export class OrgStore {
  /** Validated revisions keyed by path+size+mtime, so polling does not re-hash unchanged files. */
  private readonly revCache = new Map<string, { key: string; rev: SessionRevision | undefined; at: number }>();
  /** Reader-local last valid view per session: survives a sync client delivering deletions before replacements. */
  private readonly lastGood = new Map<string, SessionHead>();

  constructor(public readonly root: string) {}

  // --- organization ------------------------------------------------------
  static create(root: string, name: string): OrgStore {
    fs.mkdirSync(root, { recursive: true });
    const store = new OrgStore(root);
    if (fs.existsSync(path.join(root, 'org.json'))) throw new OrgStoreError('This folder already contains an organization.');
    const org: OrgInfo = { schema: SCHEMA, orgId: newId(), name: name.trim().slice(0, 120), createdAt: new Date().toISOString() };
    writeAtomic(ensureSafeDir(root), 'org.json', JSON.stringify(org, null, 2));
    ensureSafeDir(root, 'projects');
    return store;
  }

  readOrg(): OrgInfo | undefined {
    const org = readJsonBounded<OrgInfo>(path.join(this.root, 'org.json'), MAX_META_BYTES);
    if (!org || org.schema !== SCHEMA || !isValidId(org.orgId) || !isStr(org.name, 200)) return undefined;
    return org;
  }

  requireOrg(): OrgInfo {
    const org = this.readOrg();
    if (!org) throw new OrgStoreError(`No valid org.json in ${this.root}`);
    return org;
  }

  // --- projects ----------------------------------------------------------
  createProject(name: string): ProjectInfo {
    const org = this.requireOrg();
    const p: ProjectInfo = { schema: SCHEMA, projectId: newId(), orgId: org.orgId, name: name.trim().slice(0, 120), createdAt: new Date().toISOString() };
    writeAtomic(ensureSafeDir(this.root, 'projects', p.projectId), 'project.json', JSON.stringify(p, null, 2));
    return p;
  }

  listProjects(): ProjectInfo[] {
    const org = this.readOrg();
    if (!org) return [];
    const base = path.join(this.root, 'projects');
    const out: ProjectInfo[] = [];
    for (const id of listDirs(base, isValidId)) {
      const dir = path.join(base, id);
      if (!realInside(this.root, dir)) continue;
      const p = readJsonBounded<ProjectInfo>(path.join(dir, 'project.json'), MAX_META_BYTES);
      // Embedded ids must match the directory context.
      if (p && p.schema === SCHEMA && p.projectId === id && p.orgId === org.orgId && isStr(p.name, 200)) out.push(p);
    }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  getProject(projectId: string): ProjectInfo | undefined {
    return this.listProjects().find((p) => p.projectId === projectId);
  }

  // --- members -----------------------------------------------------------
  upsertMember(projectId: string, memberId: string, displayName: string): void {
    assertId(projectId, 'project id');
    assertId(memberId, 'member id');
    const existing = safeResolve(this.root, 'projects', projectId, 'members', memberId, 'member.json');
    const cur = readJsonBounded<MemberInfo>(existing, MAX_META_BYTES);
    const name = displayName.trim().slice(0, 80) || 'member';
    if (cur && cur.displayName === name) return;
    const dir = ensureSafeDir(this.root, 'projects', projectId, 'members', memberId);
    writeAtomic(dir, 'member.json', JSON.stringify({ schema: SCHEMA, memberId, displayName: name, updatedAt: new Date().toISOString() } satisfies MemberInfo, null, 2));
  }

  listMembers(projectId: string): MemberInfo[] {
    assertId(projectId, 'project id');
    const base = safeResolve(this.root, 'projects', projectId, 'members');
    const out: MemberInfo[] = [];
    for (const id of listDirs(base, isValidId)) {
      const dir = path.join(base, id);
      if (!realInside(this.root, dir)) continue;
      const m = readJsonBounded<MemberInfo>(path.join(dir, 'member.json'), MAX_META_BYTES);
      out.push(m && m.memberId === id && isStr(m.displayName, 80) ? m : { schema: SCHEMA, memberId: id, displayName: id.slice(0, 8), updatedAt: '' });
    }
    return out.sort((a, b) => a.displayName.localeCompare(b.displayName));
  }

  // --- revisions ---------------------------------------------------------
  private sessionDirs(projectId: string, memberId: string, sessionId: string): { deviceId: string; dir: string }[] {
    const devicesDir = safeResolve(this.root, 'projects', projectId, 'members', memberId, 'devices');
    const out: { deviceId: string; dir: string }[] = [];
    for (const deviceId of listDirs(devicesDir, isValidId)) {
      const sessions = path.join(devicesDir, deviceId, 'sessions');
      const dir = path.join(sessions, sessionId);
      if (isPlainDir(sessions) && isPlainDir(dir) && realInside(this.root, dir)) out.push({ deviceId, dir });
    }
    return out;
  }

  /** Read and fully validate one revision file against its directory context. */
  readRevision(file: string, ctx: RevCtx): SessionRevision | undefined {
    const m = REV_RE.exec(path.basename(file));
    if (!m) return undefined;
    let cacheKey: string;
    try {
      const st = fs.lstatSync(file);
      cacheKey = `${st.size}:${st.mtimeMs}:${ctx.orgId}`;
    } catch {
      return undefined;
    }
    const cached = this.revCache.get(file);
    // Successes are cached by size/mtime; failures only briefly (hydration/network can recover without a change).
    if (cached && cached.key === cacheKey && (cached.rev || Date.now() - cached.at < FAILED_READ_TTL_MS)) return cached.rev;
    let rev: SessionRevision | undefined;
    try {
      rev = this.validateRevision(file, m, ctx);
    } catch {
      rev = undefined; // any validation failure is contained to this revision
    }
    if (this.revCache.size > 2000) this.revCache.clear();
    this.revCache.set(file, { key: cacheKey, rev, at: Date.now() });
    return rev;
  }

  private validateRevision(file: string, m: RegExpExecArray, ctx: RevCtx): SessionRevision | undefined {
    const rev = readJsonBounded<SessionRevision>(file, MAX_REVISION_BYTES);
    if (!rev || typeof rev !== 'object' || rev.schema !== SCHEMA) return undefined;
    if (rev.orgId !== ctx.orgId || rev.projectId !== ctx.projectId || rev.memberId !== ctx.memberId || rev.deviceId !== ctx.deviceId || rev.sessionId !== ctx.sessionId) return undefined;
    if (rev.seq !== Number(m[1]) || rev.revId !== path.basename(file, '.json')) return undefined;
    if (!isStr(rev.publishedAt, 40) || rev.redaction !== 'applied') return undefined;
    if (!Array.isArray(rev.parents) || rev.parents.length > MAX_ANCESTORS ||!rev.parents.every((p) => typeof p === 'string' && REV_ID_RE.test(p))) return undefined;
    if (!isValidPublicContent(rev.summary, rev.items)) return undefined;
    if (sha256(canonicalJson({ summary: rev.summary, items: rev.items })) !== rev.contentSha256) return undefined;
    return rev;
  }

  private revisionFiles(dir: string): { file: string; seq: number }[] {
    let names: string[];
    try {
      names = fs.readdirSync(dir);
    } catch {
      return [];
    }
    return names
      .map((n) => ({ n, m: REV_RE.exec(n) }))
      .filter((x): x is { n: string; m: RegExpExecArray } => !!x.m)
      .map((x) => ({ file: path.join(dir, x.n), seq: Number(x.m[1]) }))
      .sort((a, b) => b.seq - a.seq || b.file.localeCompare(a.file));
  }

  /** Every valid revision of a session across all devices (each device retains only a few). */
  private allRevisions(projectId: string, memberId: string, sessionId: string): DeviceHead[] {
    const org = this.requireOrg();
    const all: DeviceHead[] = [];
    for (const { deviceId, dir } of this.sessionDirs(projectId, memberId, sessionId)) {
      for (const { file } of this.revisionFiles(dir)) {
        const rev = this.readRevision(file, { orgId: org.orgId, projectId, memberId, deviceId, sessionId });
        if (rev) all.push({ deviceId, rev, file });
      }
    }
    return all;
  }

  /**
   * Causal leaves: revisions no other revision lists as an ancestor. `parents` is transitive,
   * so a pruned intermediate revision still supersedes what it had seen. Several leaves =
   * concurrent versions (offline devices, or two windows on one device). Order is
   * deterministic and clock-free: seq, then deviceId, then revId.
   */
  static competingHeads(revisions: DeviceHead[]): DeviceHead[] {
    const ancestors = new Set(revisions.flatMap((h) => h.rev.parents));
    const leaves = revisions.filter((h) => !ancestors.has(h.rev.revId));
    const pool = leaves.length ? leaves : revisions;
    return [...pool].sort((a, b) => b.rev.seq - a.rev.seq || a.deviceId.localeCompare(b.deviceId) || a.rev.revId.localeCompare(b.rev.revId));
  }

  private static seqOf(revId: string): number {
    return Number(/^rev-(\d+)-/.exec(revId)?.[1] ?? 0);
  }

  publish(input: {
    projectId: string;
    memberId: string;
    deviceId: string;
    sessionId: string;
    summary: PublicSummary;
    items: TranscriptItem[];
  }): { revision: SessionRevision; file: string; unchanged: boolean } {
    const org = this.requireOrg();
    const { projectId, memberId, deviceId, sessionId } = input;
    assertId(projectId, 'project id');
    assertId(memberId, 'member id');
    assertId(deviceId, 'device id');
    if (!isValidSessionId(sessionId)) throw new OrgStoreError(`Invalid session id: ${sessionId}`);
    if (!this.getProject(projectId)) throw new OrgStoreError('Project not found in this organization (folder moved or not yet synced?).');
    if (!isValidPublicContent(input.summary, input.items)) throw new OrgStoreError('Session content does not match the shared schema.');

    const contentSha256 = sha256(canonicalJson({ summary: input.summary, items: input.items }));
    const all = this.allRevisions(projectId, memberId, sessionId);
    const competing = OrgStore.competingHeads(all);
    // Unchanged only if our copy is already the sole live version; otherwise publish to resolve the conflict.
    if (competing.length === 1 && competing[0].deviceId === deviceId && competing[0].rev.contentSha256 === contentSha256) {
      return { revision: competing[0].rev, file: competing[0].file, unchanged: true };
    }

    // Transitive ancestry: everything visible plus everything those revisions had seen (newest first, capped).
    const ancestry = new Set<string>();
    for (const h of all) {
      ancestry.add(h.rev.revId);
      for (const p of h.rev.parents) ancestry.add(p);
    }
    const parents = [...ancestry].sort((a, b) => OrgStore.seqOf(b) - OrgStore.seqOf(a) || a.localeCompare(b)).slice(0, MAX_ANCESTORS);
    const seq = all.reduce((mx, h) => Math.max(mx, h.rev.seq), 0) + 1;
    const revId = `rev-${String(seq).padStart(6, '0')}-${crypto.randomBytes(4).toString('hex')}`;
    const revision: SessionRevision = {
      schema: SCHEMA,
      revId,
      seq,
      parents,
      orgId: org.orgId,
      projectId,
      memberId,
      deviceId,
      sessionId,
      publishedAt: new Date().toISOString(),
      redaction: 'applied',
      summary: input.summary,
      items: input.items,
      contentSha256,
    };
    const json = JSON.stringify(revision);
    if (Buffer.byteLength(json) > MAX_REVISION_BYTES) throw new OrgStoreError('Session is too large to share (over 30 MB after redaction).');
    const dir = ensureSafeDir(this.root, 'projects', projectId, 'members', memberId, 'devices', deviceId, 'sessions', sessionId);
    const file = writeAtomic(dir, `${revId}.json`, json);

    // Verify the write before pruning this device's older revisions.
    const ctx = { orgId: org.orgId, projectId, memberId, deviceId, sessionId };
    if (!this.readRevision(file, ctx)) throw new OrgStoreError('Published revision failed verification; older revisions were kept.');
    this.prune(dir, file, ctx);
    return { revision, file, unchanged: false };
  }

  /**
   * Keep the new revision, any revision that is still a causal leaf (e.g. written
   * concurrently by another window on this device), and the newest valid older ones;
   * delete the rest of this device's files. Never deletes `keepFile`.
   */
  private prune(dir: string, keepFile: string, ctx: RevCtx): void {
    const leafFiles = new Set(OrgStore.competingHeads(this.allRevisions(ctx.projectId, ctx.memberId, ctx.sessionId)).map((h) => h.file));
    let keptValid = 1;
    for (const { file } of this.revisionFiles(dir)) {
      if (file === keepFile || leafFiles.has(file)) continue;
      const valid = !!this.readRevision(file, ctx);
      if (valid && keptValid < KEEP_REVISIONS_PER_DEVICE) {
        keptValid++;
        continue;
      }
      try { fs.unlinkSync(file); } catch { /* sync client may hold it */ }
      this.revCache.delete(file);
    }
  }

  /** Remove this device's copy of a session (other devices' copies are theirs to manage). */
  unpublish(projectId: string, memberId: string, deviceId: string, sessionId: string): void {
    assertId(projectId, 'project id');
    assertId(memberId, 'member id');
    assertId(deviceId, 'device id');
    if (!isValidSessionId(sessionId)) throw new OrgStoreError(`Invalid session id: ${sessionId}`);
    const segs = ['projects', projectId, 'members', memberId, 'devices', deviceId, 'sessions', sessionId];
    const dir = safeResolve(this.root, ...segs);
    // Every component must be a real directory inside the root before deleting anything.
    let cur = path.resolve(this.root);
    for (const s of segs) {
      cur = path.join(cur, s);
      if (!isPlainDir(cur)) return;
    }
    if (realInside(this.root, dir)) fs.rmSync(dir, { recursive: true, force: true });
  }

  /** All sessions of a member in a project with their live (non-superseded) versions. */
  listSessions(projectId: string, memberId: string): SessionHead[] {
    assertId(projectId, 'project id');
    assertId(memberId, 'member id');
    const devicesDir = safeResolve(this.root, 'projects', projectId, 'members', memberId, 'devices');
    const sessionIds = new Set<string>();
    for (const deviceId of listDirs(devicesDir, isValidId)) {
      for (const s of listDirs(path.join(devicesDir, deviceId, 'sessions'), isValidSessionId)) sessionIds.add(s);
    }
    const out: SessionHead[] = [];
    for (const sessionId of sessionIds) {
      const key = `${projectId}/${memberId}/${sessionId}`;
      const all = this.allRevisions(projectId, memberId, sessionId);
      if (!all.length) {
        // Sync may deliver a prune before its replacement; keep showing what this reader last validated.
        const prev = this.lastGood.get(key);
        if (prev) out.push({ ...prev, stale: true });
        continue; // otherwise: only pending/invalid revisions synced so far
      }
      const competing = OrgStore.competingHeads(all);
      const head: SessionHead = {
        projectId, memberId, sessionId, latest: competing[0].rev, file: competing[0].file,
        deviceHeads: new Set(all.map((h) => h.deviceId)).size, competing,
      };
      this.lastGood.set(key, head);
      out.push(head);
    }
    // Sessions removed entirely (unpublished) disappear from the reader cache too.
    for (const key of [...this.lastGood.keys()]) {
      const [p, m, s] = key.split('/');
      if (p === projectId && m === memberId && !sessionIds.has(s)) this.lastGood.delete(key);
    }
    const ts = (h: SessionHead) => (typeof h.latest.summary.lastTs === 'string' ? h.latest.summary.lastTs : '');
    return out.sort((a, b) => ts(b).localeCompare(ts(a)));
  }
}
