import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, beforeEach } from 'node:test';
import { FUSE_SENTINEL, findFusesInBuffer, readFusesFromFile } from '../src/core/fuses';
import { Redactor } from '../src/core/redact';
import { encodeProjectDir, parseTranscript, splitCompleteRecords } from '../src/core/claudeSessions';
import { assessEligibility, prepareSession, readBounded, SourceTooLargeError } from '../src/core/publish';
import { OrgStore, OrgStoreError, canonicalJson, sha256, type SessionRevision } from '../src/core/orgStore';
import { autoConsentValid, CONTENT_SCHEMA, type WorkspaceLink } from '../src/core/consent';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vssession-test-'));
const line = (o: unknown) => JSON.stringify(o) + '\n';

// ---------------------------------------------------------------------------
describe('electron fuses', () => {
  const block = (version: number, states: string) => Buffer.concat([Buffer.from('xxxx'), FUSE_SENTINEL, Buffer.from([version, states.length]), Buffer.from(states, 'ascii'), Buffer.from('yyyy')]);

  it('parses a v1 block with names and states', () => {
    const r = findFusesInBuffer(block(1, '1010r0110'))!;
    assert.equal(r.version, 1);
    assert.equal(r.fuses[0].name, 'RunAsNode');
    assert.equal(r.fuses[0].state, 'enabled');
    assert.equal(r.fuses[1].state, 'disabled');
    assert.equal(r.fuses[4].state, 'removed');
  });

  it('does not name fuses of an unknown wire version', () => {
    const r = findFusesInBuffer(block(7, '11'))!;
    assert.equal(r.fuses[0].name, 'Fuse0');
  });

  it('finds a block straddling a streaming chunk boundary', async () => {
    const dir = tmp();
    const f = path.join(dir, 'fake.exe');
    const pad = Buffer.alloc(1000, 0x41);
    fs.writeFileSync(f, Buffer.concat([pad, block(1, '101100001')]));
    for (const chunk of [7, 64, 1003, 1010]) {
      const r = await readFusesFromFile(f, chunk);
      assert.ok(r, `chunk ${chunk}`);
      assert.equal(r!.offset, 1004);
      assert.equal(r!.fuses.length, 9);
      assert.equal(r!.fuses[3].state, 'enabled');
    }
  });

  it('returns undefined without a sentinel', async () => {
    const dir = tmp();
    const f = path.join(dir, 'none.exe');
    fs.writeFileSync(f, Buffer.alloc(5000, 1));
    assert.equal(await readFusesFromFile(f, 512), undefined);
  });

  const code = path.join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Microsoft VS Code', 'Code.exe');
  it('reproduces the REA observation on the installed Code.exe', { skip: !fs.existsSync(code) }, async () => {
    const r = (await readFusesFromFile(code))!;
    const state = (n: string) => r.fuses.find((f) => f.name === n)?.state;
    assert.equal(state('RunAsNode'), 'enabled');
    assert.equal(state('EnableEmbeddedAsarIntegrityValidation'), 'disabled');
    assert.equal(state('OnlyLoadAppFromAsar'), 'disabled');
  });
});

// ---------------------------------------------------------------------------
describe('redaction', () => {
  const r = new Redactor({ homeDir: 'C:\\Users\\Jane Doe', userName: 'Jane Doe' });

  it('removes multiline and truncated private keys', () => {
    const pem = 'before\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ndef\n-----END RSA PRIVATE KEY-----\nafter';
    assert.equal(r.redact(pem), 'before\n[redacted:private-key]\nafter');
    assert.ok(!r.redact('x -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB').includes('AAAA'));
  });

  it('removes common token formats', () => {
    const cases = [
      'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123',
      'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
      'AKIAABCDEFGHIJKLMNOP',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2ln',
      'xoxb-1234567890-abcdefghij',
      'npm_abcdefghijklmnopqrstuvwxyz0123456789',
    ];
    for (const c of cases) assert.ok(!r.redact(`token: ${c} end`).includes(c), c);
  });

  it('redacts secret-looking assignments, URL credentials, auth headers', () => {
    assert.equal(r.redact('DATABASE_PASSWORD=hunter2hunter'), 'DATABASE_PASSWORD=[redacted]');
    assert.equal(r.redact('"api_key": "abcd1234efgh"'), '"api_key": "[redacted]"');
    assert.equal(r.redact('postgres://admin:s3cret@db:5432/x'), 'postgres://admin:[redacted]@db:5432/x');
    assert.equal(r.redact('Authorization: Bearer abc.def.ghijklmn'), 'Authorization: Bearer [redacted]');
  });

  it('replaces home paths, encoded user names and e-mails', () => {
    assert.equal(r.redact('C:\\Users\\Jane Doe\\proj'), '~\\proj');
    assert.equal(r.redact('c:/users/jane doe/proj'), '~/proj');
    assert.equal(r.redact('C--Users-Jane-Doe-proj'), 'C--Users-user-proj');
    assert.equal(r.redact('mail jane@example.com now'), 'mail [email] now');
  });

  it('redacts keys and nested values deeply', () => {
    const out = r.redactDeep({ a: ['sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123'], 'jane@example.com': 1 });
    assert.deepEqual(out, { a: ['[redacted:anthropic-key]'], '[email]': 1 });
  });

  it('redacts structured credentials using the key as context', () => {
    const out = r.redactDeep({ input: { password: 'hunter2hunter', user: 'bob', token: 42, nested: { client_secret: 'abc' }, type: 'tool_use' } });
    assert.deepEqual(out, { input: { password: '[redacted]', user: 'bob', token: '[redacted]', nested: { client_secret: '[redacted]' }, type: 'tool_use' } });
    assert.equal(r.redactDeep({ input_tokens: 10, sessionId: 'abc' }).sessionId, 'abc', 'non-secret keys untouched');
  });

  it('redacts quoted secrets containing spaces and private keys split across strings', () => {
    assert.equal(r.redact('PASSWORD="correct horse battery staple"'), 'PASSWORD="[redacted]"');
    const parts = r.redactDeep(['-----BEGIN PRIVATE KEY-----\nMIIE' + 'A'.repeat(70), 'B'.repeat(64) + '\n' + 'C'.repeat(64) + '\n-----END PRIVATE KEY-----']);
    assert.ok(!JSON.stringify(parts).includes('AAAAAAAAAA') && !JSON.stringify(parts).includes('BBBBBBBBBB'));
  });

  it('withholds a private key split across separate strings', () => {
    const parts = r.redactDeep(['-----BEGIN RSA PRIVATE KEY-----', 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=', 'MIIEpAIBAAKCAQEA', '-----END RSA PRIVATE KEY-----', 'after']);
    const s = JSON.stringify(parts);
    assert.ok(!s.includes('QUJDREVG') && !s.includes('MIIEpAIB'), s);
    assert.equal(parts[4], 'after', 'redaction stops after END');
  });

  it('redacts Git Bash style home paths and plain user names', () => {
    assert.equal(r.redact('cd "/c/Users/Jane Doe/proj"'), 'cd "~/proj"');
    assert.equal(r.redact('Author: Jane Doe'), 'Author: user');
  });

  it('redacts known literal identifiers', () => {
    const r2 = r.withLiterals(['11111111-2222-4333-8444-555555555555']);
    assert.equal(r2.redact('owner 11111111-2222-4333-8444-555555555555'), 'owner [redacted:id]');
  });

  it('ignores invalid extra patterns instead of throwing', () => {
    const r2 = new Redactor({ extraPatterns: ['(', 'internal-\\d+'] });
    assert.equal(r2.redact('see internal-42'), 'see [redacted]');
  });
});

// ---------------------------------------------------------------------------
describe('claude session parsing', () => {
  it('encodes project dirs like Claude Code', () => {
    assert.equal(encodeProjectDir('c:\\Users\\Jane Q Doe\\Projects\\my-app'), 'c--Users-Jane-Q-Doe-Projects-my-app');
  });

  it('withholds an unterminated tail and counts malformed interior lines', () => {
    const r = splitCompleteRecords(line({ a: 1 }) + 'not json\n' + line([1]) + '{"partial":');
    assert.equal(r.records.length, 1);
    assert.equal(r.malformed, 2);
    assert.equal(r.droppedTail, true);
  });

  it('builds titles from the first real prompt, stripping harness tags', () => {
    const jsonl =
      line({ type: 'session-owner', accountUuid: 'acc', organizationUuid: 'org', sessionId: 's1' }) +
      line({ type: 'user', sessionId: 's1', timestamp: '2026-01-01T00:00:00Z', message: { role: 'user', content: [{ type: 'text', text: '<system-reminder>x</system-reminder>' }, { type: 'text', text: 'Fix the login bug\nmore' }] } }) +
      line({ type: 'assistant', timestamp: '2026-01-01T00:00:05Z', message: { model: 'm', content: [{ type: 'text', text: 'ok' }, { type: 'tool_use', name: 'Bash', input: { command: 'ls' } }] } }) +
      line({ type: 'user', message: { content: [{ type: 'tool_result', content: 'file.txt', is_error: false }] } });
    const { items, summary } = parseTranscript(jsonl);
    assert.equal(summary.title, 'Fix the login bug');
    assert.equal(summary.userTurns, 1);
    assert.equal(summary.toolCalls, 1);
    assert.equal(summary.organizationUuid, 'org');
    assert.deepEqual(items.map((i) => i.kind), ['user', 'assistant', 'tool_use', 'tool_result']);
  });
});

// ---------------------------------------------------------------------------
describe('publication preparation', () => {
  const ws = path.resolve(os.tmpdir(), 'ws-proj');
  const redactor = new Redactor({ homeDir: os.homedir() });

  function sessionFile(records: unknown[], tail = ''): string {
    const f = path.join(tmp(), 'abc-123.jsonl');
    fs.writeFileSync(f, records.map(line).join('') + tail);
    return f;
  }

  it('allows auto only when every cwd is inside the workspace', () => {
    assert.equal(assessEligibility([{ cwd: ws }, { cwd: path.join(ws, 'sub') }], ws, 0, false).autoOk, true);
    const mixed = assessEligibility([{ cwd: ws }, { cwd: path.resolve(os.tmpdir(), 'ws-project-other') }], ws, 0, false);
    assert.equal(mixed.autoOk, false);
    assert.equal(mixed.foreignCwds.length, 1);
    assert.equal(assessEligibility([{ type: 'x' }], ws, 0, false).autoOk, false, 'missing provenance is ambiguous');
    assert.equal(assessEligibility([{ cwd: ws }], ws, 1, false).autoOk, false, 'malformed interior blocks auto');
    const partial = assessEligibility([{ type: 'user', cwd: ws, message: {} }, { type: 'user', message: { content: 'x' } }], ws, 0, false);
    assert.equal(partial.autoOk, false, 'every content record needs provenance');
    assert.equal(assessEligibility([{ type: 'user', cwd: ws, message: {} }, { type: 'summary', summary: 's' }], ws, 0, false).autoOk, true, 'metadata may lack cwd');
  });

  it('removes owner UUIDs even when they appear inside tool output', () => {
    const f = sessionFile([
      { type: 'session-owner', accountUuid: '11111111-2222-4333-8444-555555555555', organizationUuid: '66666666-7777-4888-9999-aaaaaaaaaaaa' },
      { type: 'user', cwd: ws, message: { content: [{ type: 'tool_result', content: '{"accountUuid":"11111111-2222-4333-8444-555555555555"}' }] } },
    ]);
    const json = JSON.stringify(prepareSession(f, ws, redactor));
    assert.ok(!json.includes('11111111') && !json.includes('66666666'));
  });

  it('never exports unattributed summary records', () => {
    const f = sessionFile([
      { type: 'summary', summary: 'secret project codename' },
      { type: 'user', cwd: ws, message: { content: 'hello' } },
    ]);
    const p = prepareSession(f, ws, redactor);
    assert.equal(p.summary.title, 'hello');
    assert.ok(!JSON.stringify(p).includes('codename'));
  });

  it('strips harness wrapper tags from titles', () => {
    const f = sessionFile([{ type: 'user', cwd: ws, message: { content: '<browser_instruction># Chrome</browser_instruction>Build the org feature' } }]);
    assert.equal(prepareSession(f, ws, redactor).summary.title, 'Build the org feature');
  });

  it('strips owner ids, thinking and signatures; redacts before clipping', () => {
    const secret = 'sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZ';
    const longOut = 'a'.repeat(3990) + secret + 'b'.repeat(100);
    const f = sessionFile([
      { type: 'session-owner', accountUuid: 'acc-1', organizationUuid: 'org-1' },
      { type: 'user', cwd: ws, message: { content: `deploy with ${secret}` } },
      { type: 'assistant', cwd: ws, message: { content: [{ type: 'thinking', thinking: 'private', signature: 'SIG' }, { type: 'text', text: 'done' }] } },
      { type: 'user', cwd: ws, message: { content: [{ type: 'tool_result', content: longOut }] } },
    ]);
    const p = prepareSession(f, ws, redactor);
    const json = JSON.stringify(p);
    assert.ok(!json.includes('ZZZZZZZZZZ'), 'no secret fragment survives clipping');
    assert.ok(!json.includes('acc-1') && !json.includes('org-1'));
    assert.ok(!json.includes('private') && !json.includes('SIG'));
    assert.equal(p.summary.title, 'deploy with [redacted:anthropic-key]');
    assert.equal(p.eligibility.autoOk, true);
    assert.equal(p.sessionId, 'abc-123');
  });

  it('withholds a record still being written', () => {
    const f = sessionFile([{ type: 'user', cwd: ws, message: { content: 'one' } }], '{"type":"user","message":{"content":"two');
    const p = prepareSession(f, ws, redactor);
    assert.equal(p.items.length, 1);
    assert.equal(p.eligibility.droppedTail, true);
  });

  it('enforces the size cap while reading, and handles growth', () => {
    const f = sessionFile([{ type: 'user', cwd: ws, message: { content: 'x'.repeat(5000) } }]);
    assert.throws(() => readBounded(f, 1024), SourceTooLargeError);
    assert.ok(readBounded(f, 1024 * 1024).length > 5000);
  });
});

// ---------------------------------------------------------------------------
describe('organization store', () => {
  let root: string;
  let store: OrgStore;
  let projectId: string;
  const member = 'aaaaaaaa-0000-4000-8000-000000000001';
  const devA = 'dddddddd-0000-4000-8000-00000000000a';
  const devB = 'dddddddd-0000-4000-8000-00000000000b';
  const summary = (title: string) => ({ sessionId: 'sess-1', title, userTurns: 1, assistantTurns: 1, toolCalls: 0, lastTs: '2026-01-01T00:00:00Z' });
  const pub = (deviceId: string, title: string, sessionId = 'sess-1') =>
    store.publish({ projectId, memberId: member, deviceId, sessionId, summary: summary(title), items: [{ kind: 'user', text: title }] });
  const sessDir = (deviceId: string, sessionId = 'sess-1') => path.join(root, 'projects', projectId, 'members', member, 'devices', deviceId, 'sessions', sessionId);

  beforeEach(() => {
    root = tmp();
    store = OrgStore.create(root, 'Acme');
    projectId = store.createProject('Website').projectId;
    store.upsertMember(projectId, member, 'Jane');
  });

  it('creates org/projects/members and refuses to re-create', () => {
    assert.equal(store.readOrg()!.name, 'Acme');
    assert.equal(store.listProjects()[0].name, 'Website');
    assert.equal(store.listMembers(projectId)[0].displayName, 'Jane');
    assert.throws(() => OrgStore.create(root, 'Again'), OrgStoreError);
  });

  it('publishes, lists, and reports unchanged content', () => {
    const r1 = pub(devA, 'v1');
    assert.equal(r1.unchanged, false);
    assert.equal(pub(devA, 'v1').unchanged, true);
    const heads = store.listSessions(projectId, member);
    assert.equal(heads.length, 1);
    assert.equal(heads[0].latest.summary.title, 'v1');
  });

  it('a new revision supersedes regardless of wall clocks (sequence ordering)', () => {
    pub(devA, 'from A');
    // Device A's clock is far in the future; B publishes later with a normal clock.
    const aFile = fs.readdirSync(sessDir(devA)).find((n) => n.startsWith('rev-'))!;
    const rev: SessionRevision = JSON.parse(fs.readFileSync(path.join(sessDir(devA), aFile), 'utf8'));
    rev.publishedAt = '2099-01-01T00:00:00.000Z';
    fs.writeFileSync(path.join(sessDir(devA), aFile), JSON.stringify(rev));
    pub(devB, 'from B');
    const head = store.listSessions(projectId, member)[0];
    assert.equal(head.latest.summary.title, 'from B');
    assert.equal(head.latest.seq, 2);
    assert.equal(head.deviceHeads, 2);
  });

  it('two offline publishers with the same seq resolve deterministically and surface both heads', () => {
    pub(devA, 'A');
    // Simulate B publishing before A's revision synced: move A's dir away, publish B, move back.
    const hidden = sessDir(devA) + '.hidden';
    fs.renameSync(sessDir(devA), hidden);
    pub(devB, 'B');
    fs.renameSync(hidden, sessDir(devA));
    const h1 = store.listSessions(projectId, member)[0];
    const h2 = new OrgStore(root).listSessions(projectId, member)[0];
    assert.equal(h1.deviceHeads, 2);
    assert.equal(h1.competing.length, 2, 'conflict is exposed, not hidden');
    assert.equal(h1.latest.seq, 1);
    assert.equal(h1.latest.deviceId, h2.latest.deviceId);
    // Publishing again from A (having seen both) supersedes both versions.
    pub(devA, 'A merged');
    const h3 = store.listSessions(projectId, member)[0];
    assert.equal(h3.competing.length, 1);
    assert.equal(h3.latest.summary.title, 'A merged');
  });

  it('a skewed clock cannot win an equal-sequence tie', () => {
    pub(devA, 'A');
    const hidden = sessDir(devA) + '.hidden';
    fs.renameSync(sessDir(devA), hidden);
    pub(devB, 'B');
    fs.renameSync(hidden, sessDir(devA));
    // Rewrite A with a far-future clock (and a valid hash): ordering must not change.
    const before = store.listSessions(projectId, member)[0].latest.deviceId;
    const aFile = path.join(sessDir(devA), fs.readdirSync(sessDir(devA)).find((n) => n.startsWith('rev-'))!);
    const rev: SessionRevision = JSON.parse(fs.readFileSync(aFile, 'utf8'));
    rev.publishedAt = '2099-01-01T00:00:00.000Z';
    fs.writeFileSync(aFile, JSON.stringify(rev));
    assert.equal(new OrgStore(root).listSessions(projectId, member)[0].latest.deviceId, before);
  });

  it('ignores hash-valid revisions that violate the public schema', () => {
    pub(devA, 'good');
    const dir = sessDir(devA);
    const good: SessionRevision = JSON.parse(fs.readFileSync(path.join(dir, fs.readdirSync(dir).find((n) => n.startsWith('rev-'))!), 'utf8'));
    for (const [i, bad] of [
      { items: [null], summary: good.summary },
      { items: good.items, summary: { ...good.summary, lastTs: 12345 } },
      { items: good.items, summary: { ...good.summary, title: undefined } },
      { items: [{ kind: 'script', text: 'x' }], summary: good.summary },
    ].entries()) {
      const seq = 20 + i;
      const revId = `rev-0000${seq}-abcdef0${i}`;
      const r = { ...good, ...bad, seq, revId, parents: [good.revId] } as any;
      r.contentSha256 = sha256(canonicalJson({ summary: r.summary, items: r.items }));
      fs.writeFileSync(path.join(dir, `${revId}.json`), JSON.stringify(r));
    }
    const fresh = new OrgStore(root).listSessions(projectId, member);
    assert.equal(fresh.length, 1);
    assert.equal(fresh[0].latest.summary.title, 'good');
  });

  it('pruning never deletes the new revision even when corrupt high-seq files exist', () => {
    pub(devA, 'v1');
    const dir = sessDir(devA);
    for (const n of ['rev-000090-aaaaaaaa.json', 'rev-000091-bbbbbbbb.json', 'rev-000092-cccccccc.json']) fs.writeFileSync(path.join(dir, n), '{"broken":');
    const r = pub(devA, 'v2');
    assert.ok(fs.existsSync(r.file));
    assert.equal(new OrgStore(root).listSessions(projectId, member)[0].latest.summary.title, 'v2');
    assert.ok(!fs.readdirSync(dir).includes('rev-000092-cccccccc.json'), 'own corrupt leftovers are cleaned up');
  });

  it('refuses to publish through a junction placed in the member/device path', (t) => {
    const outside = tmp();
    const devicesDir = path.join(root, 'projects', projectId, 'members', member, 'devices');
    fs.mkdirSync(devicesDir, { recursive: true });
    try {
      fs.symlinkSync(outside, path.join(devicesDir, devA), 'junction');
    } catch {
      t.skip('cannot create junctions here');
      return;
    }
    assert.throws(() => pub(devA, 'x'), OrgStoreError);
    assert.equal(fs.readdirSync(outside).length, 0, 'nothing written outside the root');
  });

  it('detects two windows on the same device publishing concurrently', () => {
    pub(devA, 'base');
    // Two "windows" both saw only "base" and wrote siblings with the same seq.
    const dir = sessDir(devA);
    const base: SessionRevision = JSON.parse(fs.readFileSync(path.join(dir, fs.readdirSync(dir).find((n) => n.startsWith('rev-'))!), 'utf8'));
    for (const [suffix, title] of [['11111111', 'window 1'], ['22222222', 'window 2']] as const) {
      const r: SessionRevision = { ...base, revId: `rev-000002-${suffix}`, seq: 2, parents: [base.revId], summary: { ...base.summary, title }, items: [{ kind: 'user', text: title }] };
      r.contentSha256 = sha256(canonicalJson({ summary: r.summary, items: r.items }));
      fs.writeFileSync(path.join(dir, `${r.revId}.json`), JSON.stringify(r));
    }
    const h = new OrgStore(root).listSessions(projectId, member)[0];
    assert.equal(h.competing.length, 2, 'same-device siblings are both visible');
  });

  it('supersession is transitive across pruned intermediates', () => {
    pub(devA, 'A1');
    const aDir = sessDir(devA);
    const hidden = aDir + '.hidden';
    fs.renameSync(aDir, hidden); // A1 temporarily unavailable to B... but B saw it before:
    fs.renameSync(hidden, aDir);
    pub(devB, 'B2'); // B2 lists A1
    fs.renameSync(aDir, hidden); // A1 goes offline
    for (let i = 0; i < 4; i++) pub(devB, `B${3 + i}`); // B2 pruned eventually
    fs.renameSync(hidden, aDir); // A1 comes back
    const h = new OrgStore(root).listSessions(projectId, member)[0];
    assert.equal(h.competing.length, 1, 'A1 does not reappear as a conflict');
    assert.equal(h.latest.summary.title, 'B6');
  });

  it('keeps showing the last valid version while a prune arrives before its replacement', () => {
    pub(devA, 'v1');
    const reader = new OrgStore(root);
    assert.equal(reader.listSessions(projectId, member)[0].latest.summary.title, 'v1');
    // Simulate sync delivering the deletion first: revision files vanish, folder stays.
    for (const n of fs.readdirSync(sessDir(devA))) fs.unlinkSync(path.join(sessDir(devA), n));
    const h = reader.listSessions(projectId, member)[0];
    assert.equal(h.latest.summary.title, 'v1');
    assert.equal(h.stale, true);
  });

  it('retries a failed read after hydration instead of caching the failure forever', () => {
    pub(devA, 'v1');
    const dir = sessDir(devA);
    const f = path.join(dir, fs.readdirSync(dir).find((n) => n.startsWith('rev-'))!);
    const good = fs.readFileSync(f);
    const st = fs.statSync(f);
    const reader = new OrgStore(root);
    fs.writeFileSync(f, Buffer.alloc(good.length, 0x20)); // placeholder: same size, unreadable JSON
    fs.utimesSync(f, st.atime, st.mtime);
    assert.equal(reader.listSessions(projectId, member).length, 0, 'placeholder is not shown as a valid session');
    (reader as any).revCache.forEach((v: any) => (v.at = 0)); // TTL elapsed
    fs.writeFileSync(f, good);
    fs.utimesSync(f, st.atime, st.mtime); // hydrated: same size and mtime
    const h = reader.listSessions(projectId, member)[0];
    assert.equal(h.latest.summary.title, 'v1');
    assert.notEqual(h.stale, true);
  });

  it('uses short ids so nested shared paths stay compact', () => {
    assert.ok(projectId.length <= 16);
    assert.ok(store.readOrg()!.orgId.length <= 16);
  });

  it('ignores temp files, corrupt and tampered revisions, keeping the prior valid one', () => {
    pub(devA, 'good');
    const dir = sessDir(devA);
    fs.writeFileSync(path.join(dir, '.tmp-123-abcd'), '{"half":');
    fs.writeFileSync(path.join(dir, 'rev-000009-deadbeef.json'), '{"schema":1,'); // partial sync
    assert.equal(store.listSessions(projectId, member)[0].latest.summary.title, 'good');

    const good: SessionRevision = JSON.parse(fs.readFileSync(path.join(dir, fs.readdirSync(dir).find((n) => n.startsWith('rev-000001'))!), 'utf8'));
    const tampered = { ...good, revId: 'rev-000010-cafebabe', seq: 10, summary: { ...good.summary, title: 'evil' } };
    fs.writeFileSync(path.join(dir, 'rev-000010-cafebabe.json'), JSON.stringify(tampered)); // hash mismatch
    const wrongCtx = { ...good, revId: 'rev-000011-cafebabe', seq: 11, memberId: 'bbbbbbbb-0000-4000-8000-000000000002' };
    wrongCtx.contentSha256 = sha256(canonicalJson({ summary: wrongCtx.summary, items: wrongCtx.items }));
    fs.writeFileSync(path.join(dir, 'rev-000011-cafebabe.json'), JSON.stringify(wrongCtx)); // embedded id mismatch
    assert.equal(new OrgStore(root).listSessions(projectId, member)[0].latest.summary.title, 'good');
  });

  it('a manifest-less pending session (only invalid files synced) stays hidden', () => {
    const dir = sessDir(devA, 'sess-2');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'rev-000001-aaaaaaaa.json'), '{');
    assert.equal(store.listSessions(projectId, member).length, 0);
  });

  it('prunes old revisions of this device only after a verified write', () => {
    for (let i = 0; i < 6; i++) pub(devA, `v${i}`);
    const revs = fs.readdirSync(sessDir(devA)).filter((n) => n.startsWith('rev-'));
    assert.equal(revs.length, 3);
    assert.equal(store.listSessions(projectId, member)[0].latest.summary.title, 'v5');
  });

  it('rejects traversal and reserved ids', () => {
    assert.throws(() => store.publish({ projectId, memberId: '../x', deviceId: devA, sessionId: 's', summary: summary('t'), items: [] }), OrgStoreError);
    assert.throws(() => store.publish({ projectId, memberId: member, deviceId: devA, sessionId: '..\\..\\x', summary: summary('t'), items: [] }), OrgStoreError);
    assert.throws(() => store.publish({ projectId, memberId: 'con', deviceId: devA, sessionId: 's', summary: summary('t'), items: [] }), OrgStoreError);
    assert.throws(() => store.upsertMember('../../etc', member, 'x'), OrgStoreError);
  });

  it('ignores project folders whose embedded ids do not match', () => {
    const fake = path.join(root, 'projects', 'ffffffff-0000-4000-8000-000000000000');
    fs.mkdirSync(fake, { recursive: true });
    fs.writeFileSync(path.join(fake, 'project.json'), JSON.stringify({ schema: 1, projectId: 'other', orgId: store.readOrg()!.orgId, name: 'x', createdAt: '' }));
    assert.equal(store.listProjects().length, 1);
  });

  it('refuses publishing into a project of another organization', () => {
    const other = OrgStore.create(tmp(), 'Other');
    assert.throws(() => other.publish({ projectId, memberId: member, deviceId: devA, sessionId: 's', summary: summary('t'), items: [] }), /Project not found/);
  });

  it('unpublish removes only this device copy', () => {
    pub(devA, 'A');
    pub(devB, 'B');
    store.unpublish(projectId, member, devB, 'sess-1');
    const h = store.listSessions(projectId, member)[0];
    assert.equal(h.deviceHeads, 1);
    assert.equal(h.latest.summary.title, 'A');
  });

  it('does not follow directory symlinks/junctions out of the root', { skip: process.platform !== 'win32' && process.platform !== 'linux' }, (t) => {
    const outside = tmp();
    const target = path.join(root, 'projects', projectId, 'members', 'cccccccc-0000-4000-8000-000000000003');
    try {
      fs.symlinkSync(outside, target, 'junction');
    } catch {
      t.skip('cannot create junctions here');
      return;
    }
    assert.ok(!store.listMembers(projectId).some((m) => m.memberId.startsWith('cccccccc')));
  });
});

// ---------------------------------------------------------------------------
describe('auto-share consent', () => {
  const link: WorkspaceLink = { sourceDir: 'W', root: 'R', orgId: 'o', projectId: 'p', projectName: 'P', linkedAt: '' };
  it('is valid only for the same source folder, destination and content schema', () => {
    assert.equal(autoConsentValid(link), false);
    const ok: WorkspaceLink = { ...link, auto: { sourceDir: 'W', root: 'R', orgId: 'o', projectId: 'p', contentSchema: CONTENT_SCHEMA, consentAt: '' } };
    assert.equal(autoConsentValid(ok), true);
    assert.equal(autoConsentValid({ ...ok, sourceDir: 'W2' }), false, 'different workspace folder');
    assert.equal(autoConsentValid({ ...ok, projectId: 'p2' }), false, 'relinked project');
    assert.equal(autoConsentValid({ ...ok, root: 'R2' }), false, 'moved folder');
    assert.equal(autoConsentValid(ok, CONTENT_SCHEMA + 1), false, 'content types changed');
  });
});
