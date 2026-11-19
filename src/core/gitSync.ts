import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Keeps an organization folder that is a git working tree in sync: pull before reading,
 * commit + push after writing. Deliberately narrow:
 *  - only when the organization folder IS the top level of its working tree (a dedicated
 *    branch/worktree or repo), so it never stages, rebases or pushes a code checkout;
 *  - only paths inside the folder are committed;
 *  - never force-pushes; a rejected push is retried once after `pull --rebase`;
 *  - non-interactive (no credential prompts on the terminal).
 * Every operation is serialized; the result is reported, never thrown.
 */

export interface GitResult { code: number; out: string; err: string }
export type GitRunner = (args: string[], cwd: string) => Promise<GitResult>;

export const runGit: GitRunner = (args, cwd) =>
  new Promise((resolve) => {
    cp.execFile('git', args, {
      cwd,
      windowsHide: true,
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
    }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as { code?: unknown }).code === 'number' ? (err as { code: number }).code : -1) : 0;
      resolve({ code, out: String(stdout ?? '').trim(), err: String(stderr ?? '').trim() });
    });
  });

export type SyncOutcome =
  | { ok: true; changed: boolean; detail: string }
  | { ok: false; detail: string };

function samePath(a: string, b: string): boolean {
  const norm = (p: string) => {
    let r = path.resolve(p);
    try { r = fs.realpathSync.native(r); } catch { /* keep resolved */ }
    return process.platform === 'win32' ? r.toLowerCase() : r;
  };
  return norm(a) === norm(b);
}

function firstLine(r: GitResult): string {
  return (r.err || r.out).split(/\r?\n/).find((l) => l.trim()) ?? `git exited with ${r.code}`;
}

export class GitSync {
  private chain: Promise<unknown> = Promise.resolve();

  private constructor(readonly root: string, private readonly git: GitRunner) {}

  /**
   * Returns a GitSync when `root` is the top level of a git working tree, otherwise a reason.
   */
  static async detect(root: string, git: GitRunner = runGit): Promise<GitSync | { reason: string }> {
    const top = await git(['rev-parse', '--show-toplevel'], root);
    if (top.code !== 0) return { reason: 'not a git working tree' };
    if (!samePath(top.out, root)) {
      return { reason: `the organization folder is inside a larger git checkout (${top.out}); use a dedicated branch worktree or repo for automatic sync` };
    }
    return new GitSync(root, git);
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.chain.then(fn, fn);
    this.chain = next.catch(() => undefined);
    return next;
  }

  private async hasUpstream(): Promise<boolean> {
    return (await this.git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'], this.root)).code === 0;
  }

  private async head(): Promise<string> {
    return (await this.git(['rev-parse', 'HEAD'], this.root)).out;
  }

  private async pullRebase(): Promise<SyncOutcome> {
    if (!(await this.hasUpstream())) return { ok: true, changed: false, detail: 'no upstream branch yet' };
    const before = await this.head();
    const r = await this.git(['pull', '--rebase', '--autostash', '--no-edit', '--quiet'], this.root);
    if (r.code !== 0) {
      await this.git(['rebase', '--abort'], this.root);
      return { ok: false, detail: `git pull failed: ${firstLine(r)}` };
    }
    return { ok: true, changed: (await this.head()) !== before, detail: 'pulled' };
  }

  /** Fetches and rebases onto the upstream branch. */
  pull(): Promise<SyncOutcome> {
    return this.serial(() => this.pullRebase());
  }

  /** Commits every change inside the organization folder and pushes it. */
  commitAndPush(message: string): Promise<SyncOutcome> {
    return this.serial(async () => {
      const add = await this.git(['add', '-A', '--', '.'], this.root);
      if (add.code !== 0) return { ok: false, detail: `git add failed: ${firstLine(add)}` };
      const staged = await this.git(['diff', '--cached', '--quiet', '--', '.'], this.root);
      let committed = false;
      if (staged.code === 1) {
        const c = await this.git(['commit', '--quiet', '-m', message, '--', '.'], this.root);
        if (c.code !== 0) return { ok: false, detail: `git commit failed: ${firstLine(c)}` };
        committed = true;
      } else if (staged.code !== 0) {
        return { ok: false, detail: `git diff failed: ${firstLine(staged)}` };
      }
      const upstream = await this.hasUpstream();
      if (upstream) {
        const ahead = await this.git(['rev-list', '--count', '@{u}..HEAD'], this.root);
        if (ahead.code === 0 && ahead.out === '0') return { ok: true, changed: committed, detail: 'nothing to push' };
      }
      const pushArgs = upstream ? ['push', '--quiet'] : ['push', '--quiet', '-u', 'origin', 'HEAD'];
      let p = await this.git(pushArgs, this.root);
      if (p.code !== 0 && upstream) {
        const pulled = await this.pullRebase();
        if (!pulled.ok) return pulled;
        p = await this.git(pushArgs, this.root);
      }
      if (p.code !== 0) return { ok: false, detail: `git push failed: ${firstLine(p)}` };
      return { ok: true, changed: committed, detail: 'pushed' };
    });
  }
}
