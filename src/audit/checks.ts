import * as cp from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { FUSE_RISKS, readFusesFromFile } from '../core/fuses';
import { parseRegValue } from '../core/regValue';
import { claudeProjectsDir, findLongPaths, longPath, WINDOWS_MAX_PATH } from '../core/claudeSessions';

export type Severity = 'high' | 'warning' | 'info' | 'ok';
export type Category = 'security' | 'maintenance' | 'privacy' | 'inventory' | 'claude';

export interface FindingAction {
  kind: 'fix' | 'review' | 'guidance';
  label: string;
  /** Only 'fix' actions with safe=true (security/claude categories) are applied by "Apply All Safe Fixes". */
  safe?: boolean;
  /** True when the fix records an entry that "Undo Last Audit Fix" can revert. */
  undoable?: boolean;
  run?: () => Promise<string>;
}

export interface Finding {
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  /** Plain text; rendered as text, never as HTML. */
  detail: string;
  /** observed = read from the artifact/config; inferred = our interpretation. */
  confidence: 'observed' | 'inferred';
  evidence?: string;
  action?: FindingAction;
}

const UNDO_KEY = 'vssession.audit.undo';

interface UndoEntry { key: string; previous: unknown; applied: unknown; at: string }

function execFileText(cmd: string, args: string[], timeoutMs = 8000): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    cp.execFile(cmd, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout) => {
      const code = err && typeof (err as { code?: unknown }).code === 'number' ? (err as { code: number }).code : err ? -1 : 0;
      resolve({ code, out: String(stdout ?? '').trim() });
    });
  });
}

const ENV_KEYS: Array<{ key: string; where: string }> = [
  { key: 'HKCU\\Environment', where: 'your user environment variables' },
  { key: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment', where: 'the system environment variables' },
];

/** Persistent (registry) environment variables on Windows; empty elsewhere. */
async function readPersistentEnv(names: string[]): Promise<Array<{ name: string; value: string; where: string }>> {
  if (process.platform !== 'win32') return [];
  const hits: Array<{ name: string; value: string; where: string }> = [];
  for (const { key, where } of ENV_KEYS) {
    for (const name of names) {
      const r = await execFileText('reg', ['query', key, '/v', name], 4000);
      if (r.code !== 0) continue;
      const value = parseRegValue(r.out, name);
      if (value) hits.push({ name, value, where });
    }
  }
  return hits;
}

async function sha256File(file: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(longPath(file))
      .on('data', (d) => h.update(d))
      .on('error', () => resolve(undefined))
      .on('end', () => resolve(h.digest('hex')));
  });
}

// ---------------------------------------------------------------------------
// Settings checks (names/values verified against VS Code 1.146 and Claude Code 2.1.326)
// ---------------------------------------------------------------------------

interface SettingRule {
  key: string;
  isBad: (v: unknown) => boolean;
  fixValue: unknown;
  category: Category;
  severity: Severity;
  title: string;
  why: string;
  /** Preferences (privacy/maintenance) are never part of "fix all". */
  safe: boolean;
}

const SETTING_RULES: SettingRule[] = [
  {
    key: 'security.workspace.trust.enabled', isBad: (v) => v === false, fixValue: true, category: 'security', severity: 'high', safe: true,
    title: 'Workspace Trust is disabled',
    why: 'Every folder you open is treated as trusted: tasks, debug configs and extensions may run repository-controlled code without restricted mode.',
  },
  {
    key: 'security.workspace.trust.untrustedFiles', isBad: (v) => v === 'open', fixValue: 'prompt', category: 'security', severity: 'warning', safe: true,
    title: 'Untrusted files open silently in trusted windows',
    why: 'Loose files from untrusted locations are opened in a trusted window without asking.',
  },
  {
    key: 'task.allowAutomaticTasks', isBad: (v) => v === 'on', fixValue: 'off', category: 'security', severity: 'warning', safe: true,
    title: 'Automatic tasks are allowed',
    why: 'tasks.json entries with runOn=folderOpen execute as soon as a folder is opened.',
  },
  {
    key: 'chat.tools.global.autoApprove', isBad: (v) => v === true, fixValue: false, category: 'security', severity: 'high', safe: true,
    title: 'All agent tool calls are auto-approved',
    why: 'Chat agents can run terminal commands and edit files without confirmation.',
  },
  {
    key: 'security.promptForLocalFileProtocolHandling', isBad: (v) => v === false, fixValue: true, category: 'security', severity: 'warning', safe: true,
    title: 'vscode://file links open local files without prompting',
    why: 'Web pages can open local files in VS Code via protocol links without confirmation.',
  },
  {
    key: 'security.promptForRemoteFileProtocolHandling', isBad: (v) => v === false, fixValue: true, category: 'security', severity: 'warning', safe: true,
    title: 'vscode-remote links open without prompting',
    why: 'Web pages can open remote resources via protocol links without confirmation.',
  },
  {
    key: 'http.proxyStrictSSL', isBad: (v) => v === false, fixValue: true, category: 'security', severity: 'warning', safe: true,
    title: 'Proxy TLS certificate validation is disabled',
    why: 'Extension and marketplace traffic through a proxy accepts any certificate (MITM risk).',
  },
  {
    key: 'extensions.verifySignature', isBad: (v) => v === false, fixValue: true, category: 'security', severity: 'warning', safe: true,
    title: 'Extension signature verification is disabled',
    why: 'Tampered marketplace packages would install without a signature check.',
  },
  {
    key: 'claudeCode.allowDangerouslySkipPermissions', isBad: (v) => v === true, fixValue: false, category: 'claude', severity: 'high', safe: true,
    title: 'Claude Code may skip all permission prompts',
    why: 'Allows bypassPermissions mode in the Claude Code extension: shell commands and edits run without confirmation.',
  },
  {
    key: 'claudeCode.initialPermissionMode', isBad: (v) => v === 'bypassPermissions', fixValue: 'default', category: 'claude', severity: 'high', safe: true,
    title: 'Claude Code starts in bypassPermissions mode',
    why: 'New Claude sessions start without any permission prompts.',
  },
  {
    key: 'extensions.autoUpdate', isBad: (v) => v === false || v === 'none', fixValue: true, category: 'maintenance', severity: 'info', safe: false,
    title: 'Extension auto-update is off',
    why: 'Security fixes in extensions are not installed automatically. May be intentional in managed environments.',
  },
  {
    key: 'update.mode', isBad: (v) => v === 'none' || v === 'manual', fixValue: 'default', category: 'maintenance', severity: 'info', safe: false,
    title: 'VS Code updates are not automatic',
    why: 'Electron/Chromium security patches arrive only with VS Code updates. May be intentional in managed environments.',
  },
  {
    key: 'telemetry.telemetryLevel', isBad: (v) => v === 'all', fixValue: 'error', category: 'privacy', severity: 'info', safe: false,
    title: 'Full telemetry is enabled',
    why: 'Privacy preference, not a vulnerability. "error" or "off" sends less usage data.',
  },
];

function effectiveSource(i: NonNullable<ReturnType<vscode.WorkspaceConfiguration['inspect']>>): 'policy' | 'workspaceFolder' | 'workspace' | 'global' | 'default' {
  const anyI = i as unknown as { policyValue?: unknown };
  if (anyI.policyValue !== undefined) return 'policy';
  if (i.workspaceFolderValue !== undefined) return 'workspaceFolder';
  if (i.workspaceValue !== undefined) return 'workspace';
  if (i.globalValue !== undefined) return 'global';
  return 'default';
}

function checkSettings(context: vscode.ExtensionContext): Finding[] {
  const out: Finding[] = [];
  const cfg = vscode.workspace.getConfiguration();
  for (const rule of SETTING_RULES) {
    const i = cfg.inspect(rule.key);
    if (!i) continue; // setting not registered in this build: not applicable
    const value = cfg.get(rule.key);
    if (!rule.isBad(value)) continue;
    const src = effectiveSource(i);
    const base: Finding = {
      id: `setting:${rule.key}`,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      confidence: 'observed',
      detail: `${rule.why}\n\nSetting: ${rule.key} = ${JSON.stringify(value)} (from ${src} scope). Recommended: ${JSON.stringify(rule.fixValue)}.`,
      evidence: `vscode.workspace.getConfiguration().inspect('${rule.key}')`,
    };
    if (src === 'policy') {
      base.action = { kind: 'guidance', label: 'Managed by policy — ask your administrator' };
    } else if (src === 'workspace' || src === 'workspaceFolder') {
      base.action = {
        kind: 'review', label: 'Review workspace setting',
        run: async () => {
          await vscode.commands.executeCommand('workbench.action.openWorkspaceSettingsFile');
          return `Opened workspace settings; ${rule.key} is overridden there.`;
        },
      };
    } else {
      base.action = {
        kind: 'fix', label: `Set ${rule.key} = ${JSON.stringify(rule.fixValue)}`, safe: rule.safe, undoable: true,
        run: async () => {
          // Fresh read: the value or its source may have changed since the audit ran.
          const fresh = vscode.workspace.getConfiguration();
          const now = fresh.inspect(rule.key);
          if (!now) throw new Error(`${rule.key} is no longer available.`);
          if (!rule.isBad(fresh.get(rule.key))) return `${rule.key} is already ${JSON.stringify(fresh.get(rule.key))}; nothing changed.`;
          const nowSrc = effectiveSource(now);
          if (nowSrc !== 'global' && nowSrc !== 'default') throw new Error(`${rule.key} is now set by ${nowSrc}; review it there instead.`);
          const before = now.globalValue;
          await vscode.workspace.getConfiguration().update(rule.key, rule.fixValue, vscode.ConfigurationTarget.Global);
          const after = vscode.workspace.getConfiguration().get(rule.key);
          if (rule.isBad(after)) throw new Error(`${rule.key} is still ${JSON.stringify(after)} after the update (overridden elsewhere?).`);
          const undo = context.globalState.get<UndoEntry[]>(UNDO_KEY, []);
          undo.push({ key: rule.key, previous: before, applied: rule.fixValue, at: new Date().toISOString() });
          await context.globalState.update(UNDO_KEY, undo.slice(-50));
          return `${rule.key} set to ${JSON.stringify(rule.fixValue)} (verified).`;
        },
      };
    }
    out.push(base);
  }
  return out;
}

/** Revert the last fix, refusing if the user changed the value since. */
export async function undoLastFix(context: vscode.ExtensionContext): Promise<string> {
  const undo = context.globalState.get<UndoEntry[]>(UNDO_KEY, []);
  const last = undo.pop();
  if (!last) return 'Nothing to undo.';
  const current = vscode.workspace.getConfiguration().inspect(last.key)?.globalValue;
  if (JSON.stringify(current) !== JSON.stringify(last.applied)) {
    await context.globalState.update(UNDO_KEY, undo);
    return `Not undone: ${last.key} was changed after the fix (now ${JSON.stringify(current)}).`;
  }
  await vscode.workspace.getConfiguration().update(last.key, last.previous, vscode.ConfigurationTarget.Global);
  await context.globalState.update(UNDO_KEY, undo);
  return `Restored ${last.key} to ${last.previous === undefined ? '(default)' : JSON.stringify(last.previous)}.`;
}

// ---------------------------------------------------------------------------
// Electron runtime / install checks
// ---------------------------------------------------------------------------

async function checkRuntime(): Promise<Finding[]> {
  const out: Finding[] = [];
  const exe = process.execPath;
  const appRoot = vscode.env.appRoot;
  const electron = process.versions.electron ?? 'unknown';
  const userInstall = process.platform === 'win32' && !!process.env.LOCALAPPDATA && appRoot.toLowerCase().startsWith(process.env.LOCALAPPDATA.toLowerCase());

  let exeHash: string | undefined;
  try {
    exeHash = await sha256File(exe);
  } catch {
    /* ignore */
  }
  out.push({
    id: 'inventory:vscode', title: `VS Code ${vscode.version} (Electron ${electron}, Node ${process.versions.node})`, category: 'inventory', severity: 'info', confidence: 'observed',
    detail: `Executable: ${exe}\nSHA-256: ${exeHash ?? 'unavailable'}\nApp root: ${appRoot}\nInstall type: ${userInstall ? 'per-user (user-writable)' : 'system or unknown'}`,
    evidence: 'process.execPath, vscode.env.appRoot, process.versions',
  });

  let fuses;
  try {
    fuses = await readFusesFromFile(exe);
  } catch (e) {
    out.push({ id: 'fuses:error', title: 'Could not read Electron fuses', category: 'security', severity: 'info', confidence: 'observed', detail: String(e) });
  }
  if (fuses && fuses.version !== 1) {
    out.push({ id: 'fuses:unknown', title: `Unknown Electron fuse wire version ${fuses.version}`, category: 'security', severity: 'info', confidence: 'observed', detail: 'Fuse states cannot be interpreted for this version.' });
  } else if (fuses) {
    for (const risk of FUSE_RISKS) {
      const f = fuses.fuses.find((x) => x.name === risk.fuse);
      if (!f || f.state === risk.expected || f.state === 'removed') continue;
      let severity = risk.severity;
      let detail = `${risk.why}\n\nObserved: ${risk.fuse} = ${f.state} (byte 0x${f.rawByte.toString(16)} at file offset ${fuses.offset}). Hardened value: ${risk.expected}.`;
      if (risk.fuse === 'EnableEmbeddedAsarIntegrityValidation' && userInstall) {
        severity = 'warning';
        detail += '\n\nThis is a per-user install, so files under the app root are writable by any process running as you.';
      }
      detail += risk.vscodeNeedsIt
        ? '\n\nVS Code depends on this fuse; flipping it in Code.exe would break VS Code and be overwritten by the next update. Report-only.'
        : '\n\nThis is a build-time decision by the VS Code team. Report-only; mitigate by keeping the install directory protected (system-wide install).';
      out.push({
        id: `fuse:${risk.fuse}`, title: `Electron fuse ${risk.fuse} is ${f.state}`, category: 'security', severity, confidence: 'observed', detail,
        evidence: `Code.exe sentinel at offset ${fuses.offset} (REA inspect_electron_fuses reproduced)`,
        action: { kind: 'guidance', label: 'Report-only (cannot be fixed safely)' },
      });
    }
  }

  // VS Code itself starts the extension host with ELECTRON_RUN_AS_NODE=1, so process.env cannot tell a
  // user-set value apart from VS Code's own. Only the persistent environment (registry on Windows) counts.
  const persistentEnv = await readPersistentEnv(['NODE_OPTIONS', 'ELECTRON_RUN_AS_NODE']);
  const envHits: Array<{ name: string; value: string; where: string }> = [];
  if (process.env.NODE_OPTIONS) envHits.push({ name: 'NODE_OPTIONS', value: process.env.NODE_OPTIONS, where: "VS Code's environment" });
  for (const p of persistentEnv) if (!envHits.some((h) => h.name === p.name)) envHits.push(p);
  for (const v of envHits) {
    out.push({
      id: `env:${v.name}`, title: `${v.name} is set in ${v.where}`, category: 'security', severity: 'warning', confidence: 'observed',
      detail: `${v.name}=${v.value}\nCode.exe honours this variable (its fuse is enabled), so it can inject code into every Electron/Node process launched from this environment. Remove it from your user/system environment variables unless you set it deliberately.`,
      action: { kind: 'guidance', label: 'Remove from environment variables' },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Claude Code checks
// ---------------------------------------------------------------------------

async function checkClaude(): Promise<Finding[]> {
  const out: Finding[] = [];
  const ext = vscode.extensions.getExtension('anthropic.claude-code');
  if (ext) {
    const main = path.join(ext.extensionPath, 'extension.js');
    const h = await sha256File(main);
    out.push({
      id: 'inventory:claude', title: `Claude Code extension ${ext.packageJSON?.version ?? '?'}`, category: 'inventory', severity: 'info', confidence: 'observed',
      detail: `Path: ${ext.extensionPath}\nextension.js SHA-256: ${h ?? 'unavailable'}\n\nNot examined by this audit: credential storage, network destinations and subprocess arguments of the extension. Absence of findings here is not a security verdict.`,
    });
  }

  // Claude extension settings that change what gets executed (scope=machine, so only user settings can set them).
  const cc = vscode.workspace.getConfiguration('claudeCode');
  const openUserSettings = async () => {
    await vscode.commands.executeCommand('workbench.action.openSettingsJson');
    return 'Opened user settings.json.';
  };
  const wrapper = cc.get<string>('claudeProcessWrapper');
  if (wrapper) {
    out.push({
      id: 'claude:wrapper', title: 'Claude Code runs a custom process wrapper', category: 'claude', severity: 'info', confidence: 'observed',
      detail: `claudeCode.claudeProcessWrapper = ${wrapper}\nThe extension launches this executable instead of its bundled Claude binary (observed in extension.js: pathToClaudeCodeExecutable). Make sure the file is yours and not writable by other users.`,
      evidence: 'extension.js Pse(): viaProcessWrapper',
      action: { kind: 'review', label: 'Open user settings', run: openUserSettings },
    });
  }
  const envVars = cc.get<{ name?: string; value?: string }[]>('environmentVariables') ?? [];
  const secretVars = envVars.filter((v) => v?.name && v.value && /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)/i.test(v.name));
  if (secretVars.length) {
    out.push({
      id: 'claude:envsecrets', title: 'Secrets stored in plaintext VS Code settings', category: 'claude', severity: 'warning', confidence: 'inferred',
      detail: `claudeCode.environmentVariables contains ${secretVars.map((v) => v.name).join(', ')}. settings.json is plaintext and is uploaded by Settings Sync. Prefer the OS credential store / claude login, or an environment variable set outside VS Code.`,
      action: { kind: 'review', label: 'Open user settings', run: openUserSettings },
    });
  }
  if (envVars.some((v) => v?.name && /^(NODE_OPTIONS|ELECTRON_RUN_AS_NODE)$/i.test(v.name))) {
    out.push({
      id: 'claude:envnode', title: 'Claude Code process gets NODE_OPTIONS / ELECTRON_RUN_AS_NODE', category: 'claude', severity: 'warning', confidence: 'observed',
      detail: 'claudeCode.environmentVariables injects Node runtime flags into the Claude process, which can load extra code into it.',
      action: { kind: 'review', label: 'Open user settings', run: openUserSettings },
    });
  }

  // Long paths in the session store.
  const projects = claudeProjectsDir();
  if (process.platform === 'win32' && fs.existsSync(longPath(projects))) {
    const long = findLongPaths(projects);
    if (long.length) {
      let readable = false;
      try {
        fs.readdirSync(longPath(long[0]));
        readable = true;
      } catch {
        /* ignore */
      }
      const reg = await execFileText('reg', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem', '/v', 'LongPathsEnabled']);
      const regOn = /LongPathsEnabled\s+REG_DWORD\s+0x1/i.test(reg.out);
      out.push({
        id: 'claude:longpaths', title: `${long.length}${long.length >= 500 ? '+' : ''} Claude session paths exceed Windows MAX_PATH (${WINDOWS_MAX_PATH})`, category: 'claude', severity: regOn ? 'info' : 'warning', confidence: 'observed',
        detail:
          `Example: ${long[0]}\n\nReadable by this extension (\\\\?\\ prefix via Node): ${readable ? 'yes' : 'NO'}.\n` +
          `Windows LongPathsEnabled: ${regOn ? 'on' : 'off'}. Tools without long-path support (Windows PowerShell 5.1, Explorer, many backup/sync tools) fail on these paths.\n\n` +
          'Fix (requires administrator, then sign out/in):\n  reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f\n' +
          'VsSession itself always reads sessions through \\\\?\\ paths, so sharing works regardless. Sessions are not moved or archived automatically.',
        action: regOn ? undefined : {
          kind: 'guidance', label: 'Copy the admin command',
          run: async () => {
            await vscode.env.clipboard.writeText('reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f');
            return 'Command copied. Run it in an elevated terminal, then sign out and back in.';
          },
        },
      });
    }
  }

  // Git long paths (separate, git-specific remedy).
  if (process.platform === 'win32') {
    const g = await execFileText('git', ['config', '--global', '--get', 'core.longpaths']);
    if (g.code !== -1 && g.out.toLowerCase() !== 'true') {
      out.push({
        id: 'git:longpaths', title: 'Git core.longpaths is not enabled', category: 'maintenance', severity: 'info', confidence: 'observed',
        detail: 'Git for Windows fails to check out files with paths over 260 characters (common in node_modules and in shared org folders kept in a git repo).',
        action: {
          kind: 'fix', label: 'git config --global core.longpaths true', safe: false,
          run: async () => {
            const r = await execFileText('git', ['config', '--global', 'core.longpaths', 'true']);
            const v = await execFileText('git', ['config', '--global', '--get', 'core.longpaths']);
            if (r.code !== 0 || v.out !== 'true') throw new Error('git config failed');
            return 'core.longpaths = true (verified).';
          },
        },
      });
    }
  }

  // Claude CLI settings (~/.claude/settings.json). Informational: effective policy may combine several files.
  const settingsFile = path.join(process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude'), 'settings.json');
  try {
    const s = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
    const perms = s?.permissions ?? {};
    const allow: string[] = Array.isArray(perms.allow) ? perms.allow.filter((x: unknown) => typeof x === 'string') : [];
    const broad = allow.filter((a) => /^Bash(\(\s*\*?\s*\))?$/.test(a) || a === 'Bash(*)' || a === '*');
    const open = async () => {
      await vscode.window.showTextDocument(vscode.Uri.file(settingsFile));
      return 'Opened ~/.claude/settings.json.';
    };
    if (perms.defaultMode === 'bypassPermissions') {
      out.push({
        id: 'claude:bypass', title: 'Claude Code CLI defaults to bypassPermissions', category: 'claude', severity: 'high', confidence: 'observed',
        detail: `${settingsFile}: permissions.defaultMode = "bypassPermissions". Every tool call runs without confirmation. Project/managed settings may override this file.`,
        action: { kind: 'review', label: 'Open settings.json', run: open },
      });
    }
    if (broad.length) {
      out.push({
        id: 'claude:broadbash', title: 'Claude Code allows every shell command', category: 'claude', severity: 'warning', confidence: 'inferred',
        detail: `${settingsFile}: permissions.allow contains ${broad.map((b) => JSON.stringify(b)).join(', ')}. Prefer narrow rules such as "Bash(npm test:*)".`,
        action: { kind: 'review', label: 'Open settings.json', run: open },
      });
    }
    if (s?.skipDangerousModePermissionPrompt === true) {
      out.push({
        id: 'claude:skipprompt', title: 'Bypass-mode warning prompt is suppressed', category: 'claude', severity: 'warning', confidence: 'observed',
        detail: `${settingsFile}: skipDangerousModePermissionPrompt = true.`,
        action: { kind: 'review', label: 'Open settings.json', run: open },
      });
    }
  } catch {
    /* no settings file or not JSON: nothing to report */
  }
  return out;
}

export async function runAudit(context: vscode.ExtensionContext): Promise<Finding[]> {
  const results = await Promise.all([checkRuntime(), checkClaude(), Promise.resolve(checkSettings(context))]);
  const findings = results.flat();
  const rank: Record<Severity, number> = { high: 0, warning: 1, info: 2, ok: 3 };
  return findings.sort((a, b) => rank[a.severity] - rank[b.severity] || a.title.localeCompare(b.title));
}
