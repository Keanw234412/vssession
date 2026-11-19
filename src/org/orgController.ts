import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { findProjectDirForCwd, listSessionFiles, longPath, parseRecords, splitCompleteRecords, type LocalSession } from '../core/claudeSessions';
import { OrgStore, OrgStoreError, type DeviceHead, type MemberInfo, type ProjectInfo, type SessionHead } from '../core/orgStore';
import { prepareSession, SourceTooLargeError } from '../core/publish';
import { Redactor } from '../core/redact';
import { getIdentity } from './identity';
import { openTranscriptKeys, refreshOpenTranscript, showTranscript } from './transcriptView';

import { autoConsentValid, CONTENT_SCHEMA, type WorkspaceLink } from '../core/consent';

const LINK_KEY = 'vssession.link';

type Node =
  | { type: 'project'; project: ProjectInfo }
  | { type: 'member'; project: ProjectInfo; member: MemberInfo }
  | { type: 'session'; project: ProjectInfo; member: MemberInfo; head: SessionHead }
  | { type: 'version'; project: ProjectInfo; member: MemberInfo; head: SessionHead; version: DeviceHead; index: number };

function relTime(iso?: string): string {
  if (!iso) return '';
  const d = (Date.now() - Date.parse(iso)) / 1000;
  if (!Number.isFinite(d)) return '';
  if (d < 60) return 'just now';
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

export class OrgController implements vscode.TreeDataProvider<Node>, vscode.Disposable {
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private store: OrgStore | undefined;
  private treeView: vscode.TreeView<Node> | undefined;
  private pollTimer: NodeJS.Timeout | undefined;
  private rootWatcher: fs.FSWatcher | undefined;
  private sessionWatcher: fs.FSWatcher | undefined;
  private refreshDebounce: NodeJS.Timeout | undefined;
  private readonly publishDebounce = new Map<string, NodeJS.Timeout>();
  private readonly autoSkipped = new Set<string>();
  private readonly lastAutoMtime = new Map<string, number>();
  private readonly autoRetry = new Map<string, { attempts: number; nextAt: number }>();
  private autoScanTimer: NodeJS.Timeout | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {}

  // ---------------------------------------------------------------- setup
  start(): void {
    this.treeView = vscode.window.createTreeView('vssession.org', { treeDataProvider: this, showCollapseAll: true });
    const c = this.context;
    const reg = (id: string, fn: (...a: any[]) => unknown) => c.subscriptions.push(vscode.commands.registerCommand(id, fn));
    reg('vssession.org.create', () => this.cmdCreateOrg());
    reg('vssession.org.open', () => this.cmdOpenOrg());
    reg('vssession.org.createProject', () => this.cmdCreateProject());
    reg('vssession.org.linkWorkspace', () => this.cmdLink());
    reg('vssession.org.unlinkWorkspace', () => this.cmdUnlink());
    reg('vssession.org.publishSession', () => this.cmdPublishOne());
    reg('vssession.org.publishAll', () => this.cmdPublishAll());
    reg('vssession.org.unpublishSession', (n: Node) => this.cmdUnpublish(n));
    reg('vssession.org.openSession', (n: Node, pinned?: boolean) => n?.type === 'session' && showTranscript(n.head.latest, n.member.displayName, pinned === true));
    reg('vssession.org.refresh', () => this.reload());
    reg('vssession.org.enableAutoPublish', () => this.cmdEnableAuto());
    reg('vssession.org.disableAutoPublish', () => this.cmdDisableAuto());
    c.subscriptions.push(
      this.treeView,
      this,
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('vssession')) this.reload();
      }),
      vscode.workspace.onDidGrantWorkspaceTrust(() => this.reload()),
    );
    this.reload();
  }

  dispose(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.autoScanTimer) clearInterval(this.autoScanTimer);
    if (this.refreshDebounce) clearTimeout(this.refreshDebounce);
    for (const t of this.publishDebounce.values()) clearTimeout(t);
    this.rootWatcher?.close();
    this.sessionWatcher?.close();
  }

  private rootPath(): string {
    return vscode.workspace.getConfiguration('vssession').get<string>('org.rootPath', '').trim();
  }

  private link(): WorkspaceLink | undefined {
    return this.context.workspaceState.get<WorkspaceLink>(LINK_KEY);
  }

  /**
   * The folder whose sessions are shared. Once linked, this is the exact folder recorded in
   * the link (not "the first folder"), and only while it is still open in this workspace.
   */
  private workspaceDir(): string | undefined {
    const folders = (vscode.workspace.workspaceFolders ?? []).filter((f) => f.uri.scheme === 'file').map((f) => f.uri.fsPath);
    const link = this.link();
    if (link?.sourceDir) return folders.find((f) => path.resolve(f) === path.resolve(link.sourceDir));
    return folders[0];
  }

  private reload(): void {
    const root = this.rootPath();
    this.store = undefined;
    this.rootWatcher?.close();
    this.rootWatcher = undefined;
    if (root) {
      const s = new OrgStore(root);
      const org = s.readOrg();
      if (org) {
        this.store = s;
        if (this.treeView) this.treeView.description = org.name;
        try {
          // Sync clients do not reliably emit events; the watcher is a fast path, polling is the guarantee.
          this.rootWatcher = fs.watch(root, { recursive: true }, (_e, f) => {
            if (f && /(^|[\\/])\.tmp-/.test(String(f))) return;
            this.scheduleRefresh();
          });
          this.rootWatcher.on('error', () => undefined);
        } catch {
          /* recursive watch unsupported: polling only */
        }
      } else if (this.treeView) {
        this.treeView.description = 'organization folder unavailable';
      }
    }
    const link = this.link();
    void vscode.commands.executeCommand('setContext', 'vssession.orgConfigured', !!root);
    void vscode.commands.executeCommand('setContext', 'vssession.workspaceLinked', !!link && !!this.store && link.orgId === this.store.readOrg()?.orgId);
    if (this.treeView) {
      this.treeView.message = link && this.store
        ? `This workspace → ${link.projectName}${link.auto ? ' (auto-share on)' : ''}`
        : root && !this.store ? `No valid organization at ${root} (not synced yet, or moved).` : undefined;
    }

    if (this.pollTimer) clearInterval(this.pollTimer);
    const secs = Math.max(5, vscode.workspace.getConfiguration('vssession').get<number>('org.pollIntervalSeconds', 15));
    this.pollTimer = setInterval(() => {
      // An organization that was offline at startup (share down, not yet synced) recovers by itself.
      if (!this.store && this.rootPath() && new OrgStore(this.rootPath()).readOrg()) this.reload();
      else this.refreshView();
    }, secs * 1000);
    this.setupAutoPublish();
    this.refreshView();
  }

  private scheduleRefresh(): void {
    if (this.refreshDebounce) clearTimeout(this.refreshDebounce);
    this.refreshDebounce = setTimeout(() => this.refreshView(), 1000);
  }

  private refreshView(): void {
    this.emitter.fire(undefined);
    // Live-follow open transcripts.
    if (!this.store) return;
    for (const key of openTranscriptKeys()) {
      const [projectId, memberId, sessionId] = key.split('/');
      try {
        const head = this.store.listSessions(projectId, memberId).find((h) => h.sessionId === sessionId);
        const member = this.store.listMembers(projectId).find((m) => m.memberId === memberId);
        if (head) refreshOpenTranscript(head.latest, member?.displayName ?? memberId.slice(0, 8));
      } catch {
        /* folder temporarily unavailable */
      }
    }
  }

  // ---------------------------------------------------------------- tree
  getTreeItem(n: Node): vscode.TreeItem {
    const me = getIdentity(this.context);
    const link = this.link();
    if (n.type === 'project') {
      const item = new vscode.TreeItem(n.project.name, vscode.TreeItemCollapsibleState.Collapsed);
      item.iconPath = new vscode.ThemeIcon('project');
      item.description = link?.projectId === n.project.projectId ? 'linked to this workspace' : undefined;
      item.contextValue = 'project';
      item.id = `p:${n.project.projectId}`;
      return item;
    }
    if (n.type === 'member') {
      const mine = n.member.memberId === me.memberId;
      const item = new vscode.TreeItem(n.member.displayName, vscode.TreeItemCollapsibleState.Collapsed);
      item.iconPath = new vscode.ThemeIcon(mine ? 'account' : 'person');
      item.description = mine ? 'you' : undefined;
      item.tooltip = `Member ${n.member.memberId}\nName is self-reported by the member.`;
      item.contextValue = mine ? 'member-mine' : 'member';
      item.id = `m:${n.project.projectId}/${n.member.memberId}`;
      return item;
    }
    if (n.type === 'version') {
      const v = n.version.rev;
      const item = new vscode.TreeItem(`Version ${n.index + 1}: ${v.summary.title}`, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon('git-compare');
      item.description = `device ${n.version.deviceId.slice(0, 6)} · ${v.summary.userTurns} prompts`;
      item.tooltip = 'Published from different devices without seeing each other (offline). Sharing the session again from either device resolves it.';
      item.command = { command: 'vssession.org.openSession', title: 'Open', arguments: [{ ...n, type: 'session', head: { ...n.head, latest: v } }, true] };
      item.id = `v:${n.project.projectId}/${n.member.memberId}/${n.head.sessionId}/${n.version.deviceId}`;
      return item;
    }
    const h = n.head;
    const s = h.latest.summary;
    const mine = n.member.memberId === me.memberId;
    const conflict = h.competing.length > 1;
    const item = new vscode.TreeItem(s.title || h.sessionId, conflict ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None);
    item.iconPath = new vscode.ThemeIcon(conflict ? 'warning' : 'comment-discussion');
    item.description = [relTime(typeof s.lastTs === 'string' ? s.lastTs : h.latest.publishedAt), conflict ? `${h.competing.length} conflicting versions` : h.deviceHeads > 1 ? `${h.deviceHeads} devices` : ''].filter(Boolean).join(' · ');
    item.tooltip = new vscode.MarkdownString().appendText(
      `${s.title}\n\n${s.userTurns} prompts · ${s.assistantTurns} replies · ${s.toolCalls} tool calls${s.gitBranch ? `\nBranch: ${s.gitBranch}` : ''}\n` +
        `Revision ${h.latest.seq}, published ${h.latest.publishedAt}\n` +
        (mine ? 'Published locally to the shared folder. Delivery to other members depends on your sync client.' : `Shared by ${n.member.displayName} (self-reported)`),
    );
    item.contextValue = mine ? 'session-mine' : 'session';
    item.id = `s:${n.project.projectId}/${n.member.memberId}/${h.sessionId}`;
    item.command = { command: 'vssession.org.openSession', title: 'Open', arguments: [n] };
    return item;
  }

  getChildren(n?: Node): Node[] {
    const store = this.store;
    if (!store) return [];
    try {
      if (!n) return store.listProjects().map((project) => ({ type: 'project' as const, project }));
      if (n.type === 'project') return store.listMembers(n.project.projectId).map((member) => ({ type: 'member' as const, project: n.project, member }));
      if (n.type === 'member') {
        return store.listSessions(n.project.projectId, n.member.memberId).map((head) => ({ type: 'session' as const, project: n.project, member: n.member, head }));
      }
      if (n.type === 'session' && n.head.competing.length > 1) {
        return n.head.competing.map((version, index) => ({ type: 'version' as const, project: n.project, member: n.member, head: n.head, version, index }));
      }
    } catch {
      /* folder disappeared mid-read; next poll retries */
    }
    return [];
  }

  // ---------------------------------------------------------------- guards
  private guard(needLink: boolean): { store: OrgStore; link?: WorkspaceLink } | undefined {
    if (vscode.env.remoteName) {
      vscode.window.showWarningMessage('VsSession organization sharing supports local workspaces only (Claude sessions of remote workspaces live on the remote host).');
      return undefined;
    }
    if (!vscode.workspace.isTrusted) {
      vscode.window.showWarningMessage('Trust this workspace before linking or sharing Claude sessions.');
      return undefined;
    }
    if (!this.store) {
      vscode.window.showWarningMessage('Configure an organization folder first.');
      return undefined;
    }
    if (!needLink) return { store: this.store };
    const link = this.link();
    if (!link) {
      vscode.window.showWarningMessage('Link this workspace to an organization project first.');
      return undefined;
    }
    const dest = this.validDestination();
    if (!dest) {
      vscode.window.showErrorMessage('The linked organization project is not available at the configured folder (moved, not synced, or a different organization). Re-link the workspace.');
      return undefined;
    }
    return dest;
  }

  /**
   * Re-read the configured root from settings and verify it is the exact organization and
   * project the workspace was linked to. Used before every publication, manual or automatic.
   */
  private validDestination(): { store: OrgStore; link: WorkspaceLink } | undefined {
    const link = this.link();
    const root = this.rootPath();
    if (!link || !root || !this.store) return undefined;
    if (path.resolve(this.store.root) !== path.resolve(root) || path.resolve(root) !== path.resolve(link.root)) return undefined;
    const org = this.store.readOrg();
    if (!org || org.orgId !== link.orgId || !this.store.getProject(link.projectId)) return undefined;
    return { store: this.store, link };
  }

  private redactor(): Redactor {
    const cfg = vscode.workspace.getConfiguration('vssession');
    let userName: string | undefined;
    try {
      userName = os.userInfo().username;
    } catch {
      /* ignore */
    }
    return new Redactor({
      homeDir: os.homedir(),
      userName,
      redactEmails: cfg.get<boolean>('publish.redactEmails', true),
      extraPatterns: cfg.get<string[]>('publish.extraRedactPatterns', []),
    });
  }

  private localSessions(): LocalSession[] {
    const ws = this.workspaceDir();
    if (!ws) return [];
    const dir = findProjectDirForCwd(ws);
    return dir ? listSessionFiles(dir) : [];
  }

  private quickTitle(file: string): string {
    try {
      const fd = fs.openSync(longPath(file), 'r');
      const buf = Buffer.alloc(128 * 1024);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      fs.closeSync(fd);
      const { summary } = parseRecords(splitCompleteRecords(buf.subarray(0, n).toString('utf8')).records);
      return this.redactor().redact(summary.title || path.basename(file, '.jsonl'));
    } catch {
      return path.basename(file, '.jsonl');
    }
  }

  // ---------------------------------------------------------------- commands
  private async cmdCreateOrg(): Promise<void> {
    const pick = await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, openLabel: 'Use as organization folder', title: 'Pick a folder that is shared with all members (OneDrive/SharePoint, network share, git repo)' });
    if (!pick?.[0]) return;
    const name = await vscode.window.showInputBox({ prompt: 'Organization name', validateInput: (v) => (v.trim() ? undefined : 'Required') });
    if (!name) return;
    try {
      OrgStore.create(pick[0].fsPath, name);
      await vscode.workspace.getConfiguration('vssession').update('org.rootPath', pick[0].fsPath, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(`Organization "${name}" created. Share this folder with every member; access to the folder is the access control.`);
    } catch (e) {
      vscode.window.showErrorMessage(e instanceof Error ? e.message : String(e));
    }
  }

  private async cmdOpenOrg(): Promise<void> {
    const pick = await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, openLabel: 'Open organization folder' });
    if (!pick?.[0]) return;
    const org = new OrgStore(pick[0].fsPath).readOrg();
    if (!org) {
      vscode.window.showErrorMessage('That folder has no valid org.json (if it is a cloud folder, make sure it is fully synced / "Always keep on this device").');
      return;
    }
    await vscode.workspace.getConfiguration('vssession').update('org.rootPath', pick[0].fsPath, vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage(`Joined organization "${org.name}".`);
  }

  private async cmdCreateProject(): Promise<ProjectInfo | undefined> {
    const g = this.guard(false);
    if (!g) return undefined;
    const name = await vscode.window.showInputBox({ prompt: 'Project name', validateInput: (v) => (v.trim() ? undefined : 'Required') });
    if (!name) return undefined;
    const p = g.store.createProject(name);
    this.refreshView();
    return p;
  }

  private async cmdLink(): Promise<void> {
    const g = this.guard(false);
    if (!g) return;
    const ws = this.workspaceDir();
    if (!ws) {
      vscode.window.showWarningMessage('Open a local folder first.');
      return;
    }
    const projects = g.store.listProjects();
    const NEW = '$(add) New project…';
    const pick = await vscode.window.showQuickPick([...projects.map((p) => ({ label: p.name, project: p })), { label: NEW, project: undefined as ProjectInfo | undefined }], { placeHolder: `Link ${path.basename(ws)} to…` });
    if (!pick) return;
    const project = pick.project ?? (await this.cmdCreateProject());
    if (!project) return;
    const org = g.store.requireOrg();
    const link: WorkspaceLink = { sourceDir: ws, root: g.store.root, orgId: org.orgId, projectId: project.projectId, projectName: project.name, linkedAt: new Date().toISOString() };
    await this.context.workspaceState.update(LINK_KEY, link);
    const me = getIdentity(this.context);
    g.store.upsertMember(project.projectId, me.memberId, me.displayName);
    this.reload();
    const next = await vscode.window.showInformationMessage(`Linked to "${project.name}". Nothing is shared until you share a session or enable auto-share.`, 'Share a session', 'Enable auto-share…');
    if (next === 'Share a session') await this.cmdPublishOne();
    if (next === 'Enable auto-share…') await this.cmdEnableAuto();
  }

  private async cmdUnlink(): Promise<void> {
    await this.context.workspaceState.update(LINK_KEY, undefined);
    this.reload();
    vscode.window.showInformationMessage('Workspace unlinked. Already shared sessions stay in the organization folder until you remove them.');
  }

  /**
   * Re-validate immediately before writing: settings or the link may have changed while a
   * confirmation dialog was open. The destination must be exactly the one the user approved.
   */
  private destinationAtWrite(approved: { store: OrgStore; link?: WorkspaceLink }): { store: OrgStore; link: WorkspaceLink } {
    const now = this.validDestination();
    const a = approved.link;
    if (!now || !a || path.resolve(now.store.root) !== path.resolve(approved.store.root) || now.link.orgId !== a.orgId || now.link.projectId !== a.projectId || now.link.sourceDir !== a.sourceDir) {
      throw new OrgStoreError('The destination changed while confirming; nothing was shared. Try again.');
    }
    return now;
  }

  private async publishFile(g: { store: OrgStore; link?: WorkspaceLink }, s: LocalSession, mode: 'manual' | 'auto'): Promise<'published' | 'unchanged' | 'skipped' | 'cancelled'> {
    const link = g.link!;
    const ws = this.workspaceDir();
    if (!ws) throw new OrgStoreError('The linked workspace folder is no longer open in this window.');
    const prepared = prepareSession(s.file, ws, this.redactor());
    if (mode === 'auto' && !prepared.eligibility.autoOk) {
      if (!this.autoSkipped.has(s.sessionId)) {
        this.autoSkipped.add(s.sessionId);
        vscode.window.showWarningMessage(`Not auto-shared: "${prepared.summary.title.slice(0, 60)}" — ${prepared.eligibility.reasons.join(' ')} Share it manually to review.`);
      }
      return 'skipped';
    }
    if (mode === 'manual') {
      const e = prepared.eligibility;
      const lines = [
        `Destination: ${link.projectName} (${g.store.root})`,
        `Visible to: everyone with access to that folder`,
        `Content: ${prepared.summary.userTurns} prompts, ${prepared.summary.assistantTurns} replies, ${prepared.summary.toolCalls} tool calls with clipped inputs/results. Thinking blocks and account ids are not shared.`,
        'Redaction applied (best effort — review sensitive sessions before sharing).',
      ];
      if (e.reasons.length) lines.push('', '⚠ ' + e.reasons.join('\n⚠ '));
      if (e.foreignCwds.length) lines.push(`Other folders: ${e.foreignCwds.slice(0, 5).join(', ')}`);
      if (e.droppedTail) lines.push('The last record is still being written and is not included yet.');
      const ok = await vscode.window.showWarningMessage(`Share "${prepared.summary.title.slice(0, 80)}"?`, { modal: true, detail: lines.join('\n') }, 'Share');
      if (ok !== 'Share') return 'cancelled';
    }
    const dest = this.destinationAtWrite(g);
    const me = getIdentity(this.context);
    dest.store.upsertMember(dest.link.projectId, me.memberId, me.displayName);
    const r = dest.store.publish({ projectId: dest.link.projectId, memberId: me.memberId, deviceId: me.deviceId, sessionId: prepared.sessionId, summary: prepared.summary, items: prepared.items });
    return r.unchanged ? 'unchanged' : 'published';
  }

  private async cmdPublishOne(): Promise<void> {
    const g = this.guard(true);
    if (!g) return;
    const sessions = this.localSessions();
    if (!sessions.length) {
      vscode.window.showInformationMessage('No Claude Code sessions found for this workspace.');
      return;
    }
    const pick = await vscode.window.showQuickPick(
      sessions.slice(0, 200).map((s) => ({ label: this.quickTitle(s.file), description: `${new Date(s.mtimeMs).toLocaleString()} · ${(s.size / 1024).toFixed(0)} KB`, s })),
      { placeHolder: 'Pick a Claude session to share' },
    );
    if (!pick) return;
    try {
      const r = await this.publishFile(g, pick.s, 'manual');
      if (r === 'published') vscode.window.showInformationMessage('Session published locally to the organization folder. Other members see it once your sync client uploads it.');
      if (r === 'unchanged') vscode.window.showInformationMessage('Already up to date.');
    } catch (e) {
      vscode.window.showErrorMessage(e instanceof SourceTooLargeError || e instanceof OrgStoreError ? e.message : `Share failed: ${String(e)}`);
    }
    this.refreshView();
  }

  private async cmdPublishAll(): Promise<void> {
    const g = this.guard(true);
    if (!g) return;
    const sessions = this.localSessions();
    if (!sessions.length) {
      vscode.window.showInformationMessage('No Claude Code sessions found for this workspace.');
      return;
    }
    const ok = await vscode.window.showWarningMessage(
      `Share ${sessions.length} session(s) to "${g.link!.projectName}"?`,
      { modal: true, detail: 'Only sessions that ran entirely inside this workspace are shared; others are skipped and can be shared individually after review. Redaction applied (best effort).' },
      'Share',
    );
    if (ok !== 'Share') return;
    const tally = { published: 0, unchanged: 0, skipped: 0, failed: 0 };
    const ws = this.workspaceDir();
    if (!ws) return;
    for (const s of sessions) {
      try {
        const prepared = prepareSession(s.file, ws, this.redactor());
        if (!prepared.eligibility.autoOk) {
          tally.skipped++;
          continue;
        }
        const dest = this.destinationAtWrite(g); // stops the batch if the destination changed mid-way
        const me = getIdentity(this.context);
        dest.store.upsertMember(dest.link.projectId, me.memberId, me.displayName);
        const r = dest.store.publish({ projectId: dest.link.projectId, memberId: me.memberId, deviceId: me.deviceId, sessionId: prepared.sessionId, summary: prepared.summary, items: prepared.items });
        tally[r.unchanged ? 'unchanged' : 'published']++;
      } catch (e) {
        if (e instanceof OrgStoreError && /destination changed/.test(e.message)) {
          vscode.window.showErrorMessage(e.message);
          break;
        }
        tally.failed++;
      }
    }
    this.refreshView();
    vscode.window.showInformationMessage(`Shared ${tally.published}, unchanged ${tally.unchanged}, skipped ${tally.skipped} (needs review), failed ${tally.failed}.`);
  }

  private async cmdUnpublish(n: Node): Promise<void> {
    if (n?.type !== 'session') return;
    const g = this.guard(false);
    if (!g) return;
    const me = getIdentity(this.context);
    if (n.member.memberId !== me.memberId) return;
    const ok = await vscode.window.showWarningMessage(
      `Remove "${n.head.latest.summary.title.slice(0, 60)}" from the organization?`,
      { modal: true, detail: 'Removes the copy published from this device. Copies already synced to other machines, or published from your other devices, cannot be recalled by VsSession.' },
      'Remove',
    );
    if (ok !== 'Remove') return;
    g.store.unpublish(n.project.projectId, me.memberId, me.deviceId, n.head.sessionId);
    this.refreshView();
  }

  // ---------------------------------------------------------------- auto-share
  private async cmdEnableAuto(): Promise<void> {
    const g = this.guard(true);
    if (!g) return;
    const ok = await vscode.window.showWarningMessage(
      `Automatically share future Claude sessions of this workspace with "${g.link!.projectName}"?`,
      {
        modal: true,
        detail:
          `Destination: ${g.store.root}\nVisible to: everyone with access to that folder.\n` +
          'Shared content: your prompts, Claude replies, tool names with clipped inputs and outputs (file contents, command output). Thinking blocks and account ids are excluded.\n' +
          'Redaction applied (best effort). Sessions that also ran outside this workspace are never auto-shared.\n' +
          'Changing the destination or the shared content types turns auto-share off until you agree again.',
      },
      'Enable auto-share',
    );
    if (ok !== 'Enable auto-share') return;
    const link = g.link!;
    link.auto = { sourceDir: link.sourceDir, root: link.root, orgId: link.orgId, projectId: link.projectId, contentSchema: CONTENT_SCHEMA, consentAt: new Date().toISOString() };
    await this.context.workspaceState.update(LINK_KEY, link);
    this.reload();
  }

  private async cmdDisableAuto(): Promise<void> {
    const link = this.link();
    if (!link) return;
    delete link.auto;
    await this.context.workspaceState.update(LINK_KEY, link);
    this.reload();
    vscode.window.showInformationMessage('Auto-share disabled.');
  }

  private setupAutoPublish(): void {
    this.sessionWatcher?.close();
    this.sessionWatcher = undefined;
    if (this.autoScanTimer) clearInterval(this.autoScanTimer);
    this.autoScanTimer = undefined;
    // Queued publications were validated against the previous configuration: drop them.
    for (const t of this.publishDebounce.values()) clearTimeout(t);
    this.publishDebounce.clear();
    const link = this.link();
    if (!link?.auto) return;
    if (!autoConsentValid(link)) {
      delete link.auto;
      void this.context.workspaceState.update(LINK_KEY, link);
      vscode.window.showWarningMessage('Auto-share was turned off because the destination or shared content changed. Enable it again to continue.');
      return;
    }
    if (!this.store || !vscode.workspace.isTrusted || vscode.env.remoteName) return;
    const ws = this.workspaceDir();
    if (!ws) return;
    const consentAt = Date.parse(link.auto.consentAt);
    let watchedDir: string | undefined;
    const scan = () => {
      // The session directory may not exist until the first Claude session in this workspace.
      const dir = findProjectDirForCwd(ws);
      if (!dir) return;
      if (watchedDir !== dir) {
        watchedDir = dir;
        this.sessionWatcher?.close();
        try {
          this.sessionWatcher = fs.watch(longPath(dir), () => scan());
          this.sessionWatcher.on('error', () => undefined);
        } catch {
          /* polling only */
        }
      }
      const now = Date.now();
      for (const s of listSessionFiles(dir)) {
        if (s.mtimeMs < consentAt) continue;
        if (this.lastAutoMtime.get(s.sessionId) === s.mtimeMs) continue;
        const retry = this.autoRetry.get(s.sessionId);
        if (retry && retry.nextAt > now) continue;
        this.queueAuto(s);
      }
    };
    this.autoScanTimer = setInterval(scan, 30_000);
    scan();
  }

  private queueAuto(s: LocalSession): void {
    const prev = this.publishDebounce.get(s.sessionId);
    if (prev) clearTimeout(prev);
    // Claude appends continuously while working; wait for a quiet period.
    this.publishDebounce.set(
      s.sessionId,
      setTimeout(async () => {
        this.publishDebounce.delete(s.sessionId);
        if (!vscode.workspace.isTrusted || !autoConsentValid(this.link())) return;
        // Re-validate the real destination right before writing (settings may have changed).
        const dest = this.validDestination();
        if (!dest) {
          vscode.window.setStatusBarMessage('VsSession: auto-share paused — linked organization folder unavailable', 10000);
          return;
        }
        const fresh = listSessionFiles(path.dirname(s.file)).find((x) => x.sessionId === s.sessionId);
        if (!fresh) return;
        try {
          await this.publishFile(dest, fresh, 'auto');
          this.lastAutoMtime.set(s.sessionId, fresh.mtimeMs);
          this.autoRetry.delete(s.sessionId);
          this.scheduleRefresh();
        } catch (e) {
          if (e instanceof SourceTooLargeError) {
            this.lastAutoMtime.set(s.sessionId, fresh.mtimeMs); // permanent until the file changes
          } else {
            // Transient (share offline, sync lock): retry with exponential backoff, max 30 min.
            const attempts = (this.autoRetry.get(s.sessionId)?.attempts ?? 0) + 1;
            this.autoRetry.set(s.sessionId, { attempts, nextAt: Date.now() + Math.min(30 * 60_000, 30_000 * 2 ** attempts) });
          }
          vscode.window.setStatusBarMessage(`VsSession: auto-share failed (${e instanceof Error ? e.message : String(e)})`, 10000);
        }
      }, 15_000),
    );
  }
}
