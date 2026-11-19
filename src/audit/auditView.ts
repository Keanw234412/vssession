import * as vscode from 'vscode';
import { runAudit, undoLastFix, type Category, type Finding } from './checks';

const CATEGORY_LABEL: Record<Category, string> = {
  security: 'Security',
  claude: 'Claude Code',
  maintenance: 'Maintenance',
  privacy: 'Privacy preferences',
  inventory: 'Installed components',
};
const ORDER: Category[] = ['security', 'claude', 'maintenance', 'privacy', 'inventory'];

type Node = { type: 'category'; category: Category; findings: Finding[] } | { type: 'finding'; finding: Finding };

const ICON: Record<Finding['severity'], vscode.ThemeIcon> = {
  high: new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
  warning: new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground')),
  info: new vscode.ThemeIcon('info'),
  ok: new vscode.ThemeIcon('pass'),
};

export class AuditProvider implements vscode.TreeDataProvider<Node> {
  private findings: Finding[] | undefined;
  private running = false;
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly context: vscode.ExtensionContext) {}

  async run(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      this.findings = await vscode.window.withProgress(
        { location: { viewId: 'vssession.audit' }, title: 'Auditing VS Code…' },
        () => runAudit(this.context),
      );
      this.emitter.fire(undefined);
      const high = this.findings.filter((f) => f.severity === 'high').length;
      const warn = this.findings.filter((f) => f.severity === 'warning').length;
      vscode.window.setStatusBarMessage(`VsSession audit: ${high} high, ${warn} warning`, 8000);
    } finally {
      this.running = false;
    }
  }

  getTreeItem(n: Node): vscode.TreeItem {
    if (n.type === 'category') {
      const item = new vscode.TreeItem(`${CATEGORY_LABEL[n.category]} (${n.findings.length})`, vscode.TreeItemCollapsibleState.Expanded);
      item.contextValue = 'category';
      return item;
    }
    const f = n.finding;
    const item = new vscode.TreeItem(f.title, vscode.TreeItemCollapsibleState.None);
    item.iconPath = ICON[f.severity];
    item.description = f.action ? (f.action.kind === 'fix' ? 'fixable' : f.action.kind) : undefined;
    item.tooltip = new vscode.MarkdownString().appendText(`${f.detail}\n\nConfidence: ${f.confidence}${f.evidence ? `\nEvidence: ${f.evidence}` : ''}`);
    item.contextValue = f.action?.kind === 'fix' && f.action.run ? 'finding-fixable' : 'finding';
    item.command = { command: 'vssession.audit.details', title: 'Details', arguments: [n] };
    return item;
  }

  getChildren(n?: Node): Node[] {
    if (!this.findings) return [];
    if (!n) {
      return ORDER.map((c) => ({ type: 'category' as const, category: c, findings: this.findings!.filter((f) => f.category === c) })).filter((g) => g.findings.length);
    }
    return n.type === 'category' ? n.findings.map((finding) => ({ type: 'finding' as const, finding })) : [];
  }

  async applyFix(f: Finding): Promise<void> {
    if (!f.action?.run) return;
    try {
      const msg = await f.action.run();
      if (f.action.undoable) {
        vscode.window.showInformationMessage(msg, 'Undo').then(async (pick) => {
          if (pick) vscode.window.showInformationMessage(await undoLastFix(this.context));
        });
      } else {
        vscode.window.showInformationMessage(msg);
      }
    } catch (e) {
      vscode.window.showErrorMessage(`Fix failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    await this.run();
  }

  async details(f: Finding): Promise<void> {
    const actionLabel = f.action?.run ? f.action.label : undefined;
    const detail = `${f.detail}\n\nCategory: ${CATEGORY_LABEL[f.category]} · Severity: ${f.severity} · Confidence: ${f.confidence}${f.evidence ? `\nEvidence: ${f.evidence}` : ''}${f.action && !f.action.run ? `\n\n${f.action.label}` : ''}`;
    const pick = await vscode.window.showInformationMessage(f.title, { modal: true, detail }, ...(actionLabel ? [actionLabel] : []));
    if (pick && pick === actionLabel) await this.applyFix(f);
  }

  async fixAll(): Promise<void> {
    if (!this.findings) await this.run();
    const safe = (this.findings ?? []).filter(
      (f) => (f.category === 'security' || f.category === 'claude') && f.action?.kind === 'fix' && f.action.safe && f.action.run,
    );
    if (!safe.length) {
      vscode.window.showInformationMessage('No safe automatic fixes available.');
      return;
    }
    const ok = await vscode.window.showWarningMessage(
      `Apply ${safe.length} fix(es)?`,
      { modal: true, detail: safe.map((f) => `• ${f.action!.label}`).join('\n') + '\n\nPrivacy and maintenance preferences are not included.' },
      'Apply',
    );
    if (ok !== 'Apply') return;
    const results: string[] = [];
    for (const f of safe) {
      try {
        results.push(`✓ ${await f.action!.run!()}`);
      } catch (e) {
        results.push(`✗ ${f.title}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    await this.run();
    vscode.window.showInformationMessage('Fixes applied', { modal: true, detail: results.join('\n') });
  }
}

export function registerAudit(context: vscode.ExtensionContext): AuditProvider {
  const provider = new AuditProvider(context);
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('vssession.audit', provider),
    vscode.commands.registerCommand('vssession.audit.run', () => provider.run()),
    vscode.commands.registerCommand('vssession.audit.fixAll', () => provider.fixAll()),
    vscode.commands.registerCommand('vssession.audit.fix', (n: Node) => n?.type === 'finding' && provider.applyFix(n.finding)),
    vscode.commands.registerCommand('vssession.audit.details', (n: Node) => n?.type === 'finding' && provider.details(n.finding)),
    vscode.commands.registerCommand('vssession.audit.undo', async () => vscode.window.showInformationMessage(await undoLastFix(context))),
  );
  return provider;
}
