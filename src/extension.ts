import * as vscode from 'vscode';
import { registerAudit } from './audit/auditView';
import { registerIdentityCommands } from './org/identity';
import { OrgController } from './org/orgController';

export function activate(context: vscode.ExtensionContext): void {
  registerAudit(context);
  registerIdentityCommands(context);
  new OrgController(context).start();
}

export function deactivate(): void {
  /* disposables are owned by context.subscriptions */
}
