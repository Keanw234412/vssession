import * as os from 'node:os';
import * as vscode from 'vscode';
import { isValidId, newId } from '../core/orgStore';

/**
 * Member identity is an opaque id, stored machine-locally (never registered with
 * Settings Sync). To appear as the same member on several machines, export the id on
 * one machine and import it on the others. Device ids are always per machine.
 */
const MEMBER_KEY = 'vssession.memberId';
const DEVICE_KEY = 'vssession.deviceId';

export interface Identity {
  memberId: string;
  deviceId: string;
  displayName: string;
}

export function getIdentity(context: vscode.ExtensionContext): Identity {
  let memberId = context.globalState.get<string>(MEMBER_KEY);
  if (!isValidId(memberId)) {
    memberId = newId();
    void context.globalState.update(MEMBER_KEY, memberId);
  }
  let deviceId = context.globalState.get<string>(DEVICE_KEY);
  if (!isValidId(deviceId)) {
    deviceId = newId();
    void context.globalState.update(DEVICE_KEY, deviceId);
  }
  const configured = vscode.workspace.getConfiguration('vssession').get<string>('member.displayName', '').trim();
  let displayName = configured;
  if (!displayName) {
    try {
      displayName = os.userInfo().username;
    } catch {
      displayName = 'member';
    }
  }
  return { memberId, deviceId, displayName };
}

export function registerIdentityCommands(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('vssession.identity.export', async () => {
      const { memberId } = getIdentity(context);
      await vscode.env.clipboard.writeText(memberId);
      vscode.window.showInformationMessage('Member id copied. Run "VsSession: Import Member Identity" on your other machines to share as the same member.');
    }),
    vscode.commands.registerCommand('vssession.identity.import', async () => {
      const id = (await vscode.window.showInputBox({
        prompt: 'Paste the member id exported from your other machine',
        validateInput: (v) => (isValidId(v.trim()) ? undefined : 'Not a valid member id'),
      }))?.trim();
      if (!id) return;
      await context.globalState.update(MEMBER_KEY, id);
      vscode.window.showInformationMessage('Member identity imported. Sessions shared from now on appear under that member.');
      await vscode.commands.executeCommand('vssession.org.refresh');
    }),
  );
}
