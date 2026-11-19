import * as crypto from 'node:crypto';
import * as vscode from 'vscode';
import type { SessionRevision } from '../core/orgStore';

export const MAX_RENDERED_ITEMS = 1500;
const MAX_ITEM_CHARS = 20000;

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

function text(s: unknown): string {
  const str = typeof s === 'string' ? s : JSON.stringify(s ?? '');
  return escapeHtml(str.length > MAX_ITEM_CHARS ? `${str.slice(0, MAX_ITEM_CHARS)}\n… [truncated for display]` : str);
}

/**
 * Shared transcripts are untrusted input from other members' machines:
 * no scripts, no remote resources, every string rendered as text.
 */
export function renderTranscriptHtml(rev: SessionRevision, ownerName: string, nonce: string): string {
  const s = rev.summary;
  const items = Array.isArray(rev.items) ? rev.items : [];
  const shown = items.slice(0, MAX_RENDERED_ITEMS);
  const rows = shown
    .map((it) => {
      switch (it.kind) {
        case 'user':
          return `<section class="msg user"><div class="who">${text(ownerName)}</div><pre>${text(it.text)}</pre></section>`;
        case 'assistant':
          return `<section class="msg assistant"><div class="who">Claude${it.model ? ` · ${text(it.model)}` : ''}</div><pre>${text(it.text)}</pre></section>`;
        case 'tool_use':
          return `<details class="tool"><summary>Tool: ${text(it.name)}</summary><pre>${text(it.input)}</pre></details>`;
        case 'tool_result':
          return `<details class="tool${it.isError ? ' err' : ''}"><summary>${it.isError ? 'Tool error' : 'Tool result'}</summary><pre>${text(it.text)}</pre></details>`;
        default:
          return '';
      }
    })
    .join('\n');
  const more = items.length > shown.length ? `<p class="note">${items.length - shown.length} more item(s) not displayed.</p>` : '';
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="${nonce}">
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); background: var(--vscode-editor-background); padding: 0 16px 32px; max-width: 980px; margin: 0 auto; }
  header { border-bottom: 1px solid var(--vscode-panel-border); padding: 12px 0; margin-bottom: 12px; }
  h1 { font-size: 1.25em; margin: 0 0 4px; }
  .meta { opacity: .8; font-size: .9em; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); font-size: .8em; margin-right: 6px; }
  .msg { margin: 12px 0; padding: 8px 12px; border-radius: 6px; }
  .user { background: var(--vscode-textBlockQuote-background); border-left: 3px solid var(--vscode-textLink-foreground); }
  .assistant { border-left: 3px solid var(--vscode-charts-purple, #a371f7); }
  .who { font-weight: 600; font-size: .85em; opacity: .85; margin-bottom: 4px; }
  pre { white-space: pre-wrap; word-break: break-word; font-family: var(--vscode-editor-font-family); font-size: var(--vscode-editor-font-size); margin: 0; }
  details.tool { margin: 4px 0 4px 16px; font-size: .9em; opacity: .9; }
  details.tool summary { cursor: pointer; }
  details.tool pre { padding: 6px; background: var(--vscode-textCodeBlock-background); max-height: 400px; overflow: auto; }
  details.err summary { color: var(--vscode-errorForeground); }
  .note { opacity: .7; font-style: italic; }
</style><title>${text(s.title)}</title></head>
<body>
<header>
  <h1>${text(s.title)}</h1>
  <div class="meta">
    <span class="badge">shared by ${text(ownerName)} (self-reported)</span>
    <span class="badge">redaction applied</span>
    ${s.gitBranch ? `<span class="badge">branch ${text(s.gitBranch)}</span>` : ''}
    revision ${text(String(rev.seq))} · published ${text(rev.publishedAt)} · ${text(String(s.userTurns))} prompts · ${text(String(s.toolCalls))} tool calls
  </div>
</header>
${rows || '<p class="note">This session has no displayable messages.</p>'}
${more}
</body></html>`;
}

const panels = new Map<string, vscode.WebviewPanel>();

/**
 * Live views follow the newest version of a session; pinned views (a specific conflicting
 * version the user picked) never change underneath the user.
 */
export function showTranscript(rev: SessionRevision, ownerName: string, pinned = false): void {
  const key = `${rev.projectId}/${rev.memberId}/${rev.sessionId}${pinned ? `#${rev.revId}` : ''}`;
  let panel = panels.get(key);
  if (!panel) {
    panel = vscode.window.createWebviewPanel('vssession.transcript', rev.summary.title.slice(0, 60) || 'Session', vscode.ViewColumn.Active, {
      enableScripts: false,
      enableCommandUris: false,
      localResourceRoots: [],
    });
    panels.set(key, panel);
    panel.onDidDispose(() => panels.delete(key));
  } else {
    panel.reveal();
  }
  panel.title = `${pinned ? '📌 ' : ''}${rev.summary.title.slice(0, 60) || 'Session'}`;
  panel.webview.html = renderTranscriptHtml(rev, ownerName, crypto.randomBytes(16).toString('base64'));
}

/** Keys (project/member/session) of live-following transcripts currently open. */
export function openTranscriptKeys(): string[] {
  return [...panels.keys()].filter((k) => !k.includes('#'));
}

/** Update an open transcript when a newer revision arrives (live follow). */
export function refreshOpenTranscript(rev: SessionRevision, ownerName: string): void {
  const panel = panels.get(`${rev.projectId}/${rev.memberId}/${rev.sessionId}`);
  if (panel) panel.webview.html = renderTranscriptHtml(rev, ownerName, crypto.randomBytes(16).toString('base64'));
}
