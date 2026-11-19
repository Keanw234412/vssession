# Contributing to VsSession

Thanks for helping! Contributions of any size are welcome.

## Getting started

```bash
git clone https://github.com/Keanw234412/vssession.git
cd vssession
npm install
npm test
```

To run the extension: open the folder in VS Code and press **F5** (Extension Development Host).

## Project layout

| Path | What lives there |
|---|---|
| `src/core/` | Pure logic, with no `vscode` import: fuse reader, redactor, session parser, shared-folder store, consent. **Unit-test everything here.** |
| `src/audit/` | Audit checks and the Audit tree view |
| `src/org/` | Organization tree, publishing, identity, transcript webview |
| `test/` | `node:test` suites (run without VS Code) |

## Good first contributions

- **Redaction rules.** Add a token format to `src/core/redact.ts`. Each rule needs a test with a realistic (fake!) sample in `test/core.test.ts`.
- **Audit checks.** Add a setting rule to `SETTING_RULES` in `src/audit/checks.ts`. Verify the setting name and allowed values against the current VS Code build, and say how you verified it in the PR.
- **Translations.** README translations and, later, `package.nls.*.json`.
- **Docs.** Screenshots and GIFs of the views are very welcome.

## Rules of the road

- Never commit real secrets, tokens, account ids, or personal paths, even in tests. Use obviously fake values.
- Shared-folder content is untrusted input. New fields must be validated in `isValidPublicContent`.
- Keep runtime dependencies at zero unless there is a strong reason.
- `npm test` must pass on Windows, macOS and Linux (CI checks all three).
- One logical change per PR, and describe *why*.

## Commit / PR

- Use conventional-ish messages: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`.
- Fill in the PR template. Link the issue if there is one.

By contributing you agree your work is released under the MIT license and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).
