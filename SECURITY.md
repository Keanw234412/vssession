# Security Policy

VsSession moves Claude Code transcripts into folders other people can read, so redaction gaps and path-handling bugs matter.

## Reporting a vulnerability

Please **do not open a public issue** for:
- secrets or personal data that survive redaction,
- ways to write or read outside the organization folder (path traversal, links/junctions),
- shared content that executes code or exfiltrates data in a viewer's VS Code,
- auto-share publishing somewhere the user did not consent to.

Report it privately via **GitHub → Security → Report a vulnerability** (private vulnerability reporting) on this repository. Include a minimal reproduction with **fake** secrets.

You can expect an acknowledgement within a few days. Fixes are released as a patch version with credit, unless you prefer to stay anonymous.

## Scope and known limits (by design)

- Access control is the shared folder's own permissions. Anyone who can read the folder can read the sessions.
- Member display names are self-reported and are not authenticated.
- Redaction is best-effort pattern matching. It reduces accidental disclosure, but it cannot guarantee a transcript is secret-free.
- Copies already synchronized to other machines cannot be recalled.
