/**
 * Best-effort secret redaction applied to every string that leaves the machine.
 * This reduces accidental disclosure; it cannot prove a transcript is secret-free.
 */

export interface RedactOptions {
  homeDir?: string;
  userName?: string;
  redactEmails?: boolean;
  /** Phone numbers and WhatsApp ids (default true). */
  redactPhones?: boolean;
  extraPatterns?: string[];
  /** Exact values known to be private (e.g. account/organization UUIDs of the session owner). */
  literals?: string[];
}

export interface PemState {
  inPem: boolean;
}

/** Object keys whose (scalar) values are secrets regardless of what the value looks like. */
export const SECRET_KEY_RE = /(^|[_\-.])?(pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|auth(orization)?|cookie|bearer)([_\-.]|$)/i;

interface Rule {
  re: RegExp;
  replace: string | ((m: string, ...g: string[]) => string);
}

const BUILTIN_RULES: Rule[] = [
  // PEM / OpenSSH private keys (multiline). Also catches a block truncated without END.
  { re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, replace: '[redacted:private-key]' },
  // Anthropic / OpenAI style keys
  { re: /\bsk-ant-[A-Za-z0-9_\-]{10,}/g, replace: '[redacted:anthropic-key]' },
  { re: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}/g, replace: '[redacted:api-key]' },
  // GitHub tokens
  { re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/g, replace: '[redacted:github-token]' },
  // GitLab, Slack, Stripe, Google, npm, Hugging Face, Vercel
  { re: /\bglpat-[A-Za-z0-9_\-]{20,}/g, replace: '[redacted:gitlab-token]' },
  { re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, replace: '[redacted:slack-token]' },
  { re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}/g, replace: '[redacted:stripe-key]' },
  { re: /\bAIza[0-9A-Za-z_\-]{35}/g, replace: '[redacted:google-key]' },
  { re: /\bnpm_[A-Za-z0-9]{36}/g, replace: '[redacted:npm-token]' },
  { re: /\bhf_[A-Za-z0-9]{30,}/g, replace: '[redacted:hf-token]' },
  // AWS access key id + secret
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: '[redacted:aws-key-id]' },
  { re: /(aws_secret_access_key\s*[=:]\s*)["']?[A-Za-z0-9/+=]{40}["']?/gi, replace: (_m, p) => `${p}[redacted]` },
  // JWTs
  { re: /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}/g, replace: '[redacted:jwt]' },
  // Bearer / Basic auth headers
  { re: /(\b(?:Authorization|Proxy-Authorization)\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+)[A-Za-z0-9._~+/=\-]{8,}/gi, replace: (_m, p) => `${p}[redacted]` },
  // Credentials embedded in URLs: scheme://user:pass@host
  { re: /\b([a-z][a-z0-9+.\-]*:\/\/[^\s:/@]+:)[^\s@/]+@/gi, replace: (_m, p) => `${p}[redacted]@` },
  // Tail of a private key whose BEGIN line ended up in another string/record.
  { re: /^[A-Za-z0-9+/=\s]*-----END [A-Z0-9 ]*PRIVATE KEY-----/g, replace: '[redacted:private-key]' },
  // Long base64 bodies (key material split across strings, certificates, blobs).
  { re: /(?:[A-Za-z0-9+/]{60,}={0,2}(?:\r?\n|\\n)?){2,}/g, replace: '[redacted:base64]' },
  // Quoted secret assignments whose value contains spaces: PASSWORD="correct horse battery"
  {
    re: /((?:^|[\s"'{,;])[A-Za-z0-9_.\-]*(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)[A-Za-z0-9_.\-]*["']?\s*[:=]\s*)(["'])([^"'\n]{4,}?)\2/gim,
    replace: (_m, p, q) => `${p}${q}[redacted]${q}`,
  },
  // KEY=value / "key": "value" assignments whose name suggests a secret
  {
    re: /((?:^|[\s"'{,;])[A-Za-z0-9_.\-]*(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|CONN(?:ECTION)?[_-]?STRING|DATABASE_URL)[A-Za-z0-9_.\-]*["']?\s*[:=]\s*)(["']?)([^\s"',;]{4,})\2/gim,
    replace: (_m, p, q) => `${p}${q}[redacted]${q}`,
  },
];

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

const digitCount = (s: string) => (s.match(/\d/g) ?? []).length;

/**
 * Phone numbers and messaging ids (customer data in support/CRM projects). Conservative on purpose:
 * WhatsApp JIDs, "+<country>" numbers and Indonesian mobile numbers (08…, 628…), so ordinary
 * long numbers (timestamps, ids, sizes) are left alone.
 */
const PHONE_RULES: Rule[] = [
  { re: /\b\d{5,20}(?::\d{1,3})?@(?:s\.whatsapp\.net|c\.us|g\.us|lid|broadcast|newsletter)\b/g, replace: '[redacted:wa-id]' },
  { re: /\btg:-?\d{5,20}\b/g, replace: '[redacted:tg-id]' },
  {
    re: /(?<![\w+])\+\d{1,3}(?:[ \-.]?\(?\d{1,5}\)?){2,6}(?!\d)/g,
    replace: (m) => (digitCount(m) >= 8 && digitCount(m) <= 15 ? '[redacted:phone]' : m),
  },
  {
    re: /(?<![\w+])(?:62|0)8\d{1,3}(?:[ \-.]?\d{2,5}){1,3}(?!\d)/g,
    replace: (m) => (digitCount(m) >= 9 && digitCount(m) <= 15 ? '[redacted:phone]' : m),
  },
];

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export class Redactor {
  private readonly rules: Rule[];
  private readonly redactEmails: boolean;

  constructor(private readonly opts: RedactOptions = {}) {
    this.rules = [];
    for (const lit of new Set(opts.literals ?? [])) {
      if (typeof lit !== 'string' || lit.length < 8) continue;
      this.rules.push({ re: new RegExp(escapeRe(lit), 'gi'), replace: '[redacted:id]' });
      // Also catch shortened forms of a UUID (its first group identifies it in practice).
      const uuid = /^([0-9a-f]{8})-[0-9a-f]{4}-/i.exec(lit);
      if (uuid) this.rules.push({ re: new RegExp(`\\b${uuid[1]}(?:-[0-9a-f]{1,4})*`, 'gi'), replace: '[redacted:id]' });
    }
    this.rules.push(...BUILTIN_RULES);
    if (opts.redactPhones ?? true) this.rules.push(...PHONE_RULES);
    for (const src of opts.extraPatterns ?? []) {
      try {
        this.rules.push({ re: new RegExp(src, 'g'), replace: '[redacted]' });
      } catch {
        /* invalid user pattern: ignored, surfaced by settings validation */
      }
    }
    // Home directory -> "~" (both slash styles, case-insensitive for Windows).
    if (opts.homeDir) {
      const h = opts.homeDir;
      const variants = new Set([h, h.replace(/\\/g, '/'), h.replace(/\\/g, '\\\\')]);
      // Git Bash / MSYS form: C:\Users\x -> /c/Users/x
      const drive = /^([A-Za-z]):[\\/](.*)$/.exec(h);
      if (drive) variants.add(`/${drive[1].toLowerCase()}/${drive[2].replace(/\\/g, '/')}`);
      for (const v of [...variants].sort((a, b) => b.length - a.length)) this.rules.push({ re: new RegExp(escapeRe(v), 'gi'), replace: '~' });
    }
    if (opts.userName && opts.userName.length >= 3) {
      // Claude's encoded project dir names also leak the user name (C--Users-Jane-Doe-...).
      const dashed = opts.userName.replace(/[^a-zA-Z0-9]/g, '-');
      this.rules.push({ re: new RegExp(`(Users-)${escapeRe(dashed)}`, 'gi'), replace: (_m, p) => `${p}user` });
      // Distinctive user names (with a space or long enough) are removed everywhere.
      if (/\s/.test(opts.userName) || opts.userName.length >= 6) {
        this.rules.push({ re: new RegExp(`\\b${escapeRe(opts.userName)}\\b`, 'gi'), replace: 'user' });
        if (dashed !== opts.userName) this.rules.push({ re: new RegExp(`\\b${escapeRe(dashed)}\\b`, 'gi'), replace: 'user' });
      }
    }
    this.redactEmails = opts.redactEmails ?? true;
  }

  redact(s: string): string {
    let out = s;
    for (const r of this.rules) {
      r.re.lastIndex = 0;
      out = out.replace(r.re, r.replace as never);
    }
    if (this.redactEmails) out = out.replace(EMAIL_RE, '[email]');
    return out;
  }

  /** A copy of this redactor that additionally removes the given exact values. */
  withLiterals(literals: string[]): Redactor {
    return new Redactor({ ...this.opts, literals: [...(this.opts.literals ?? []), ...literals] });
  }

  /**
   * Deeply redact every string in a JSON-like value (keys included). Scalar values under
   * secret-looking keys ({ password: "…" }) are replaced using the key as context.
   */
  redactDeep<T>(value: T, state: PemState = { inPem: false }, depth = 0): T {
    if (depth > 64) return '[redacted:too-deep]' as unknown as T;
    if (typeof value === 'string') return this.redactWithState(value, state) as unknown as T;
    if (Array.isArray(value)) return value.map((v) => this.redactDeep(v, state, depth + 1)) as unknown as T;
    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        const secretKey = SECRET_KEY_RE.test(k) && !/^(type|name|kind|tool_use_id|id)$/i.test(k);
        out[this.redact(k)] = secretKey && (typeof v === 'string' || typeof v === 'number') && String(v).length > 0 ? '[redacted]' : this.redactDeep(v, state, depth + 1);
      }
      return out as T;
    }
    return value;
  }

  /**
   * A private key can be split over several strings/records (BEGIN in one, body lines in
   * the next, END later). Once a BEGIN without END is seen, everything is withheld until END.
   */
  private redactWithState(s: string, state: PemState): string {
    let rest = s;
    let prefix = '';
    if (state.inPem) {
      const end = /-----END [A-Z0-9 ]*PRIVATE KEY-----/.exec(rest);
      if (!end) return '[redacted:private-key]';
      state.inPem = false;
      prefix = '[redacted:private-key]';
      rest = rest.slice(end.index + end[0].length);
    }
    const lastBegin = rest.lastIndexOf('PRIVATE KEY-----');
    const begins = [...rest.matchAll(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g)];
    if (begins.length && lastBegin >= 0) {
      const tail = rest.slice(begins[begins.length - 1].index!);
      if (!/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(tail)) state.inPem = true;
    }
    return prefix + this.redact(rest);
  }
}
