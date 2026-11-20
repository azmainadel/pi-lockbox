// Finds credentials in text a user is about to send, so they can be stored instead of sent.
// It recognizes formats only and does not guess which service a key belongs to (Stripe and Clerk
// both use sk_live_, for example). A match is named after the variable it is assigned to, such as
// CLERK_WEBHOOK_SECRET=..., and otherwise gets a generic label.

export type SecretKind = "url" | "token" | "private-key" | "assignment" | "standalone";

export interface SecretMatch {
  /** Offsets of the text to replace. */
  start: number;
  end: number;
  /** The secret itself, which is what gets stored. */
  value: string;
  kind: SecretKind;
  /** What it is, for the user: the variable it is assigned to, or a generic label. */
  label: string;
  /** A masked form the model may see, e.g. "postgres://admin:***@db:5432/app". */
  masked: string;
  /** Name to store it under: the variable name in upper case, or "SECRET". */
  name: string;
}

type RawMatch = Omit<SecretMatch, "label" | "name"> & { key?: string };

const KIND_LABELS: Record<SecretKind, string> = {
  url: "URL with password",
  token: "API key or token",
  "private-key": "Private key",
  assignment: "Secret value",
  standalone: "Possible password or key",
};

const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g;

/** Prefixes that appear only on credentials. Some are shared by several services. */
const TOKEN_PATTERNS: RegExp[] = [
  /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
  /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g,
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g,
  /\bwhsec_[A-Za-z0-9+/=_-]{20,}/g,
  /\bpdl_(?:live|sdbx)_apikey_[A-Za-z0-9_]{20,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{36,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{22,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}/g,
  /\bnpm_[A-Za-z0-9]{36}\b/g,
  /\bhf_[A-Za-z0-9]{30,}/g,
  /\blin_api_[A-Za-z0-9]{30,}/g,
  /\bphx_[A-Za-z0-9]{30,}/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
];

// scheme://user:password@host[...]. The user may be empty (redis://:pass@host). The password is
// greedy so an unencoded "@" in it still parses.
const URL_WITH_PASSWORD = /\b([a-z][a-z0-9+.-]*):\/\/([^\s:@/?#]*):([^\s/?#]+)@([^\s/?#@'"<>`]+)([^\s'"<>`]*)/gi;

const ASSIGNMENT =
  /\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH_?KEY|CREDENTIALS?)[A-Za-z0-9_]*)["']?[ \t]*[:=][ \t]*(["']?)([^\s"']+)\2/gi;

/** NAME=, NAME: , "name": " and export NAME=' right before a value. */
const ASSIGNED_BEFORE = /(["']?)([A-Za-z_][A-Za-z0-9_]*)\1[ \t]*([:=])[ \t]*["']?$/;

/** Values that stand for a secret rather than being one: ***, <password>, ${VAR}, and so on. */
const PLACEHOLDER = /^(?:\*+|•+|x{3,}|X{3,}|\.{3}|…|<[^>]*>|\[[^\]]*\]|\{[^}]*\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_]+%)$/;
const PLACEHOLDER_WORDS = new Set([
  "password",
  "pass",
  "passwd",
  "pwd",
  "secret",
  "token",
  "changeme",
  "example",
  "redacted",
  "yourpassword",
  "your_password",
  "your-password",
  "mypassword",
]);

const TRAILING_PUNCTUATION = /[.,;:!?)\]}]+$/;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value) || PLACEHOLDER_WORDS.has(value.toLowerCase());
}

/** Keeps the recognizable prefix of a token, e.g. "ghp_***" or "sk-proj-***". */
export function maskToken(value: string): string {
  const head = value.slice(0, 12).match(/^.*[_\-.]/);
  return `${head ? head[0] : value.slice(0, 4)}***`;
}

/**
 * Assignment values are only treated as secrets when they look like one. This keeps code such as
 * `token: string` or `password = form.get("password")` from being flagged.
 */
function looksLikeSecretValue(value: string): boolean {
  if (value.length < 6 || isPlaceholder(value)) return false;
  if (/[()[\]{};,<>]/.test(value)) return false;
  if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/.test(value)) return false;
  if (/^(?:true|false|null|undefined|none|required|optional)$/i.test(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
  return classes >= 2;
}

/** The variable a value at `start` is assigned to, if any. */
function assignedName(text: string, start: number): string | undefined {
  const m = ASSIGNED_BEFORE.exec(text.slice(Math.max(0, start - 100), start));
  if (!m) return undefined;
  const [, quote, name, operator] = m;
  // "check this: ghp_..." is prose. A colon counts only after a quoted key or a variable-like name.
  if (operator === ":" && !quote && !name.includes("_") && name !== name.toUpperCase()) return undefined;
  return name;
}

function findUrls(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(URL_WITH_PASSWORD)) {
    const [, scheme, user, password] = m;
    if (isPlaceholder(password)) continue;
    let full = m[0];
    // A sentence can end right after the URL. Trim that punctuation, but keep a host after the "@".
    const trimmed = full.replace(TRAILING_PUNCTUATION, "");
    if (trimmed.lastIndexOf("@") < trimmed.length - 1) full = trimmed;
    const start = m.index ?? 0;
    const rest = full.slice(`${scheme}://${user}:${password}`.length);
    out.push({ start, end: start + full.length, value: full, kind: "url", masked: `${scheme}://${user}:***${rest}` });
  }
  return out;
}

function findTokens(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(PRIVATE_KEY)) {
    const start = m.index ?? 0;
    out.push({ start, end: start + m[0].length, value: m[0], kind: "private-key", masked: "-----BEGIN PRIVATE KEY----- ***" });
  }
  for (const re of TOKEN_PATTERNS) {
    for (const m of text.matchAll(re)) {
      const start = m.index ?? 0;
      out.push({ start, end: start + m[0].length, value: m[0], kind: "token", masked: maskToken(m[0]) });
    }
  }
  return out;
}

function findAssignments(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  for (const m of text.matchAll(ASSIGNMENT)) {
    const [whole, key, quote, rawValue] = m;
    const value = quote ? rawValue : rawValue.replace(TRAILING_PUNCTUATION, "");
    if (!looksLikeSecretValue(value)) continue;
    // The value sits at the end of the match, after its opening quote if any.
    const start = (m.index ?? 0) + whole.length - quote.length - rawValue.length;
    out.push({ start, end: start + value.length, value, kind: "assignment", masked: "***", key });
  }
  return out;
}

/** All secrets in `text`, in order, without overlaps. Earlier and longer matches win. */
export function detectSecrets(text: string): SecretMatch[] {
  const all = [...findTokens(text), ...findUrls(text), ...findAssignments(text)];
  all.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const kept: SecretMatch[] = [];
  for (const { key, ...match } of all) {
    const last = kept.at(-1);
    if (last && match.start < last.end) continue;
    const variable = assignedName(text, match.start) ?? key;
    kept.push({
      ...match,
      label: variable ?? KIND_LABELS[match.kind],
      name: variable ? variable.toUpperCase() : "SECRET",
    });
  }
  return kept;
}

/** What a whole value is, when it is one recognizable secret such as a database URL or an API key. */
export function classifySecret(value: string): SecretMatch | undefined {
  const trimmed = value.trim();
  const [first] = detectSecrets(trimmed);
  return first && first.start === 0 && first.end === trimmed.length ? first : undefined;
}

// Separators that identifiers, paths, file names, and addresses use. Other symbols, such as
// ! * ^ % & or @, suggest a password.
const SEPARATOR = /[-_./:#]/;
const EMAIL = /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/;
const HEX_OR_UUID = /^[0-9a-f-]+$/i;
// Versions, dates, and IP addresses: 1.5.2, v2.3.1-beta.4, 2026-01-18, 203.0.113.42.
const VERSION = /^v?\d+(?:[._-]\d+)*(?:[-+][0-9A-Za-z.-]+)?$/;

type CharClass = "lower" | "upper" | "digit" | "symbol";

function charClass(ch: string): CharClass | undefined {
  if (/\p{Lu}/u.test(ch)) return "upper";
  if (/\p{L}/u.test(ch)) return "lower";
  if (/\p{Nd}/u.test(ch)) return "digit";
  return SEPARATOR.test(ch) ? undefined : "symbol";
}

interface TokenProfile {
  classes: Set<CharClass>;
  /**
   * How often the character type changes, ignoring separators and a capital letter starting a word.
   * Words and identifiers change rarely (getUserById2: 4 in 12); random strings change often.
   */
  switches: number;
}

function profile(token: string): TokenProfile {
  const classes = new Set<CharClass>();
  let switches = 0;
  let previous: CharClass | undefined;
  for (const ch of token) {
    const current = charClass(ch);
    if (current === undefined) continue;
    classes.add(current);
    if (previous !== undefined && current !== previous && !(previous === "upper" && current === "lower")) switches++;
    previous = current;
  }
  return { classes, switches };
}

function isOrdinaryToken(token: string): boolean {
  return (
    token.length < 8 ||
    token.length > 512 ||
    /^[/~.@#!$]/.test(token) ||
    token.includes("://") ||
    EMAIL.test(token) ||
    HEX_OR_UUID.test(token) ||
    VERSION.test(token) ||
    isPlaceholder(token)
  );
}

/**
 * Whether one token looks like a password or key rather than a word, identifier, file name, path,
 * version, hash, or ID. Only used on a message that is nothing but that token.
 */
export function looksLikeStandaloneSecret(token: string): boolean {
  // A one-word question or sentence ("Option3?") ends in punctuation that passwords rarely end in.
  const core = token.replace(/[.?,;]+$/, "");
  if (isOrdinaryToken(core)) return false;
  const { classes, switches } = profile(core);
  const hasDigit = classes.has("digit");
  const hasLetter = classes.has("lower") || classes.has("upper");
  const random = switches >= 4 && switches / core.length >= 0.4;
  // Summer2024!, Tr0ub4dor&3, P@ssw0rd123
  if (classes.size >= 3 && hasDigit && classes.has("symbol")) return true;
  // Xk9mP2qL, a3f9K2mQx7Lp0Zr8Vb4N, k8sdj2kd9fj3kd8sj2kd
  if (random && hasLetter && hasDigit) return classes.size >= 3 || core.length >= 16;
  // xK*mQ&pLz!
  return random && classes.size >= 3 && core.length >= 10;
}

/** A message that is only one random-looking token, such as a password pasted on its own. */
export function detectStandaloneSecret(text: string): SecretMatch | undefined {
  const m = /^(\s*)([`'"]?)(\S+?)\2\s*$/.exec(text);
  if (!m) return undefined;
  const [, lead, quote, token] = m;
  if (!looksLikeStandaloneSecret(token)) return undefined;
  const start = lead.length + quote.length;
  return {
    start,
    end: start + token.length,
    value: token,
    kind: "standalone",
    label: `${KIND_LABELS.standalone} (${[...token].length} characters)`,
    masked: "***",
    name: "SECRET",
  };
}

/**
 * What the paste guard checks: known formats anywhere in the message, or, when there are none, a
 * message that is only a random-looking token.
 */
export function detectInMessage(text: string): SecretMatch[] {
  const found = detectSecrets(text);
  if (found.length > 0) return found;
  const standalone = detectStandaloneSecret(text);
  return standalone ? [standalone] : [];
}

/** Replaces each match with `replace(match)`, working from the end so offsets stay valid. */
export function replaceMatches(text: string, matches: SecretMatch[], replace: (match: SecretMatch, index: number) => string): string {
  let out = text;
  for (let i = matches.length - 1; i >= 0; i--) {
    const match = matches[i];
    out = out.slice(0, match.start) + replace(match, i) + out.slice(match.end);
  }
  return out;
}
