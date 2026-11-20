// Replaces stored secret values with [REDACTED: NAME] in anything headed for the model or the
// session file. Unchanged inputs come back as the same object, so callers can tell nothing changed.

export interface Redactable {
  name: string;
  value: string;
}

export interface Needle {
  text: string;
  name: string;
}

/** Shorter strings are too likely to appear by chance, and replacing them would garble output. */
const MIN_NEEDLE_LENGTH = 6;

export function redactionMarker(name: string): string {
  return `[REDACTED: ${name}]`;
}

/** The forms a value can take in output: as stored, URL-encoded, and a URL's password on its own. */
export function needlesFor(secret: Redactable): Needle[] {
  const forms = new Set<string>();
  const value = secret.value.trim();
  forms.add(value);
  forms.add(encodeURIComponent(value));
  const url = /^[a-z][a-z0-9+.-]*:\/\/[^\s:@/?#]*:([^\s/?#]+)@/i.exec(value);
  if (url) {
    forms.add(url[1]);
    try {
      forms.add(decodeURIComponent(url[1]));
    } catch {
      // Not valid percent-encoding; the raw form is already covered.
    }
  }
  // Multi-line values such as private keys also show up one line at a time.
  if (value.includes("\n")) {
    for (const line of value.split(/\r?\n/)) {
      if (line.length >= 16 && !/^-----(BEGIN|END) /.test(line)) forms.add(line);
    }
  }
  return [...forms].filter((text) => text.length >= MIN_NEEDLE_LENGTH).map((text) => ({ text, name: secret.name }));
}

/** Needles for every secret, longest first so a full URL is replaced before its password. */
export function buildNeedles(secrets: Redactable[]): Needle[] {
  return secrets.flatMap(needlesFor).sort((a, b) => b.text.length - a.text.length);
}

export function redactText(text: string, needles: Needle[]): string {
  let out = text;
  for (const needle of needles) {
    if (out.includes(needle.text)) out = out.split(needle.text).join(redactionMarker(needle.name));
  }
  return out;
}

/**
 * Redacts every string inside a JSON-like value. Arrays and objects are copied only along paths that
 * changed, so an unchanged input comes back as the same object.
 */
export function redactDeep<T>(value: T, needles: Needle[]): T {
  if (needles.length === 0) return value;
  return walk(value as JsonLike, needles, undefined) as T;
}

/** Message content, tool arguments, and tool details are all plain JSON-shaped data. */
export type JsonLike = string | number | boolean | null | undefined | JsonLike[] | { [key: string]: JsonLike };

// Image data is base64. Provider signatures and thinking blocks must reach the provider unchanged,
// or it rejects the replayed conversation.
const SKIPPED_KEY = /^(?:data|.*Signature)$/;
const SKIPPED_TYPES = new Set(["image", "thinking", "redacted_thinking"]);

function walk(value: JsonLike, needles: Needle[], key: string | undefined): JsonLike {
  if (typeof value === "string") return key !== undefined && SKIPPED_KEY.test(key) ? value : redactText(value, needles);
  if (Array.isArray(value)) {
    let copy: JsonLike[] | undefined;
    for (let i = 0; i < value.length; i++) {
      const next = walk(value[i], needles, undefined);
      if (next !== value[i]) {
        copy ??= value.slice();
        copy[i] = next;
      }
    }
    return copy ?? value;
  }
  if (value !== null && typeof value === "object") {
    if (typeof value.type === "string" && SKIPPED_TYPES.has(value.type)) return value;
    let copy: { [key: string]: JsonLike } | undefined;
    for (const [k, v] of Object.entries(value)) {
      const next = walk(v, needles, k);
      if (next !== v) {
        copy ??= { ...value };
        copy[k] = next;
      }
    }
    return copy ?? value;
  }
  return value;
}
