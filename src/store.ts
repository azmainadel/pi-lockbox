// Owner-only storage for secrets. Each secret is two files in one 0700 directory:
//   <id>       the value, mode 0600, which the agent's commands read with "$(cat <id>)"
//   <id>.json  metadata without the value, used for listing and naming
// Separate files per secret mean concurrent pi processes never rewrite a shared index.

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

export type SecretSource = "request" | "paste" | "add";

export interface SecretMeta {
  id: string;
  name: string;
  label: string;
  /** Masked form that is safe to show the model. */
  masked: string;
  source: SecretSource;
  createdAt: number;
  expiresAt: number;
}

export interface StoredSecret extends SecretMeta {
  /** Absolute path of the value file. */
  file: string;
}

export interface SaveInput {
  value: string;
  name: string;
  label: string;
  masked: string;
  source: SecretSource;
}

const ID_PATTERN = /^[0-9a-f]{32}$/;
const META_SUFFIX = ".json";
const STRAY_PATTERN = /^([0-9a-f]{32})(?:\.json)?(?:\.[0-9a-f]{8}\.partial)?$/;
const STRAY_GRACE_MS = 60_000;

/** Turns a label such as "Staging DATABASE_URL" into "STAGING_DATABASE_URL". */
export function toSecretName(text: string): string {
  const name = text
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 48);
  if (!name) return "SECRET";
  return /^[0-9]/.test(name) ? `S_${name}` : name;
}

/**
 * Trims what the user typed or pasted. PEM keys keep a final newline, which tools such as ssh-add
 * require.
 */
export function normalizeSecretValue(raw: string): string {
  const value = raw.replace(/\r\n?/g, "\n").trim();
  return /-----END [A-Z0-9 ]+-----$/.test(value) ? `${value}\n` : value;
}

export class SecretStore {
  readonly dir: string;
  readonly ttlMs: number;
  private readonly now: () => number;

  constructor(dir: string, options: { ttlMs?: number; now?: () => number } = {}) {
    this.dir = dir;
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.now = options.now ?? Date.now;
  }

  private ensureDir(): void {
    if (existsSync(this.dir)) {
      if (lstatSync(this.dir).isSymbolicLink()) {
        throw new Error(`Refusing to use ${this.dir}: it is a symbolic link`);
      }
    } else {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    }
    chmodSync(this.dir, 0o700);
  }

  private readMeta(id: string): SecretMeta | undefined {
    try {
      const meta = JSON.parse(readFileSync(join(this.dir, id + META_SUFFIX), "utf8")) as SecretMeta;
      return meta.id === id ? meta : undefined;
    } catch {
      return undefined;
    }
  }

  private ids(): string[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir).filter((file) => ID_PATTERN.test(file));
  }

  /**
   * Changes whenever a secret is added or removed, and at least once a minute so expiry is noticed.
   * Callers use it to know when to rebuild what they derived from the store.
   */
  stamp(): string {
    try {
      return `${lstatSync(this.dir).mtimeMs}:${Math.floor(this.now() / 60_000)}`;
    } catch {
      return "none";
    }
  }

  /** Live secrets, oldest first. Expired ones are deleted on the way. */
  list(): StoredSecret[] {
    const now = this.now();
    const out: StoredSecret[] = [];
    for (const id of this.ids()) {
      const meta = this.readMeta(id);
      if (!meta || meta.expiresAt <= now) {
        this.remove(id);
        continue;
      }
      out.push({ ...meta, file: join(this.dir, id) });
    }
    return out.sort((a, b) => a.createdAt - b.createdAt);
  }

  readValue(id: string): string | undefined {
    if (!ID_PATTERN.test(id)) return undefined;
    try {
      return readFileSync(join(this.dir, id), "utf8");
    } catch {
      return undefined;
    }
  }

  /** Live secrets with their values, for redaction. */
  entries(): Array<{ secret: StoredSecret; value: string }> {
    const out: Array<{ secret: StoredSecret; value: string }> = [];
    for (const secret of this.list()) {
      const value = this.readValue(secret.id);
      if (value !== undefined) out.push({ secret, value });
    }
    return out;
  }

  /**
   * Stores a value and returns where it lives. Saving a value that is already stored returns the
   * existing entry, so re-sending the same message does not create duplicates.
   */
  save(input: SaveInput): StoredSecret {
    const live = this.entries();
    const existing = live.find((entry) => entry.value === input.value);
    if (existing) return existing.secret;

    this.ensureDir();
    const taken = new Set(live.map((entry) => entry.secret.name));
    const base = toSecretName(input.name);
    let name = base;
    for (let n = 2; taken.has(name); n++) name = `${base}_${n}`;

    const id = randomBytes(16).toString("hex");
    const file = join(this.dir, id);
    const createdAt = this.now();
    const meta: SecretMeta = {
      id,
      name,
      label: input.label,
      masked: input.masked,
      source: input.source,
      createdAt,
      expiresAt: createdAt + this.ttlMs,
    };
    // Metadata goes first: list() treats a value file without metadata as junk, so writing the value
    // last means another pi process never deletes a secret that is still being saved.
    writeAtomic(file + META_SUFFIX, JSON.stringify(meta, null, 2));
    writeAtomic(file, input.value);
    return { ...meta, file };
  }

  remove(id: string): void {
    if (!ID_PATTERN.test(id)) return;
    rmSync(join(this.dir, id), { force: true });
    rmSync(join(this.dir, id + META_SUFFIX), { force: true });
  }

  clear(): number {
    const secrets = this.list();
    for (const secret of secrets) this.remove(secret.id);
    return secrets.length;
  }

  /** Deletes expired secrets and leftovers from interrupted saves. Returns how many secrets were removed. */
  sweep(): number {
    if (!existsSync(this.dir)) return 0;
    const before = this.ids().length;
    const live = new Set(this.list().map((secret) => secret.id));
    const cutoff = this.now() - STRAY_GRACE_MS;
    for (const file of readdirSync(this.dir)) {
      const match = STRAY_PATTERN.exec(file);
      if (!match || live.has(match[1])) continue;
      // A save in another process may be between its two writes, so only old leftovers go.
      const path = join(this.dir, file);
      try {
        if (lstatSync(path).mtimeMs < cutoff) rmSync(path, { force: true });
      } catch {
        // Already gone.
      }
    }
    return before - live.size;
  }
}

function writeAtomic(path: string, data: string): void {
  const partial = `${path}.${randomBytes(4).toString("hex")}.partial`;
  // "wx" never follows or replaces an existing path, so a planted symlink cannot redirect the write.
  writeFileSync(partial, data, { flag: "wx", mode: 0o600 });
  renameSync(partial, path);
}
