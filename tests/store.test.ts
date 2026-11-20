import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { normalizeSecretValue, SecretStore, toSecretName } from "../src/store.ts";

function withDir(run: (dir: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "pi-lockbox-test-"));
  try {
    run(join(root, "secrets"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const input = (value: string, name = "DB_URL") => ({ value, name, label: "Test", masked: "***", source: "add" as const });

test("saves values in owner-only files inside an owner-only directory", () => {
  withDir((dir) => {
    const store = new SecretStore(dir);
    const secret = store.save(input("postgres://u:pw@h/db"));
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.equal(statSync(secret.file).mode & 0o777, 0o600);
    assert.equal(statSync(`${secret.file}.json`).mode & 0o777, 0o600);
    assert.equal(store.readValue(secret.id), "postgres://u:pw@h/db");
    assert.equal(secret.name, "DB_URL");
    assert.ok(!readdirSync(dir).some((file) => file.endsWith(".partial")));
  });
});

test("metadata never contains the value", () => {
  withDir((dir) => {
    const store = new SecretStore(dir);
    const secret = store.save(input("very-secret-value-123"));
    const files = readdirSync(dir).filter((file) => file.endsWith(".json"));
    assert.deepEqual(files, [`${secret.id}.json`]);
    for (const file of files) {
      assert.ok(!statSync(join(dir, file)).isSymbolicLink());
    }
    assert.ok(!JSON.stringify(store.list()).includes("very-secret-value-123"));
  });
});

test("names are unique and saving the same value twice returns the first entry", () => {
  withDir((dir) => {
    const store = new SecretStore(dir);
    const a = store.save(input("value-one-111"));
    const b = store.save(input("value-two-222"));
    const again = store.save(input("value-one-111", "OTHER"));
    assert.equal(a.name, "DB_URL");
    assert.equal(b.name, "DB_URL_2");
    assert.equal(again.id, a.id);
    assert.equal(store.list().length, 2);
  });
});

test("secrets expire and are swept", () => {
  withDir((dir) => {
    let now = 1_000_000;
    const store = new SecretStore(dir, { ttlMs: 1000, now: () => now });
    const secret = store.save(input("short-lived-secret"));
    assert.equal(store.list().length, 1);
    now += 1001;
    assert.equal(store.sweep(), 1);
    assert.equal(store.list().length, 0);
    assert.equal(store.readValue(secret.id), undefined);
    assert.deepEqual(readdirSync(dir), []);
  });
});

test("sweep removes old leftovers from interrupted saves but keeps recent ones", () => {
  withDir((dir) => {
    const store = new SecretStore(dir);
    store.save(input("keep-me-please"));
    const stray = join(dir, `${"a".repeat(32)}.1234abcd.partial`);
    const fresh = join(dir, `${"b".repeat(32)}`);
    writeFileSync(stray, "x");
    writeFileSync(fresh, "y");
    const old = new Date(Date.now() - 5 * 60_000);
    utimesSync(stray, old, old);
    store.sweep();
    const files = readdirSync(dir);
    assert.ok(!files.includes(`${"a".repeat(32)}.1234abcd.partial`));
    // A value file without metadata is removed by list(), regardless of age.
    assert.ok(!files.includes("b".repeat(32)));
    assert.equal(store.list().length, 1);
  });
});

test("remove and clear", () => {
  withDir((dir) => {
    const store = new SecretStore(dir);
    const a = store.save(input("first-secret-1"));
    store.save(input("second-secret-2"));
    store.remove(a.id);
    assert.equal(store.list().length, 1);
    assert.equal(store.clear(), 1);
    assert.equal(store.list().length, 0);
    store.remove("../../etc/passwd");
  });
});

test("refuses a symlinked store directory", () => {
  withDir((dir) => {
    const target = `${dir}-real`;
    new SecretStore(target).save(input("seed-value-xyz"));
    symlinkSync(target, dir);
    assert.throws(() => new SecretStore(dir).save(input("another-value")), /symbolic link/);
  });
});

test("toSecretName and normalizeSecretValue", () => {
  assert.equal(toSecretName("Staging DATABASE_URL"), "STAGING_DATABASE_URL");
  assert.equal(toSecretName("  github token! "), "GITHUB_TOKEN");
  assert.equal(toSecretName("123"), "S_123");
  assert.equal(toSecretName("!!!"), "SECRET");
  assert.equal(normalizeSecretValue("  abc \r\n"), "abc");
  assert.equal(
    normalizeSecretValue("-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----"),
    "-----BEGIN KEY-----\nabc\n-----END KEY-----\n",
  );
});
