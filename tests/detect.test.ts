import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classifySecret,
  detectInMessage,
  detectSecrets,
  detectStandaloneSecret,
  isPlaceholder,
  looksLikeStandaloneSecret,
  maskToken,
  replaceMatches,
} from "../src/detect.ts";

// Token-shaped test values are built from parts so secret scanners do not flag this file.
const fake = (prefix: string, body: string) => prefix + body;
const STRIPE_LIKE = fake("sk_" + "live_", "4eC39HqLyjWDarjtT1zdp7dc");
const CLERK_LIKE = fake("sk_" + "test_", "Fa4eKq9Lm2Zx7Pr3Tw8Vb5Nc1Yh6Jd0Gs2Qe4Uk8Ro");
const WEBHOOK_LIKE = fake("wh" + "sec_", "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");
const SLACK_LIKE = fake("xo" + "xb-", "1234567890-abcdefghij");
const AWS_LIKE = fake("AK" + "IA", "IOSFODNN7EXAMPLE");

const values = (text: string) => detectSecrets(text).map((m) => m.value);

test("a message that is only a random-looking token is caught", () => {
  const secrets = [
    "Qm7xR2vK9pL*tz^Wn4BsH8jY3eFa615d",
    "Summer2024!",
    "Tr0ub4dor&3",
    "P@ssw0rd123",
    "Xk9mP2qL",
    "a3f9K2mQx7Lp0Zr8Vb4N",
    "k8sdj2kd9fj3kd8sj2kd",
    "xK*mQ&pLz!",
  ];
  for (const secret of secrets) assert.ok(looksLikeStandaloneSecret(secret), secret);

  const [match] = detectInMessage("  Qm7xR2vK9pL*tz^Wn4BsH8jY3eFa615d\n");
  assert.equal(match.value, "Qm7xR2vK9pL*tz^Wn4BsH8jY3eFa615d");
  assert.equal(match.kind, "standalone");
  assert.equal(match.label, "Possible password or key (32 characters)");
  assert.equal(match.masked, "***");
  assert.equal(detectStandaloneSecret("`Summer2024!`")?.value, "Summer2024!", "quotes are not part of the value");
});

test("one-word messages that are not secrets are left alone", () => {
  const ordinary = [
    "yes",
    "continue",
    "Perfect!",
    "getUserById2",
    "camelCaseName2",
    "README.md",
    "ENG-1234",
    "src/index.ts",
    "./scripts/run.sh",
    "v2.3.1-beta.4",
    "2026-01-18",
    "203.0.113.42",
    "e8c4824b",
    "3fb137a64c45a46ea885f45e9ff65ebe",
    "550e8400-e29b-41d4-a716-446655440000",
    "adel@example.com",
    "https://github.com",
    "feature/my-branch",
    "claude-opus-5-5",
    "OAuth2",
    "iPhone15",
    "x86_64",
    "Option3?",
    "PR#123",
    "localhost:3000",
    "@azmainadel",
  ];
  for (const word of ordinary) assert.ok(!looksLikeStandaloneSecret(word), word);
});

test("a random-looking token inside a sentence is not caught", () => {
  assert.deepEqual(detectInMessage("the password is Qm7xR2vK9pL*tz^Wn4BsH8jY3eFa615d"), []);
  assert.deepEqual(detectInMessage("Qm7xR2vK9pL*tz^Wn4BsH8jY3eFa615d Qm7xR2vK9pL*tz^Wn4BsH8jY3eFa615d"), []);
});

test("known formats take priority over the standalone check", () => {
  const [match] = detectInMessage("ghp_" + "x".repeat(36));
  assert.equal(match.kind, "token");
});

test("finds a Postgres URL with a password and masks only the password", () => {
  const text = "check why signups fail, db is postgres://admin:S3cr3t!x@db.prod.internal:5432/app";
  const [match] = detectSecrets(text);
  assert.equal(match.value, "postgres://admin:S3cr3t!x@db.prod.internal:5432/app");
  assert.equal(match.label, "URL with password");
  assert.equal(match.masked, "postgres://admin:***@db.prod.internal:5432/app");
  assert.equal(match.name, "SECRET");
  assert.equal(text.slice(match.start, match.end), match.value);
});

test("a secret assigned to a variable is named after it", () => {
  const clerk = detectSecrets(`CLERK_WEBHOOK_SECRET=${CLERK_LIKE}`);
  assert.equal(clerk.length, 1);
  assert.equal(clerk[0].value, CLERK_LIKE);
  assert.equal(clerk[0].label, "CLERK_WEBHOOK_SECRET");
  assert.equal(clerk[0].name, "CLERK_WEBHOOK_SECRET");
  assert.equal(clerk[0].masked, "sk_test_***");

  const [db] = detectSecrets("DATABASE_URL=postgresql://postgres:Pw0rd123@10.0.0.1:5438/app?sslmode=prefer");
  assert.equal(db.name, "DATABASE_URL");
  assert.equal(db.masked, "postgresql://postgres:***@10.0.0.1:5438/app?sslmode=prefer");

  assert.equal(detectSecrets(`{"stripeKey": "${STRIPE_LIKE}"}`)[0].name, "STRIPEKEY");
  assert.equal(detectSecrets("export GH_TOKEN='ghp_" + "x".repeat(36) + "'")[0].name, "GH_TOKEN");
});

test("prose before a colon is not taken as a variable name", () => {
  const [match] = detectSecrets("check this: ghp_" + "x".repeat(36));
  assert.equal(match.name, "SECRET");
  assert.equal(match.label, "API key or token");
  assert.equal(detectSecrets(`API_KEY: ${STRIPE_LIKE}`)[0].name, "API_KEY");
});

test("URL detection handles an @ in the password, an empty user, and trailing punctuation", () => {
  assert.deepEqual(values("use mysql://root:p@ss@localhost/db."), ["mysql://root:p@ss@localhost/db"]);
  assert.deepEqual(values("redis://:hunter2x@cache:6379"), ["redis://:hunter2x@cache:6379"]);
  assert.deepEqual(values("(mongodb+srv://u:Abc123xyz@cluster0.x.mongodb.net/test?retryWrites=true)"), [
    "mongodb+srv://u:Abc123xyz@cluster0.x.mongodb.net/test?retryWrites=true",
  ]);
});

test("URLs without a password, or with a placeholder password, are left alone", () => {
  assert.deepEqual(values("see https://github.com/pingdotgg/t3code"), []);
  assert.deepEqual(values("postgres://admin@localhost/app"), []);
  assert.deepEqual(values("postgres://user:password@localhost/app"), []);
  assert.deepEqual(values("postgres://user:***@localhost/app"), []);
  assert.deepEqual(values("postgres://user:${DB_PASS}@localhost/app"), []);
  assert.deepEqual(values("postgres://user:<password>@localhost/app"), []);
});

test("finds API tokens by prefix without guessing the service", () => {
  const tokens = [
    "sk-ant-api03-" + "a".repeat(40),
    "sk-proj-" + "A1b2".repeat(10),
    STRIPE_LIKE,
    "ghp_" + "x".repeat(36),
    "github_pat_11ABCDEFG0" + "y".repeat(40),
    AWS_LIKE,
    SLACK_LIKE,
    "AIza" + "S".repeat(35),
    WEBHOOK_LIKE,
  ];
  for (const token of tokens) {
    const [match] = detectSecrets(`token is ${token} ok`);
    assert.equal(match?.value, token, token);
    assert.equal(match.label, "API key or token");
    assert.equal(match.name, "SECRET");
    assert.ok(!match.masked.includes(token.slice(10)), `${token} masked form hides the token`);
  }
});

test("finds a PEM private key across lines", () => {
  const key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAABG5vbmUAAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----";
  const [match] = detectSecrets(`here:\n${key}\nthanks`);
  assert.equal(match.value, key);
  assert.equal(match.kind, "private-key");
});

test("finds secret-looking assignments", () => {
  const [env] = detectSecrets("DB_PASSWORD=Tr0ub4dor&3");
  assert.equal(env.value, "Tr0ub4dor&3");
  assert.equal(env.name, "DB_PASSWORD");
  assert.equal(env.label, "DB_PASSWORD");
  assert.equal(env.masked, "***");
  assert.deepEqual(values('{"api_key": "abcd1234efgh"}'), ["abcd1234efgh"]);
  assert.deepEqual(values("export STRIPE_SECRET='k3y-Value-99'"), ["k3y-Value-99"]);
});

test("ignores code and prose that only mention secrets", () => {
  assert.deepEqual(values("token: string"), []);
  assert.deepEqual(values('const password = form.get("password")'), []);
  assert.deepEqual(values("password = config.db.password"), []);
  assert.deepEqual(values("API_KEY=${API_KEY}"), []);
  assert.deepEqual(values("SECRET_KEY=changeme"), []);
  assert.deepEqual(values("the token expired, can you refresh it?"), []);
  assert.deepEqual(values("set TOKEN=true"), []);
});

test("overlapping matches keep the longest at each position", () => {
  const text = "DATABASE_PASSWORD=postgres://a:Secret123@h/db";
  const matches = detectSecrets(text);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].kind, "url");
  assert.equal(matches[0].name, "DATABASE_PASSWORD");
});

test("replaceMatches replaces every match in order", () => {
  const text = "a ghp_" + "1".repeat(36) + " b DB=postgres://u:Pw0rd123@h/d c";
  const out = replaceMatches(text, detectSecrets(text), (m, i) => `<${i}:${m.name}>`);
  assert.equal(out, "a <0:SECRET> b DB=<1:DB> c");
});

test("classifySecret recognizes a whole value", () => {
  assert.equal(classifySecret("  postgres://u:Pw0rd123@h/d \n")?.masked, "postgres://u:***@h/d");
  assert.equal(classifySecret("not a secret postgres://u:Pw0rd123@h/d"), undefined);
  assert.equal(classifySecret("plain-value"), undefined);
});

test("placeholders and token masks", () => {
  assert.ok(isPlaceholder("***"));
  assert.ok(isPlaceholder("${TOKEN}"));
  assert.ok(isPlaceholder("Password"));
  assert.ok(!isPlaceholder("S3cr3t!x"));
  assert.equal(maskToken("ghp_abcdefghijklmnop"), "ghp_***");
  assert.equal(maskToken("sk-proj-abcdefghijkl"), "sk-proj-***");
  assert.equal(maskToken(AWS_LIKE), "AKIA***");
});
