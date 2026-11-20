import assert from "node:assert/strict";
import { test } from "node:test";
import { buildNeedles, needlesFor, redactDeep, redactText } from "../src/redact.ts";
import { displayReferences, hasReference, REFERENCE_NOTE, referenceTag, withReferenceNote } from "../src/reference.ts";

const DB = { name: "DB_URL", value: "postgres://admin:S3cr3t!x@db.prod.internal:5432/app" };

test("redacts a URL, its password on its own, and its URL-encoded form", () => {
  const needles = buildNeedles([DB]);
  assert.equal(redactText(`psql "${DB.value}"`, needles), 'psql "[REDACTED: DB_URL]"');
  assert.equal(redactText("FATAL: password S3cr3t!x rejected", needles), "FATAL: password [REDACTED: DB_URL] rejected");
  assert.equal(redactText(encodeURIComponent(DB.value), needles), "[REDACTED: DB_URL]");
});

test("decodes a percent-encoded URL password", () => {
  const needles = needlesFor({ name: "X", value: "mysql://u:p%40ssw0rd@h/d" });
  assert.ok(needles.some((n) => n.text === "p@ssw0rd"));
});

test("short values are not used as needles", () => {
  assert.deepEqual(needlesFor({ name: "PIN", value: "1234" }), []);
  assert.equal(redactText("pin 1234", buildNeedles([{ name: "PIN", value: "1234" }])), "pin 1234");
});

test("multi-line keys are also matched one line at a time", () => {
  const key = "-----BEGIN KEY-----\nAAAABBBBCCCCDDDDEEEE\nFFFFGGGGHHHHIIIIJJJJ\n-----END KEY-----\n";
  const needles = buildNeedles([{ name: "KEY", value: key }]);
  assert.equal(redactText("line FFFFGGGGHHHHIIIIJJJJ end", needles), "line [REDACTED: KEY] end");
  // Header and footer lines are the same in every key, so replacing them would hide nothing.
  assert.ok(!needles.some((n) => n.text === "-----BEGIN KEY-----" || n.text === "-----END KEY-----"));
});

test("redactDeep copies only what changed and skips images, thinking, and signatures", () => {
  const needles = buildNeedles([DB]);
  const untouched = { role: "user", content: [{ type: "text", text: "hello" }] };
  assert.equal(redactDeep(untouched, needles), untouched);

  const textBlock = { type: "text", text: `using ${DB.value}`, textSignature: DB.value };
  const image = { type: "image", data: DB.value, mimeType: "image/png" };
  const thinking = { type: "thinking", thinking: DB.value, thinkingSignature: DB.value };
  const message = {
    role: "assistant",
    content: [textBlock, thinking, image] as [typeof textBlock, typeof thinking, typeof image],
    usage: { input: 1 },
  };
  const out = redactDeep(message, needles);
  const [outText, outThinking, outImage] = out.content;
  assert.notEqual(out, message);
  assert.equal(outText.text, "using [REDACTED: DB_URL]");
  assert.equal(outText.textSignature, DB.value);
  assert.equal(outThinking, thinking);
  assert.equal(outImage, image);
  assert.equal(out.usage, message.usage);
  assert.equal(textBlock.text, `using ${DB.value}`, "input is not mutated");
});

test("redactDeep reaches tool-call arguments", () => {
  const needles = buildNeedles([DB]);
  const call = { type: "toolCall", id: "1", name: "bash", arguments: { command: `psql '${DB.value}' -c 'select 1'` } };
  assert.equal(redactDeep(call, needles).arguments.command, "psql '[REDACTED: DB_URL]' -c 'select 1'");
});

test("reference tags round-trip to a display form without the path", () => {
  const tag = referenceTag({ name: "DB_URL", file: "/home/u/.pi/agent/secrets/abc", masked: 'postgres://a:***@h/"x"' });
  assert.ok(hasReference(tag));
  const message = withReferenceNote(`db is ${tag}`);
  assert.ok(message.endsWith(REFERENCE_NOTE));
  assert.equal(withReferenceNote(message), message, "the note is added once");
  assert.equal(displayReferences(message), 'db is `postgres://a:***@h/"x"` 🔒 *DB_URL*');
  assert.equal(withReferenceNote("no tags"), "no tags");
});
