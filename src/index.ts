// pi-lockbox: give pi secrets without sending them to the model.
//
// - request_secret: the agent asks, you type the value into a masked card, and the model only gets
//   the path of an owner-only file that its commands read with "$(cat <file>)".
// - Paste guard: a message with a database URL, API key, or private key is caught before it is
//   sent. The value is stored and the model sees a masked form plus the file path.
// - Redaction: stored values that show up anyway (command output, error messages, the model's own
//   text) are replaced with [REDACTED: NAME] before they reach the model or the session file.

import { getAgentDir, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { join } from "node:path";
import { Type } from "typebox";
import { classifySecret, detectInMessage, replaceMatches, type SecretMatch } from "./detect.ts";
import { buildNeedles, type Needle, redactDeep } from "./redact.ts";
import { displayReferences, hasReference, referenceTag, withReferenceNote } from "./reference.ts";
import { DEFAULT_TTL_MS, normalizeSecretValue, SecretStore, type StoredSecret, toSecretName } from "./store.ts";
import { type GuardChoice, GuardPrompt, SecretPrompt, type SecretPromptResult } from "./ui.ts";

const TOOL_NAME = "request_secret";

const RequestSecretParams = Type.Object({
  label: Type.String({ description: "Card title, e.g. 'Staging DATABASE_URL'. One secret per call." }),
  reason: Type.String({ description: "What it is for and where the user can find it." }),
  url: Type.Optional(Type.String({ description: "Sign-in or settings page where the user can get the value." })),
  name: Type.Optional(
    Type.String({ description: "Environment-style name to refer to it by, e.g. 'STAGING_DB_URL'. Defaults to the label." }),
  ),
});

interface RequestSecretDetails {
  status: "saved" | "declined" | "unavailable";
  name?: string;
  file?: string;
  masked?: string;
  length?: number;
  expiresAt?: number;
}

function lifetime(ttlMs: number): string {
  const hours = Math.round(ttlMs / 3_600_000);
  if (hours >= 1) return hours === 1 ? "1 hour" : `${hours} hours`;
  const minutes = Math.max(1, Math.round(ttlMs / 60_000));
  return minutes === 1 ? "1 minute" : `${minutes} minutes`;
}

function tildePath(path: string): string {
  const home = process.env.HOME;
  return home && path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path;
}

function remaining(expiresAt: number): string {
  const ms = expiresAt - Date.now();
  if (ms <= 0) return "expired";
  const hours = Math.floor(ms / 3_600_000);
  const minutes = Math.floor((ms % 3_600_000) / 60_000);
  return hours > 0 ? `${hours}h ${minutes}m left` : `${minutes}m left`;
}

function savedResultText(secret: StoredSecret): string {
  return [
    `Saved. The value is in ${secret.file} (owner-only, deleted after ${lifetime(secret.expiresAt - secret.createdAt)}).`,
    `Use it only inside the command that needs it, e.g. DATABASE_URL="$(cat ${secret.file})" <command>.`,
    "Never print the file or the value, and never repeat it in replies. If it shows up in output, pi replaces it with",
    `[REDACTED: ${secret.name}].`,
  ].join(" ");
}

export default function piLockbox(pi: ExtensionAPI) {
  const ttlMs = Number(process.env.PI_LOCKBOX_TTL_MS) > 0 ? Number(process.env.PI_LOCKBOX_TTL_MS) : DEFAULT_TTL_MS;
  const store = new SecretStore(process.env.PI_LOCKBOX_DIR || join(getAgentDir(), "secrets"), { ttlMs });

  // Needles are rebuilt only when the store changes, so the hooks below stay cheap.
  let cachedStamp = "";
  let cachedNeedles: Needle[] = [];
  const needles = (): Needle[] => {
    const stamp = store.stamp();
    if (stamp !== cachedStamp) {
      cachedNeedles = buildNeedles(store.entries().map(({ secret, value }) => ({ name: secret.name, value })));
      cachedStamp = store.stamp();
    }
    return cachedNeedles;
  };

  pi.on("session_start", () => {
    store.sweep();
  });

  // ---------------------------------------------------------------- request_secret
  pi.registerTool({
    name: TOOL_NAME,
    label: "Request secret",
    description: [
      "Ask the user for one secret (password, API key, token, database URL) in a private masked card instead of in chat.",
      "Returns the path of an owner-only file that holds the value; the value itself never reaches you.",
      'Read it only inside the command that needs it, e.g. psql "$(cat <file>)". Never print it.',
      "If the user declines, do not ask for it in chat; say what is blocked and continue without it.",
    ].join(" "),
    promptSnippet: "Ask the user for a password, token, or other secret in a masked prompt",
    promptGuidelines: [
      "When a task needs a password, API key, token, or connection string the user has not given, call request_secret instead of asking for it in chat.",
      "Never print, echo, or cat secret files that request_secret returns; use them inside the command that needs them.",
    ],
    parameters: RequestSecretParams,
    executionMode: "sequential",

    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      if (ctx.mode !== "tui") {
        return {
          content: [
            {
              type: "text",
              text: "No interactive terminal is available, so the user cannot enter a secret here. Ask them to set it as an environment variable before starting pi.",
            },
          ],
          details: { status: "unavailable" } satisfies RequestSecretDetails,
          isError: true,
        };
      }

      const result = await ctx.ui.custom<SecretPromptResult>(
        (tui, theme, keybindings, done) => {
          const finish = (value: SecretPromptResult) => {
            signal?.removeEventListener("abort", onAbort);
            done(value);
          };
          const onAbort = () => finish({ action: "cancel" });
          signal?.addEventListener("abort", onAbort, { once: true });
          return new SecretPrompt(
            tui,
            theme,
            keybindings,
            { label: params.label, reason: params.reason, url: params.url, lifetime: lifetime(ttlMs) },
            finish,
          );
        },
        { blocked: { kind: "auth", message: `Secret requested: ${params.label}` } },
      );

      if (result.action !== "save") {
        const cancelled = result.action === "cancel";
        return {
          content: [
            {
              type: "text",
              text: cancelled
                ? "The request was cancelled before the user answered."
                : "The user declined. Don't ask for it in chat or another way; say what's blocked and go on without it.",
            },
          ],
          details: { status: "declined" } satisfies RequestSecretDetails,
        };
      }

      const value = normalizeSecretValue(result.value);
      const known = classifySecret(value);
      const secret = store.save({
        value,
        name: params.name ? toSecretName(params.name) : toSecretName(params.label),
        label: params.label,
        masked: known?.masked ?? "***",
        source: "request",
      });
      return {
        content: [{ type: "text", text: savedResultText(secret) }],
        details: {
          status: "saved",
          name: secret.name,
          file: secret.file,
          masked: secret.masked,
          length: value.length,
          expiresAt: secret.expiresAt,
        } satisfies RequestSecretDetails,
      };
    },

    renderCall(args, theme) {
      const label = typeof args.label === "string" ? args.label : "";
      return new Text(`${theme.fg("toolTitle", theme.bold("request_secret "))}${theme.fg("accent", label)}`, 0, 0);
    },

    renderResult(result, { isPartial }, theme) {
      if (isPartial) return new Text(theme.fg("dim", "waiting for you…"), 0, 0);
      const details = result.details as RequestSecretDetails | undefined;
      if (details?.status === "saved") {
        const lines = [
          `${theme.fg("success", "✓ Saved securely")} ${theme.fg("dim", `as ${details.name} · ${details.length} chars`)}`,
          theme.fg("dim", `→ ${tildePath(details.file ?? "")} · deleted in ${lifetime((details.expiresAt ?? Date.now()) - Date.now())}`),
        ];
        return new Text(lines.join("\n"), 0, 0);
      }
      if (details?.status === "unavailable") return new Text(theme.fg("error", "✗ No terminal to ask in"), 0, 0);
      return new Text(theme.fg("warning", "✗ Declined"), 0, 0);
    },
  });

  // ---------------------------------------------------------------- paste guard
  let requestRender: (() => void) | undefined;
  const guard = async (matches: SecretMatch[], ctx: ExtensionContext): Promise<GuardChoice> => {
    if (ctx.mode !== "tui") return "store";
    return ctx.ui.custom<GuardChoice>(
      (tui, theme, keybindings, done) => {
        requestRender = () => tui.requestRender();
        return new GuardPrompt(
          tui,
          theme,
          keybindings,
          matches.map((match) => ({ label: match.label, masked: match.masked })),
          done,
        );
      },
      { blocked: { kind: "question", message: "Your message looks like it contains a secret" } },
    );
  };

  pi.on("input", async (event, ctx) => {
    if (event.source === "extension") return { action: "continue" };
    const matches = detectInMessage(event.text);
    if (matches.length === 0) return { action: "continue" };

    const choice = await guard(matches, ctx);
    if (choice === "edit") {
      // Closing the card restores the editor to what it held when the card opened, which is empty
      // because the message was already submitted. Put the message back after that, and redraw.
      setTimeout(() => {
        ctx.ui.setEditorText(event.text);
        requestRender?.();
      }, 0);
      return { action: "handled" };
    }
    if (choice === "send") return { action: "continue" };

    const stored = matches.map((match) =>
      store.save({ value: match.value, name: match.name, label: match.label, masked: match.masked, source: "paste" }),
    );
    const text = withReferenceNote(replaceMatches(event.text, matches, (_match, i) => referenceTag(stored[i])));
    ctx.ui.notify(
      `Stored ${stored.map((secret) => secret.name).join(", ")} securely. The model gets a file reference.`,
      "info",
    );
    return { action: "transform", text, images: event.images };
  });

  // Show references in the transcript as the masked value and name, without the file path and note.
  pi.registerMarkdownTransformer((markdown) => (hasReference(markdown) ? displayReferences(markdown) : markdown), {
    messageTypes: ["user"],
  });

  // ---------------------------------------------------------------- redaction
  // Command output and other tool results, before the model sees them.
  pi.on("tool_result", (event) => {
    const current = needles();
    if (current.length === 0) return;
    const content = redactDeep(event.content, current);
    const details = redactDeep(event.details, current);
    const structuredContent = redactDeep(event.structuredContent, current);
    if (content === event.content && details === event.details && structuredContent === event.structuredContent) return;
    return { content, details, structuredContent };
  });

  // Every message as it is finalized: what the model wrote, command output from "!", and messages
  // sent as is. This is also what gets saved to the session file. Tool calls are left alone: pi
  // runs them from this same message, and a command must receive the real value. The context hook
  // below still hides them from the model on later requests.
  pi.on("message_end", (event) => {
    const current = needles();
    if (current.length === 0) return;
    const original = event.message;
    if (original.role === "assistant") {
      const content = redactExceptToolCalls(original.content, current);
      return content === original.content ? undefined : { message: { ...original, content } };
    }
    const message = redactDeep(original, current);
    return message === original ? undefined : { message };
  });

  // Anything still in context from before a secret was stored, on every request.
  pi.on("context", (event) => {
    const current = needles();
    if (current.length === 0) return;
    const messages = redactDeep(event.messages, current);
    return messages === event.messages ? undefined : { messages };
  });

  // ---------------------------------------------------------------- /secrets
  const listText = (): string => {
    const secrets = store.list();
    if (secrets.length === 0) return "No stored secrets.";
    return secrets
      .map((secret) => `${secret.name}  ${secret.masked}  (${secret.source}, ${remaining(secret.expiresAt)})  ${tildePath(secret.file)}`)
      .join("\n");
  };

  pi.registerCommand("secrets", {
    description: "List, add, or delete stored secrets: /secrets [add <NAME>|rm <NAME>|clear]",
    getArgumentCompletions(prefix) {
      const [sub = "", arg] = prefix.split(/\s+/, 2);
      if (arg === undefined) {
        return ["list", "add", "rm", "clear"]
          .filter((name) => name.startsWith(sub))
          .map((name) => ({ value: name, label: name }));
      }
      if (sub !== "rm") return null;
      return store
        .list()
        .filter((secret) => secret.name.startsWith(arg.toUpperCase()))
        .map((secret) => ({ value: `rm ${secret.name}`, label: secret.name, description: secret.masked }));
    },
    async handler(args, ctx) {
      const [sub = "list", ...rest] = args.trim().split(/\s+/).filter(Boolean);
      const arg = rest.join(" ");

      if (sub === "list") {
        ctx.ui.notify(listText(), "info");
        return;
      }

      if (sub === "add") {
        if (ctx.mode !== "tui") {
          ctx.ui.notify("/secrets add needs the interactive terminal.", "error");
          return;
        }
        const name = toSecretName(arg || "SECRET");
        const result = await ctx.ui.custom<SecretPromptResult>(
          (tui, theme, keybindings, done) =>
            new SecretPrompt(
              tui,
              theme,
              keybindings,
              {
                label: name,
                reason: "Stored for the agent to use. Mention it by name and it can read the file in its commands.",
                lifetime: lifetime(ttlMs),
              },
              done,
            ),
          { blocked: { kind: "auth", message: `Add secret ${name}` } },
        );
        if (result.action !== "save") return;
        const value = normalizeSecretValue(result.value);
        const secret = store.save({
          value,
          name,
          label: name,
          masked: classifySecret(value)?.masked ?? "***",
          source: "add",
        });
        // Tell the model where it is, without the value.
        await pi.sendMessage(
          {
            customType: "pi-lockbox",
            content: `The user stored a secret named ${secret.name}. ${savedResultText(secret)}`,
            display: true,
            details: { name: secret.name },
          },
          { triggerTurn: false },
        );
        return;
      }

      if (sub === "rm") {
        const target = store.list().find((secret) => secret.name === arg.toUpperCase());
        if (!target) {
          ctx.ui.notify(`No stored secret named ${arg || "(none given)"}.`, "error");
          return;
        }
        store.remove(target.id);
        ctx.ui.notify(`Deleted ${target.name}.`, "info");
        return;
      }

      if (sub === "clear") {
        const count = store.list().length;
        if (count === 0) {
          ctx.ui.notify("No stored secrets.", "info");
          return;
        }
        const ok = await ctx.ui.confirm("Delete all stored secrets?", `${count} secret file(s) will be deleted.`);
        if (ok) ctx.ui.notify(`Deleted ${store.clear()} secret(s).`, "info");
        return;
      }

      ctx.ui.notify("Usage: /secrets [list | add <NAME> | rm <NAME> | clear]", "error");
    },
  });

  pi.registerMessageRenderer("pi-lockbox", (message, _options, theme) => {
    const name = (message.details as { name?: string } | undefined)?.name ?? "secret";
    return new Text(`${theme.fg("success", "🔒 Stored")} ${theme.fg("accent", name)} ${theme.fg("dim", "· the agent can use it by name")}`, 1, 0);
  });
}

function redactExceptToolCalls<T extends { type: string }>(content: T[], needles: Needle[]): T[] {
  let copy: T[] | undefined;
  content.forEach((block, i) => {
    if (block.type === "toolCall") return;
    const next = redactDeep(block, needles);
    if (next !== block) {
      copy ??= content.slice();
      copy[i] = next;
    }
  });
  return copy ?? content;
}
