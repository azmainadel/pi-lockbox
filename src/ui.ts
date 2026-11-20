// Terminal cards: the masked secret prompt and the paste guard.

import type { KeybindingsManager, Theme } from "@earendil-works/pi-coding-agent";
import {
  type Component,
  CURSOR_MARKER,
  decodeKittyPrintable,
  type Focusable,
  Key,
  matchesKey,
  renderFakeCursor,
  type TUI,
  truncateToWidth,
  visibleWidth,
  wrapTextWithAnsi,
} from "@earendil-works/pi-tui";

const PASTE_START = "\x1b[200~";
const PASTE_END = "\x1b[201~";
const segmenter = new Intl.Segmenter();

function graphemes(text: string): string[] {
  return [...segmenter.segment(text)].map((part) => part.segment);
}

/** The end of `text` that fits in `maxWidth` columns. */
function tail(text: string, maxWidth: number): string {
  const parts = graphemes(text);
  let out = "";
  for (let i = parts.length - 1; i >= 0; i--) {
    const next = parts[i] + out;
    if (visibleWidth(next) > maxWidth) break;
    out = next;
  }
  return out;
}

function hasControlCharacters(data: string): boolean {
  return [...data].some((ch) => {
    const code = ch.charCodeAt(0);
    return code < 32 || code === 0x7f || (code >= 0x80 && code <= 0x9f);
  });
}

function wrapped(text: string, width: number, style: (line: string) => string, indent = " "): string[] {
  return wrapTextWithAnsi(text, Math.max(10, width - indent.length)).map((line) => indent + style(line));
}

export interface SecretPromptView {
  label: string;
  reason: string;
  url?: string;
  /** How long commands can read the value, e.g. "24 hours". */
  lifetime: string;
}

export type SecretPromptResult = { action: "save"; value: string } | { action: "decline" } | { action: "cancel" };

/** A single masked field. The value is shown as dots until the user reveals it with Ctrl+R. */
export class SecretPrompt implements Component, Focusable {
  focused = false;
  private value = "";
  private revealed = false;
  private error: string | undefined;
  private inPaste = false;
  private pasteBuffer = "";
  private readonly tui: TUI;
  private readonly theme: Theme;
  private readonly keybindings: KeybindingsManager;
  private readonly view: SecretPromptView;
  private readonly done: (result: SecretPromptResult) => void;

  constructor(
    tui: TUI,
    theme: Theme,
    keybindings: KeybindingsManager,
    view: SecretPromptView,
    done: (result: SecretPromptResult) => void,
  ) {
    this.tui = tui;
    this.theme = theme;
    this.keybindings = keybindings;
    this.view = view;
    this.done = done;
  }

  handleInput(data: string): void {
    if (this.inPaste || data.includes(PASTE_START)) {
      this.handlePaste(data);
      return;
    }
    const kb = this.keybindings;
    if (kb.matches(data, "tui.select.cancel")) {
      this.done({ action: "decline" });
      return;
    }
    if (kb.matches(data, "tui.input.submit") || data === "\r" || data === "\n") {
      if (this.value.trim() === "") {
        this.error = "Enter a value, or press Esc to decline.";
      } else {
        this.done({ action: "save", value: this.value });
        return;
      }
    } else if (matchesKey(data, Key.ctrl("r"))) {
      this.revealed = !this.revealed;
    } else if (kb.matches(data, "tui.editor.deleteCharBackward")) {
      this.value = graphemes(this.value).slice(0, -1).join("");
    } else if (kb.matches(data, "tui.editor.deleteToLineStart") || kb.matches(data, "tui.editor.deleteWordBackward")) {
      this.value = "";
    } else {
      const printable = decodeKittyPrintable(data) ?? (hasControlCharacters(data) ? undefined : data);
      if (printable === undefined) return;
      this.value += printable;
    }
    if (this.value !== "") this.error = undefined;
    this.tui.requestRender();
  }

  private handlePaste(data: string): void {
    let chunk = data;
    if (!this.inPaste) {
      const at = chunk.indexOf(PASTE_START);
      const typedBefore = chunk.slice(0, at);
      if (typedBefore) this.handleInput(typedBefore);
      chunk = chunk.slice(at + PASTE_START.length);
      this.inPaste = true;
      this.pasteBuffer = "";
    }
    this.pasteBuffer += chunk;
    const end = this.pasteBuffer.indexOf(PASTE_END);
    if (end === -1) return;
    // Newlines are kept: private keys need them.
    this.value += this.pasteBuffer.slice(0, end).replace(/\r\n?/g, "\n");
    const rest = this.pasteBuffer.slice(end + PASTE_END.length);
    this.inPaste = false;
    this.pasteBuffer = "";
    this.error = undefined;
    this.tui.requestRender();
    if (rest) this.handleInput(rest);
  }

  private fieldLine(width: number): string {
    const t = this.theme;
    const prefix = ` ${t.fg("accent", "›")} `;
    const cursor = (this.focused ? CURSOR_MARKER : "") + renderFakeCursor(" ");
    const room = Math.max(4, width - visibleWidth(prefix) - 1);
    if (this.value === "") {
      return prefix + cursor + t.fg("dim", truncateToWidth("type or paste the value", room - 1, ""));
    }
    const count = graphemes(this.value).length;
    let shown = this.revealed ? this.value.replace(/\n/g, "⏎") : "•".repeat(count);
    if (visibleWidth(shown) > room) shown = `…${tail(shown, room - 1)}`;
    return prefix + shown + cursor;
  }

  render(width: number): string[] {
    const t = this.theme;
    const rule = t.fg("accent", "─".repeat(Math.max(1, width)));
    const lines = [
      rule,
      ` ${t.fg("accent", t.bold("🔒 Secret request"))}`,
      ` ${t.bold(this.view.label)}`,
      ...wrapped(this.view.reason, width, (line) => t.fg("muted", line)),
    ];
    if (this.view.url) lines.push(` ${t.fg("dim", "Get it:")} ${t.fg("accent", t.underline(this.view.url))}`);
    lines.push("", this.fieldLine(width));
    if (this.error) lines.push(` ${t.fg("error", this.error)}`);
    lines.push(
      "",
      ...wrapped(`Commands the agent runs can read this value for ${this.view.lifetime}.`, width, (line) =>
        t.fg("warning", line),
      ),
      ...wrapped("It never appears in the chat, the session file, or what the model sees.", width, (line) =>
        t.fg("dim", line),
      ),
      ` ${t.fg("dim", `Enter save · Ctrl+R ${this.revealed ? "hide" : "show"} · Esc decline`)}`,
      rule,
    );
    return lines.map((line) => truncateToWidth(line, width));
  }

  invalidate(): void {}
}

export type GuardChoice = "store" | "send" | "edit";

export interface GuardItem {
  label: string;
  masked: string;
}

export const GUARD_OPTIONS: ReadonlyArray<{ choice: GuardChoice; label: string; detail: string }> = [
  {
    choice: "store",
    label: "Store securely and send a reference",
    detail: "The model sees the masked form and a file path. Commands it runs can read the file.",
  },
  {
    choice: "send",
    label: "Send as is",
    detail: "The model provider receives the value, and it is saved in the session file.",
  },
  { choice: "edit", label: "Edit message", detail: "Go back to the editor with your message." },
];

/** Asks what to do with a message that contains secrets. */
export class GuardPrompt implements Component {
  private selected = 0;
  private readonly tui: TUI;
  private readonly theme: Theme;
  private readonly keybindings: KeybindingsManager;
  private readonly items: GuardItem[];
  private readonly done: (choice: GuardChoice) => void;

  constructor(
    tui: TUI,
    theme: Theme,
    keybindings: KeybindingsManager,
    items: GuardItem[],
    done: (choice: GuardChoice) => void,
  ) {
    this.tui = tui;
    this.theme = theme;
    this.keybindings = keybindings;
    this.items = items;
    this.done = done;
  }

  handleInput(data: string): void {
    const kb = this.keybindings;
    const count = GUARD_OPTIONS.length;
    if (kb.matches(data, "tui.select.up")) {
      this.selected = (this.selected + count - 1) % count;
    } else if (kb.matches(data, "tui.select.down")) {
      this.selected = (this.selected + 1) % count;
    } else if (kb.matches(data, "tui.select.confirm") || data === "\r") {
      this.done(GUARD_OPTIONS[this.selected].choice);
      return;
    } else if (kb.matches(data, "tui.select.cancel")) {
      this.done("edit");
      return;
    } else if (/^[1-3]$/.test(data)) {
      this.done(GUARD_OPTIONS[Number(data) - 1].choice);
      return;
    } else {
      return;
    }
    this.tui.requestRender();
  }

  render(width: number): string[] {
    const t = this.theme;
    const rule = t.fg("error", "─".repeat(Math.max(1, width)));
    const title =
      this.items.length === 1
        ? "Your message looks like it contains a secret"
        : `Your message looks like it contains ${this.items.length} secrets`;
    const lines = [rule, ` ${t.fg("error", t.bold(`⚠ ${title}`))}`];
    for (const item of this.items) {
      lines.push(`   ${t.fg("muted", `${item.label}:`)} ${item.masked}`);
    }
    lines.push("");
    GUARD_OPTIONS.forEach((option, index) => {
      const active = index === this.selected;
      const text = `${index + 1}. ${option.label}`;
      lines.push(active ? ` ${t.fg("accent", `› ${text}`)}` : `   ${text}`);
      if (active) lines.push(...wrapped(option.detail, width, (line) => t.fg("dim", line), "      "));
    });
    lines.push("", ` ${t.fg("dim", "↑↓ select · Enter confirm · Esc edit message")}`, rule);
    return lines.map((line) => truncateToWidth(line, width));
  }

  invalidate(): void {}
}
