// How a stored secret appears in a message to the model: a tag naming the file that holds it.

export interface Referable {
  name: string;
  file: string;
  masked: string;
}

export const REFERENCE_NOTE =
  '(pi-lockbox: each <secret /> tag above stands for a value stored in an owner-only file. Use it only inside the command that needs it, e.g. "$(cat <file>)". Never print it or repeat it in replies.)';

const TAG_PATTERN = /<secret name="([^"]*)" file="([^"]*)" masked="([^"]*)" \/>/g;

function escapeAttribute(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function unescapeAttribute(text: string): string {
  return text.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

export function referenceTag(secret: Referable): string {
  return `<secret name="${escapeAttribute(secret.name)}" file="${escapeAttribute(secret.file)}" masked="${escapeAttribute(secret.masked)}" />`;
}

export function hasReference(text: string): boolean {
  TAG_PATTERN.lastIndex = 0;
  return TAG_PATTERN.test(text);
}

/** Adds the usage note once to a message that contains references. */
export function withReferenceNote(text: string): string {
  if (!hasReference(text) || text.includes(REFERENCE_NOTE)) return text;
  return `${text}\n\n${REFERENCE_NOTE}`;
}

/** Display form for the transcript: the masked shape and the name, without the file path or note. */
export function displayReferences(markdown: string): string {
  if (!markdown.includes("<secret ")) return markdown;
  return markdown
    .replace(`\n\n${REFERENCE_NOTE}`, "")
    .replace(REFERENCE_NOTE, "")
    .replace(TAG_PATTERN, (_tag, name: string, _file: string, masked: string) => {
      return `\`${unescapeAttribute(masked)}\` 🔒 *${unescapeAttribute(name)}*`;
    });
}
