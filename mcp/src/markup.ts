/**
 * Plain text / small Markdown subset -> safe HTML for Hangar `description_html`
 * and `comment_html`. Plane sanitizes stored HTML with nh3 on its side
 * (apps/api/plane/utils/content_validator.py); this converter never lets caller
 * HTML through in the first place: every character of input is escaped and only
 * the tags generated here reach Hangar.
 *
 * Supported: paragraphs (blank-line separated, single newlines become <br>),
 * ATX headings (#..###), fenced code blocks, "-"/"*"/"+" and "1." lists,
 * "> " quotes, inline `code`, **bold**, *italic* or _italic_, and
 * [text](http(s)/mailto URL) links. Anything else is literal text.
 */

/**
 * Hangar records the real author (the MCP calls it as the logged-in user), so
 * the footer only says the text came through the MCP; it names nobody.
 */
export const FOOTER_TEXT = "— via MCP";

// A line shaped like a generated footer: an em dash, then "via MCP", then
// anything. That covers the current `— via MCP` and the retired
// `— via MCP por <name>` (which named a person). Removed from caller text
// wherever it appears, so a caller can neither stack footers nor forge an old
// attribution line naming someone else. Lines starting with "-" or "--" are
// ordinary list items/prose and are left alone.
const FOOTER_LINE = /^[ \t]*—[ \t]*via[ \t]+MCP(?![A-Za-z0-9_]).*$/i;

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const SAFE_LINK = /^(?:https?:\/\/[^\s<>"']+|mailto:[^\s<>"']+)$/i;

function inline(raw: string): string {
  // Split out code spans first so their content is not formatted.
  const parts = raw.split(/(`[^`\n]+`)/g);
  return parts
    .map((part) => {
      if (/^`[^`\n]+`$/.test(part)) return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
      // NUL never survives into text we emit, so it is a safe placeholder mark.
      let text = escapeHtml(part.replaceAll("\u0000", ""));
      // Links become placeholders first, so the emphasis rules below can never
      // rewrite characters inside an href (e.g. "_" or "*" in a URL).
      const links: string[] = [];
      text = text.replace(/\[([^\]\n]{1,500})\]\(([^)\s]{1,2000})\)/g, (match, label: string, href: string) => {
        // href was escaped with the rest; undo only &amp; to validate the URL shape.
        const url = href.replaceAll("&amp;", "&");
        if (!SAFE_LINK.test(url)) return match;
        links.push(`<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer nofollow">${label}</a>`);
        return `\u0000${links.length - 1}\u0000`;
      });
      text = text.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
      text = text.replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,;:!?]|$)/g, "$1<em>$2</em>");
      text = text.replace(/(^|[\s(])_([^_\n]+)_(?=[\s).,;:!?]|$)/g, "$1<em>$2</em>");
      // Intentional NUL placeholder mark (stripped from input above).
      // oxlint-disable-next-line no-control-regex
      return text.replace(/\u0000(\d+)\u0000/g, (_match, index: string) => links[Number(index)] ?? "");
    })
    .join("");
}

type Block =
  | { kind: "p"; lines: string[] }
  | { kind: "h"; level: number; text: string }
  | { kind: "code"; lines: string[] }
  | { kind: "ul" | "ol"; items: string[] }
  | { kind: "quote"; lines: string[] };

function parseBlocks(text: string): Block[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index] ?? "";
    if (!line.trim()) {
      index += 1;
      continue;
    }
    if (/^\s*```/.test(line)) {
      const code: string[] = [];
      index += 1;
      while (index < lines.length && !/^\s*```\s*$/.test(lines[index] ?? "")) {
        code.push(lines[index] ?? "");
        index += 1;
      }
      index += 1; // closing fence (or end of input)
      blocks.push({ kind: "code", lines: code });
      continue;
    }
    const heading = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      blocks.push({ kind: "h", level: Math.min(heading[1]!.length, 3), text: heading[2]! });
      index += 1;
      continue;
    }
    if (/^\s*[-*+]\s+/.test(line) || /^\s*\d{1,9}[.)]\s+/.test(line)) {
      const ordered = /^\s*\d/.test(line);
      const marker = ordered ? /^\s*\d{1,9}[.)]\s+/ : /^\s*[-*+]\s+/;
      const items: string[] = [];
      while (index < lines.length && marker.test(lines[index] ?? "")) {
        items.push((lines[index] ?? "").replace(marker, ""));
        index += 1;
      }
      blocks.push({ kind: ordered ? "ol" : "ul", items });
      continue;
    }
    if (/^\s*>/.test(line)) {
      const quoted: string[] = [];
      while (index < lines.length && /^\s*>/.test(lines[index] ?? "")) {
        quoted.push((lines[index] ?? "").replace(/^\s*>\s?/, ""));
        index += 1;
      }
      blocks.push({ kind: "quote", lines: quoted });
      continue;
    }
    const paragraph: string[] = [];
    while (
      index < lines.length &&
      (lines[index] ?? "").trim() &&
      !/^\s*(?:```|#{1,6}\s|[-*+]\s|\d{1,9}[.)]\s|>)/.test(lines[index] ?? "")
    ) {
      paragraph.push(lines[index] ?? "");
      index += 1;
    }
    if (paragraph.length === 0) {
      // Defensive: never loop forever on an unexpected line shape.
      paragraph.push(line);
      index += 1;
    }
    blocks.push({ kind: "p", lines: paragraph });
  }
  return blocks;
}

function renderBlock(block: Block): string {
  switch (block.kind) {
    case "p":
      return `<p>${block.lines.map((line) => inline(line.trim())).join("<br>")}</p>`;
    case "h":
      return `<h${block.level}>${inline(block.text)}</h${block.level}>`;
    case "code":
      return `<pre><code>${escapeHtml(block.lines.join("\n"))}</code></pre>`;
    case "ul":
    case "ol":
      return `<${block.kind}>${block.items.map((item) => `<li><p>${inline(item.trim())}</p></li>`).join("")}</${block.kind}>`;
    case "quote":
      return `<blockquote>${parseBlocks(block.lines.join("\n")).map(renderBlock).join("")}</blockquote>`;
  }
}

export function textToHtml(text: string): string {
  return parseBlocks(text).map(renderBlock).join("");
}

/** Removes every footer-shaped line, then trailing blank lines, from caller text. */
export function stripFooter(text: string): string {
  const lines = text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .filter((line) => !FOOTER_LINE.test(line));
  while (lines.length > 0 && !lines[lines.length - 1]!.trim()) lines.pop();
  return lines.join("\n");
}

export function footerHtml(): string {
  return `<p>${escapeHtml(FOOTER_TEXT)}</p>`;
}

/** Caller text -> HTML body with exactly one footer at the end. */
export function htmlWithFooter(text: string): string {
  const body = textToHtml(stripFooter(text));
  return `${body}${footerHtml()}`;
}

/**
 * Appends caller text (as safe HTML) and one footer after the stored
 * description HTML. The stored HTML is kept byte for byte; it was already
 * sanitized by Plane when it was saved (older footers in it stay as they were).
 */
export function appendWithFooter(existingHtml: string, text: string): string {
  return `${existingHtml}${textToHtml(stripFooter(text))}${footerHtml()}`;
}
