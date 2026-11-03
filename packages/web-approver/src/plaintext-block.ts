/**
 * The exact hash-bound plaintext as a `<pre>` that wraps at any width without hiding anything and
 * without letting a wrapped tail pass for a field label.
 *
 * Each logical line is its own block (`.plaintext-line`) with a hanging indent. A line's first row
 * starts in column 0, where field labels (`cwd:`, `host:`, `raw:`) live. Every row produced by
 * wrapping a long or padded value starts indented, so no part of an untrusted value can begin a row
 * that looks like a label. This is the web analogue of the CLI approver's `↪` continuation rows.
 *
 * The text is set with `textContent` only. The newline that ends a line is kept inside its block,
 * so the element's `textContent` is exactly the input text.
 *
 * @see ../../approver/src/lib/render.ts (the CLI's continuation-row rule)
 * @see ../public/styles.css (`.plaintext-line`)
 */
export function plaintextBlock(text: string, className: string): HTMLPreElement {
  const pre = document.createElement("pre");
  pre.className = `${className} plaintext-block`;
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    const row = document.createElement("span");
    row.className = "plaintext-line";
    row.textContent = index < lines.length - 1 ? `${line}\n` : line;
    pre.append(row);
  });
  return pre;
}
