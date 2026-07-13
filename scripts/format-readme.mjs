import { readFileSync, writeFileSync } from 'node:fs';

// Runs right after docgen. docgen renders each type-alias union as a whole-line inline
// `<code>'a' | 'b' | ...</code>`, which GitHub paints as a cramped grey pill that wraps
// mid-value. Rewrite those into a fenced ts block, one member per line. Inline <code> inside
// the interface tables is untouched (those lines start with `|`, not `<code>`).
const path = new URL('../README.md', import.meta.url);
const lines = readFileSync(path, 'utf8').split('\n');

const out = [];
let lastType = null;
for (const line of lines) {
  const header = line.match(/^#### (\w+)$/);
  if (header) lastType = header[1];

  const code = line.match(/^<code>(.+?)<\/code>$/);
  if (code && code[1].includes(' | ') && lastType) {
    const members = code[1].split(' | ');
    out.push('```ts');
    out.push(`type ${lastType} =`);
    members.forEach((m, i) => out.push(`  | ${m}${i === members.length - 1 ? ';' : ''}`));
    out.push('```');
    lastType = null;
    continue;
  }
  out.push(line);
}

writeFileSync(path, out.join('\n'));
