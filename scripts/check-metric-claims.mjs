// A-12's gate: a performance number in the docs must come with the five elements, or be
// marked as a design target.
//
// The rule the plan sets is: every quantitative claim carries `(规模, 硬件, 负载, 基线, 定义)`,
// and **a number missing any of them must not be written into the documentation**. The original
// design wrote seven such numbers and described all of them as measured "in the lab / in
// production" with no scale, no hardware, no load, no baseline and no definition -- so none of
// them can be reproduced, and a reader cannot tell which are measurements and which are hopes.
//
// # How the rule is scoped, and why that took a calibration pass
//
// These documents contain hundreds of numbers, and almost none are performance claims: quota
// ceilings ("50% CPU"), port numbers, byte counts, versions, and reports of things that
// happened ("the build succeeded after 2 minutes 56 seconds"). A gate that flagged all of them
// would be a gate people learn to skip, and a skipped gate is worse than none because it also
// shows a green tick.
//
// So what is scanned for is narrow and stated here:
//
//   * a line must contain BOTH a claim verb (降低/提升/开销/耗时/延迟/吞吐/从 X 降至/实测 …)
//     AND a duration, rate or ratio unit;
//   * lines inside fenced code blocks are skipped -- a comment in a listing is not a claim;
//   * a `±` tolerance is skipped: that is a bound the code enforces, not a measurement;
//   * the five elements may appear anywhere in the surrounding paragraph, because a table row
//     has no room for them and a claim table explains itself above or below;
//   * the phrase 设计目标 / design target marks a number as an intention, which is allowed --
//     the rule is that a reader can tell a measurement from a target, not that targets are
//     forbidden.
//
// The calibration is not decoration: the first candidate rule flagged 23 lines of which most
// were reports of past events, and this one flags a handful, of which every one is a real claim.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');

// The unit alternation, and one trap in it worth recording.
//
// `\b` in a JavaScript regular expression is an ASCII word boundary: it is a boundary between
// `\w` and non-`\w`, and CJK characters are not `\w`. So `分\b` does **not** match `60 分。` --
// there is no boundary after 分 -- and the first version of this pattern therefore never fired
// on the single most common shape of claim in these documents. The counter-proof caught it:
// injecting "把安装耗时从 60 分降至 35 分" into a document left the gate exiting 0, which is
// the one outcome that would have made the gate useless while it showed a green tick.
//
// `分` and `秒` are written without a boundary; `s` keeps one, spelled as a negative lookahead
// so it means "seconds" rather than "the s in ms".
const UNIT = String.raw`(?:\d+(?:\.\d+)?\s*(?:ms|µs|us|ns|s(?![A-Za-z0-9])|秒|分钟|分|MB\/s|GB\/s|Mbps|iops|倍)|1000\s*%|\d+(?:\.\d+)?\s*%)`;
const CLAIM = String.raw`降至|降低|提升|提高|减少|下降|开销|耗时|延迟|吞吐|加速|从\s*\d|省下|缩短|实测`;
// An arrow only counts as a claim when it sits BETWEEN two quantities -- `60 分 → 35 分`.
// A bare `→` in these documents usually means "therefore", and the first version of this rule
// matched `→ **已死中继可被复活**；15 秒探测超时` in the upstream gap analysis, which is a
// logical implication followed later by a timeout, not a performance claim at all.
const ARROW = `${UNIT}[^\\n]{0,12}(?:→|->)[^\\n]{0,12}${UNIT}`;
const CLAIM_RE = new RegExp(`(?:${CLAIM})[^\\n]{0,40}${UNIT}|${UNIT}[^\\n]{0,40}(?:${CLAIM})|${ARROW}`);

const FIVE = ['规模', '硬件', '负载', '基线', '定义'];
const TARGET_MARK = /设计目标|design target|目标值/;

/** The documents the rule applies to. */
function documents() {
  const out = [path.join(ROOT, 'README.md')];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full);
        continue;
      }
      if (e.name.endsWith('.md')) out.push(full);
    }
  })(path.join(ROOT, 'docs'));
  return out.filter((f) => fs.existsSync(f));
}

const findings = [];
let scanned = 0;
for (const file of documents()) {
  scanned++;
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  let fenced = false;
  lines.forEach((line, i) => {
    if (/^\s*```/.test(line)) {
      fenced = !fenced;
      return;
    }
    if (fenced) return;
    if (line.includes('±')) return;
    if (!CLAIM_RE.test(line)) return;

    const window = lines.slice(Math.max(0, i - 8), i + 9).join('\n');
    const missing = FIVE.filter((k) => !window.includes(k));
    if (missing.length === 0) return;
    if (TARGET_MARK.test(window)) return;

    findings.push({
      file: path.relative(ROOT, file),
      line: i + 1,
      missing,
      text: line.trim().slice(0, 140),
    });
  });
}

console.log(`metric-claim gate over ${scanned} document(s)`);
if (findings.length === 0) {
  console.log('  ok   every performance claim carries the five elements or is marked a target');
  console.log('OK: no unreproducible numbers in the documentation.');
  process.exit(0);
}
for (const f of findings) {
  console.log(`  FAIL ${f.file}:${f.line}  missing ${f.missing.join('/')}`);
  console.log(`       ${f.text}`);
}
console.log(`\n${findings.length} claim(s) lack the five elements.`);
console.log('A number a reader cannot reproduce is not a measurement; either add the five');
console.log('elements, or mark it 设计目标 so a reader can tell it from one.');
process.exit(1);
