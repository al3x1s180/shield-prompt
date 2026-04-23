import { describe, it, expect } from "vitest";
import {
  commentRanges,
  isInComment,
  isInRange,
  filterFindingsInComments,
  filterFindingsInNonCode,
  tokenize,
  isCredentialRule,
  Range,
} from "../src/astLayer";
import { Finding } from "../src/analyser";

const mkFinding = (line: number, col: number, ruleId = "test"): Finding => ({
  line, col, severity: "warning", ruleId, message: "", detail: "", cves: [],
});

describe("commentRanges — JS/TS", () => {
  it("finds a single line comment", () => {
    const text = `const x = 1; // hello`;
    const ranges = commentRanges(text, "javascript");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("// hello");
  });

  it("finds a block comment", () => {
    const text = `const x = /* in between */ 1;`;
    const ranges = commentRanges(text, "javascript");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("/* in between */");
  });

  it("handles multi-line block comments", () => {
    const text = `a;\n/* line 1\n   line 2 */\nb;`;
    const ranges = commentRanges(text, "javascript");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("/* line 1\n   line 2 */");
  });

  it("does NOT treat // inside a string as a comment", () => {
    const text = `const url = "https://example.com"; const x = 1;`;
    const ranges = commentRanges(text, "javascript");
    expect(ranges.length).toBe(0);
  });

  it("does NOT treat # inside a JS string as a comment", () => {
    const text = `const x = "not # a comment"; // real comment`;
    const ranges = commentRanges(text, "javascript");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("// real comment");
  });

  it("handles template literals without mis-parsing // inside them", () => {
    const text = "const s = `https://a.com/${x}`; // real";
    const ranges = commentRanges(text, "typescript");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("// real");
  });

  it("returns multiple ranges in order", () => {
    const text = `// one\nconst x = 1; /* two */\n// three`;
    const ranges = commentRanges(text, "javascript");
    expect(ranges.length).toBe(3);
    // Must be sorted by start
    for (let i = 1; i < ranges.length; i++) {
      expect(ranges[i][0]).toBeGreaterThanOrEqual(ranges[i - 1][0]);
    }
  });
});

describe("commentRanges — Python", () => {
  it("finds a # line comment", () => {
    const text = `x = 1  # hello`;
    const ranges = commentRanges(text, "python");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("# hello");
  });

  it("does NOT treat # inside a string as a comment", () => {
    const text = `url = "https://example.com#section"`;
    const ranges = commentRanges(text, "python");
    expect(ranges.length).toBe(0);
  });

  it("skips over triple-quoted strings (so a # inside them is not a comment)", () => {
    const text = `doc = """not a # comment\nstill not"""\n# real`;
    const ranges = commentRanges(text, "python");
    expect(ranges.length).toBe(1);
    expect(text.slice(ranges[0][0], ranges[0][1])).toBe("# real");
  });
});

describe("commentRanges — unsupported language", () => {
  it("returns an empty list instead of throwing", () => {
    expect(commentRanges(`// still a comment?`, "rust")).toEqual([]);
    expect(commentRanges(`anything`, "plaintext")).toEqual([]);
  });
});

describe("isInComment — binary search", () => {
  const ranges: Range[] = [[5, 10], [20, 25], [100, 200]];

  it("returns true for offsets inside any range", () => {
    expect(isInComment(5, ranges)).toBe(true);
    expect(isInComment(7, ranges)).toBe(true);
    expect(isInComment(24, ranges)).toBe(true);
    expect(isInComment(150, ranges)).toBe(true);
  });

  it("returns false for offsets outside every range", () => {
    expect(isInComment(0, ranges)).toBe(false);
    expect(isInComment(10, ranges)).toBe(false); // end is exclusive
    expect(isInComment(19, ranges)).toBe(false);
    expect(isInComment(300, ranges)).toBe(false);
  });

  it("handles empty range list", () => {
    expect(isInComment(42, [])).toBe(false);
  });
});

describe("filterFindingsInComments — the headline behaviour", () => {
  it("drops a finding whose location is inside a // comment", () => {
    const text = `// Expected findings: crypto-sha1\nconst hash = crypto.createHash("sha1");`;
    // col pointing at "sha1" in the first line (comment)
    const inComment = mkFinding(0, text.indexOf("sha1"));
    // col pointing at "sha1" in the second line (real code)
    const inCode    = mkFinding(1, text.split("\n")[1].indexOf("sha1"));

    const result = filterFindingsInComments(text, "javascript", [inComment, inCode]);
    expect(result.length).toBe(1);
    expect(result[0]).toBe(inCode);
  });

  it("drops a finding whose location is inside a block comment", () => {
    const text = `/* NOTE: contains sha1 */\ncrypto.createHash("sha1")`;
    const inBlock = mkFinding(0, text.indexOf("sha1"));
    const inCode  = mkFinding(1, text.split("\n")[1].indexOf("sha1"));

    const result = filterFindingsInComments(text, "javascript", [inBlock, inCode]);
    expect(result.length).toBe(1);
    expect(result[0]).toBe(inCode);
  });

  it("keeps findings on lines that mix comment + code when the match is in the code part", () => {
    const text = `crypto.createHash("sha1"); // note: sha1 weak`;
    // Match at the "sha1" string literal (not the comment)
    const inCode = mkFinding(0, text.indexOf(`"sha1"`) + 1);
    const result = filterFindingsInComments(text, "javascript", [inCode]);
    expect(result.length).toBe(1);
  });

  it("returns input unchanged for unsupported languages", () => {
    const f = mkFinding(0, 0);
    const result = filterFindingsInComments("whatever", "rust", [f]);
    expect(result).toEqual([f]);
  });

  it("returns input unchanged when there are no comments in the text", () => {
    const text = `const x = 1;\nconst y = 2;`;
    const findings = [mkFinding(0, 0), mkFinding(1, 0)];
    const result = filterFindingsInComments(text, "javascript", findings);
    expect(result).toEqual(findings);
  });

  it("works on Python", () => {
    const text = `# note: sha1\nhashlib.sha1("")`;
    const inComment = mkFinding(0, text.indexOf("sha1"));
    const inCode    = mkFinding(1, text.split("\n")[1].indexOf("sha1"));
    const result = filterFindingsInComments(text, "python", [inComment, inCode]);
    expect(result.length).toBe(1);
    expect(result[0]).toBe(inCode);
  });
});

describe("tokenize — string tracking", () => {
  it("tracks single- and double-quoted strings, plus plain template literals (no interpolation)", () => {
    // Templates WITHOUT `${}` count as strings. Templates WITH `${}` don't —
    // they contain executable expressions and are not safe to filter by.
    const text = `const a = "hello"; const b = 'world'; const c = \`plain\`; const d = \`t\${x}\`;`;
    const { strings } = tokenize(text, "javascript");
    expect(strings.length).toBe(3);
    expect(text.slice(strings[0][0], strings[0][1])).toBe('"hello"');
    expect(text.slice(strings[1][0], strings[1][1])).toBe("'world'");
    expect(text.slice(strings[2][0], strings[2][1])).toBe("`plain`");
  });

  it("does NOT mark template literals containing ${} as strings (they are part-code)", () => {
    const text = "const q = `SELECT * FROM u WHERE id = ${req.body.id}`";
    const { strings } = tokenize(text, "javascript");
    expect(strings.length).toBe(0);
  });

  it("tracks triple-quoted and single-line strings in Python", () => {
    const text = `x = "short"\ny = """long\nstring"""`;
    const { strings } = tokenize(text, "python");
    expect(strings.length).toBe(2);
    expect(text.slice(strings[0][0], strings[0][1])).toBe('"short"');
    expect(text.slice(strings[1][0], strings[1][1])).toBe('"""long\nstring"""');
  });
});

describe("isCredentialRule", () => {
  it("flags credential-style ruleIds", () => {
    expect(isCredentialRule("hardcoded-secret")).toBe(true);
    expect(isCredentialRule("insecure-session-secret")).toBe(true);
    expect(isCredentialRule("django-hardcoded-secret")).toBe(true);
    expect(isCredentialRule("secret-in-url")).toBe(true);
    expect(isCredentialRule("aws-api-key")).toBe(true);
    expect(isCredentialRule("bearer-token")).toBe(true);
    expect(isCredentialRule("private-key-found")).toBe(true);
    expect(isCredentialRule("db-password-leak")).toBe(true);
  });

  it("does NOT flag behavior-style ruleIds", () => {
    expect(isCredentialRule("eval-external")).toBe(false);
    expect(isCredentialRule("sql-concat")).toBe(false);
    expect(isCredentialRule("weak-hash-sha1")).toBe(false);
    expect(isCredentialRule("prisma-raw-query-injection")).toBe(false);
    expect(isCredentialRule("express-no-helmet")).toBe(false);
  });
});

describe("filterFindingsInNonCode — strings + comments + credential exemption", () => {
  it("drops a non-credential finding inside a string literal", () => {
    // A rule that matches 'eval(' should NOT fire when 'eval(' appears inside
    // a string literal — that's just text, not executable code.
    const text = `const msg = "do not call eval() on user input";`;
    const f    = mkFinding(0, text.indexOf("eval("), "eval-external");
    const out  = filterFindingsInNonCode(text, "javascript", [f]);
    expect(out.length).toBe(0);
  });

  it("KEEPS a credential finding inside a string literal", () => {
    // This is the whole point: AWS keys etc. live inside strings, and MUST
    // be flagged there.
    const text = `const k = "AKIAIOSFODNN7EXAMPLE";`;
    const f    = mkFinding(0, text.indexOf("AKIA"), "hardcoded-secret");
    const out  = filterFindingsInNonCode(text, "javascript", [f]);
    expect(out.length).toBe(1);
  });

  it("still drops any finding inside a comment (credential or not)", () => {
    const text = `// key = AKIAIOSFODNN7EXAMPLE\nconst x = 1;`;
    const fCred    = mkFinding(0, text.indexOf("AKIA"), "hardcoded-secret");
    const fOther   = mkFinding(0, text.indexOf("key"), "eval-external");
    const out      = filterFindingsInNonCode(text, "javascript", [fCred, fOther]);
    // Both dropped: inside a comment, nothing executes.
    expect(out.length).toBe(0);
  });

  it("keeps the finding when it's in real code", () => {
    const text = `eval(userInput);`;
    const f    = mkFinding(0, 0, "eval-external");
    const out  = filterFindingsInNonCode(text, "javascript", [f]);
    expect(out.length).toBe(1);
  });

  it("works on Python strings", () => {
    // # inside a Python string isn't a comment — covered earlier.
    // Here: an eval-like keyword inside a Python string should drop.
    const text = `msg = "please don't exec() untrusted input"`;
    const f    = mkFinding(0, text.indexOf("exec("), "python-exec");
    const out  = filterFindingsInNonCode(text, "python", [f]);
    expect(out.length).toBe(0);
  });
});
