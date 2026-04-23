// Tiny heuristic for "is this file a test/fixture/mock file?".
//
// Why it matters for ShieldPrompt: test files routinely contain:
//   - Fake API keys, mock passwords, sample tokens  → false positive on secret rules
//   - Intentional eval(), child_process spawn, raw SQL → false positive on behavior rules
//   - Example vulnerable code used to verify the rule itself
//
// We ship with sensible defaults. Users can disable via
// shieldprompt.skipNoisyInTests: false if they have a weird setup.
//
// Behavior:
//   - Credential rules still fire even in test files (a real key is real)
//   - Non-credential rules ("eval-external", "sql-concat", etc.) are dropped
//     when the file looks like a test/fixture
//
// This is deliberately conservative — we'd rather miss an FP reduction in a
// file that isn't *really* a test, than accidentally hide a real finding.

import { isCredentialRule } from "./astLayer";
import { Finding } from "./analyser";

const TEST_PATH_PATTERNS: RegExp[] = [
  /(^|[\\/])__tests__[\\/]/i,
  /(^|[\\/])__mocks__[\\/]/i,
  /(^|[\\/])tests?[\\/]/i,
  /(^|[\\/])specs?[\\/]/i,
  /(^|[\\/])fixtures?[\\/]/i,
  /(^|[\\/])mocks?[\\/]/i,
  /(^|[\\/])e2e[\\/]/i,
  /(^|[\\/])cypress[\\/]/i,
  /(^|[\\/])playwright[\\/]/i,
  /(^|[\\/])storybook[\\/]/i,

  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /\.e2e\.[jt]sx?$/i,
  /\.stories\.[jt]sx?$/i,
  /test_[^\\/]+\.py$/i,
  /[^\\/]+_test\.py$/i,
  /conftest\.py$/i,
];

export function isTestFile(filePath: string | undefined): boolean {
  if (!filePath) return false;
  return TEST_PATH_PATTERNS.some((re) => re.test(filePath));
}

// Filters findings for test files: keeps credential rules, drops everything
// else. Returns the input unchanged when the file isn't a test.
export function filterFindingsForTestFile<T extends Finding>(
  filePath: string | undefined,
  findings: T[]
): T[] {
  if (!isTestFile(filePath)) return findings;
  return findings.filter((f) => isCredentialRule(f.ruleId));
}
