import { describe, it, expect } from "vitest";
import { isTestFile, filterFindingsForTestFile } from "../src/testFileHeuristic";
import { Finding } from "../src/analyser";

const mk = (ruleId: string): Finding => ({
  line: 0, col: 0, severity: "critical", ruleId, message: "", detail: "", cves: [],
});

describe("isTestFile", () => {
  it("matches common JS/TS test path patterns", () => {
    expect(isTestFile("src/__tests__/foo.ts")).toBe(true);
    expect(isTestFile("src/__mocks__/user.ts")).toBe(true);
    expect(isTestFile("test/integration/api.js")).toBe(true);
    expect(isTestFile("tests/unit.ts")).toBe(true);
    expect(isTestFile("spec/model_spec.js")).toBe(true);
    expect(isTestFile("e2e/checkout.spec.ts")).toBe(true);
    expect(isTestFile("cypress/integration/a.cy.js")).toBe(true);
    expect(isTestFile("playwright/home.spec.ts")).toBe(true);
    expect(isTestFile("fixtures/bad-code.ts")).toBe(true);
    expect(isTestFile("mocks/handlers.ts")).toBe(true);
  });

  it("matches *.test.* and *.spec.* suffixes", () => {
    expect(isTestFile("src/user.test.ts")).toBe(true);
    expect(isTestFile("src/user.test.tsx")).toBe(true);
    expect(isTestFile("src/api.spec.js")).toBe(true);
    expect(isTestFile("src/home.stories.tsx")).toBe(true);
  });

  it("matches Python test patterns", () => {
    expect(isTestFile("app/test_models.py")).toBe(true);
    expect(isTestFile("app/models_test.py")).toBe(true);
    expect(isTestFile("conftest.py")).toBe(true);
    expect(isTestFile("app/conftest.py")).toBe(true);
  });

  it("does NOT match production paths", () => {
    expect(isTestFile("src/index.ts")).toBe(false);
    expect(isTestFile("src/app/login.tsx")).toBe(false);
    expect(isTestFile("app/models.py")).toBe(false);
    expect(isTestFile("lib/utils.js")).toBe(false);
  });

  it("returns false for undefined / empty paths", () => {
    expect(isTestFile(undefined)).toBe(false);
    expect(isTestFile("")).toBe(false);
  });
});

describe("filterFindingsForTestFile", () => {
  const findings = [
    mk("eval-external"),
    mk("sql-concat"),
    mk("hardcoded-secret"),
    mk("bearer-token"),
  ];

  it("keeps ONLY credential findings in test files", () => {
    const out = filterFindingsForTestFile("src/user.test.ts", findings);
    expect(out.map((f) => f.ruleId).sort()).toEqual(["bearer-token", "hardcoded-secret"]);
  });

  it("keeps every finding in production files", () => {
    const out = filterFindingsForTestFile("src/user.ts", findings);
    expect(out.length).toBe(4);
  });

  it("is a no-op when filePath is undefined", () => {
    const out = filterFindingsForTestFile(undefined, findings);
    expect(out.length).toBe(4);
  });
});
