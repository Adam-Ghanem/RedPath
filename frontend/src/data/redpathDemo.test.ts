import { describe, expect, it } from "vitest";
import { attackPaths, coverageByTactic, overallCoverage, scenarioHasCompleteDetail, scenarios } from "./redpathDemo";

describe("RedPath demo contracts", () => {
  it("provides weighted, explorable attack paths", () => {
    expect(attackPaths).toHaveLength(3);
    expect(attackPaths.every((path) => path.cost > 0 && path.nodeIds.length >= 3 && path.edgeIds.length >= 2)).toBe(true);
  });

  it("derives the overall coverage score from tactic-level evidence", () => {
    expect(coverageByTactic).toHaveLength(4);
    expect(overallCoverage()).toBe(75);
  });

  it("keeps every safe playbook fully detailed and explicitly dry-run", () => {
    expect(scenarios).toHaveLength(4);
    expect(scenarios.every(scenarioHasCompleteDetail)).toBe(true);
    expect(scenarios.every((scenario) => scenario.reconPlan.every((command) => command.includes("dry-run")))).toBe(true);
  });
});
