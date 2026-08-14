import { describe, expect, it } from "vitest";
import { maskNetworkIdentity, parseWorkspaceQuery, redactDisplayText, savedFilters, serializeWorkspaceQuery, telemetryFreshness } from "./workspace-state";

describe("analyst workspace state", () => {
  it("parses and serializes only bounded URL-safe query values", () => {
    const parsed = parseWorkspaceQuery("#analyst-console?view=evidence&q=DNS%20review&page=99999&selected=evidence-01&review=unreviewed&saved=review-backlog");
    expect(parsed).toEqual({ view: "evidence", q: "DNS review", page: 10000, selected: "evidence-01", review: "unreviewed", saved: "review-backlog" });
    expect(serializeWorkspaceQuery(parsed)).toContain("view=evidence");
    expect(serializeWorkspaceQuery(parsed)).toContain("q=DNS+review");
    expect(parseWorkspaceQuery("#analyst-console?view=unknown&selected=%3Cscript%3E")).toMatchObject({ view: "assets", selected: "" });
  });

  it("ships stable saved-filter contracts and classifies stale telemetry", () => {
    expect(savedFilters.map((filter) => filter.id)).toContain("review-backlog");
    expect(telemetryFreshness(new Date(1_000), 1_000 + 10 * 60 * 1000)).toBe("fresh");
    expect(telemetryFreshness(new Date(1_000), 1_000 + 16 * 60 * 1000)).toBe("stale");
    expect(telemetryFreshness(undefined)).toBe("unavailable");
  });

  it("masks network identifiers and redacts accidental sensitive display text", () => {
    expect(maskNetworkIdentity("192.0.2.44")).toBe("192.0.•.•");
    expect(maskNetworkIdentity("2001:db8::1")).toBe("[redacted IPv6 address]");
    expect(redactDisplayText("owner@example.test from 192.0.2.44 Bearer superlongtokenvalue")).toContain("[redacted email]");
    expect(redactDisplayText("owner@example.test from 192.0.2.44 Bearer superlongtokenvalue")).not.toContain("superlongtokenvalue");
  });
});
