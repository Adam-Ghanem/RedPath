import { useCallback, useEffect, useState } from "react";

export type AnalystDetailView = "assets" | "detections" | "evidence" | "cases";
export type TelemetryFreshness = "fresh" | "stale" | "unavailable";

export type AnalystWorkspaceQuery = {
  view: AnalystDetailView;
  q: string;
  review: string;
  page: number;
  selected: string;
  saved: string;
};

export type SavedFilterContract = {
  id: string;
  label: string;
  description: string;
  query: Partial<Pick<AnalystWorkspaceQuery, "view" | "q" | "review">>;
  scope: "workspace" | "evidence" | "cases";
};

const detailViews: AnalystDetailView[] = ["assets", "detections", "evidence", "cases"];
const maxQueryLength = 96;
const maxPage = 10_000;
const safeSelectedId = /^[A-Za-z0-9._:/-]{0,128}$/;

export const savedFilters: SavedFilterContract[] = [
  { id: "all-records", label: "All records", description: "Clear the current workspace query.", query: {}, scope: "workspace" },
  { id: "review-backlog", label: "Evidence review backlog", description: "Open evidence awaiting review.", query: { view: "evidence", review: "unreviewed" }, scope: "evidence" },
  { id: "active-cases", label: "Active cases", description: "Open the case register for active work.", query: { view: "cases", q: "active" }, scope: "cases" },
  { id: "detection-catalog", label: "Detection catalog", description: "Open the read-only rule catalog.", query: { view: "detections" }, scope: "workspace" },
];

export const defaultWorkspaceQuery: AnalystWorkspaceQuery = {
  view: "assets",
  q: "",
  review: "all",
  page: 1,
  selected: "",
  saved: "all-records",
};

function safeText(value: string | null) {
  return (value ?? "").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, maxQueryLength);
}

function safePage(value: string | null) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) ? Math.min(maxPage, Math.max(1, parsed)) : 1;
}

export function parseWorkspaceQuery(hash = typeof window === "undefined" ? "" : window.location.hash): AnalystWorkspaceQuery {
  const queryStart = hash.indexOf("?");
  const params = new URLSearchParams(queryStart >= 0 ? hash.slice(queryStart + 1) : "");
  const candidateView = params.get("view") as AnalystDetailView | null;
  const selected = safeText(params.get("selected"));
  return {
    view: candidateView && detailViews.includes(candidateView) ? candidateView : defaultWorkspaceQuery.view,
    q: safeText(params.get("q")),
    review: safeText(params.get("review")) || defaultWorkspaceQuery.review,
    page: safePage(params.get("page")),
    selected: safeSelectedId.test(selected) ? selected : "",
    saved: safeText(params.get("saved")) || defaultWorkspaceQuery.saved,
  };
}

export function serializeWorkspaceQuery(query: AnalystWorkspaceQuery) {
  const params = new URLSearchParams();
  if (query.view !== defaultWorkspaceQuery.view) params.set("view", query.view);
  if (query.q) params.set("q", query.q);
  if (query.review !== defaultWorkspaceQuery.review) params.set("review", query.review);
  if (query.page > 1) params.set("page", String(query.page));
  if (query.selected) params.set("selected", query.selected);
  if (query.saved !== defaultWorkspaceQuery.saved) params.set("saved", query.saved);
  const encoded = params.toString();
  return `#analyst-console${encoded ? `?${encoded}` : ""}`;
}

export function useWorkspaceQueryState() {
  const [query, setQuery] = useState<AnalystWorkspaceQuery>(() => parseWorkspaceQuery());

  useEffect(() => {
    const syncFromHash = () => setQuery(parseWorkspaceQuery());
    window.addEventListener("hashchange", syncFromHash);
    return () => window.removeEventListener("hashchange", syncFromHash);
  }, []);

  const updateQuery = useCallback((patch: Partial<AnalystWorkspaceQuery>) => {
    setQuery((current) => {
      const next = { ...current, ...patch };
      if (patch.q !== undefined || patch.review !== undefined || patch.view !== undefined) {
        next.page = patch.page ?? 1;
        next.selected = patch.selected ?? "";
      }
      const nextHash = serializeWorkspaceQuery(next);
      if (window.location.hash !== nextHash) window.history.replaceState(null, "", nextHash);
      return next;
    });
  }, []);

  const applySavedFilter = useCallback((filterId: string) => {
    const filter = savedFilters.find((item) => item.id === filterId) ?? savedFilters[0];
    updateQuery({ ...filter.query, saved: filter.id, page: 1, selected: "" });
  }, [updateQuery]);

  return { query, updateQuery, applySavedFilter };
}

export function telemetryFreshness(refreshedAt: Date | undefined, now = Date.now(), staleAfterMs = 15 * 60 * 1000): TelemetryFreshness {
  if (!refreshedAt || Number.isNaN(refreshedAt.getTime())) return "unavailable";
  return now - refreshedAt.getTime() > staleAfterMs ? "stale" : "fresh";
}

export function useTelemetryFreshness(refreshedAt: Date | undefined) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 60_000);
    return () => window.clearInterval(interval);
  }, []);
  return telemetryFreshness(refreshedAt, now);
}

export function maskNetworkIdentity(value: string) {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    const [first, second] = value.split(".");
    return `${first}.${second}.•.•`;
  }
  if (value.includes(":")) return "[redacted IPv6 address]";
  return "[redacted network reference]";
}

export function redactDisplayText(value: string) {
  return value
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted email]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[redacted network]")
    .replace(/\b(?:Bearer|token|secret|password)\s+[A-Za-z0-9._-]{12,}\b/gi, "[redacted value]")
    .slice(0, 600);
}
