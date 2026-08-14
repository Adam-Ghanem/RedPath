import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import VirtualizedDataList from "./VirtualizedDataList";

const records = Array.from({ length: 50 }, (_, index) => ({ id: `asset-${index + 1}`, label: `Asset ${index + 1}` }));

describe("virtualized analyst list", () => {
  it("renders an accessible bounded listbox window with active row metadata", () => {
    const markup = renderToStaticMarkup(<VirtualizedDataList ariaLabel="Asset results" items={records} activeKey="asset-2" getKey={(item) => item.id} onActiveChange={vi.fn()} renderItem={(item) => <span>{item.label}</span>} />);

    expect(markup).toContain('role="listbox"');
    expect(markup).toContain('aria-label="Asset results"');
    expect(markup).toContain('role="option"');
    expect(markup).toContain('aria-posinset="2"');
    expect(markup).toContain('aria-setsize="50"');
    expect(markup).toContain('aria-selected="true"');
    expect(markup).not.toContain("Asset 50");
  });
});
