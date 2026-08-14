import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

type VirtualizedDataListProps<T> = {
  ariaLabel: string;
  items: T[];
  getKey: (item: T) => string;
  activeKey?: string;
  onActiveChange: (item: T) => void;
  renderItem: (item: T, active: boolean) => ReactNode;
  itemHeight?: number;
  viewportHeight?: number;
  overscan?: number;
};

export default function VirtualizedDataList<T>({
  ariaLabel,
  items,
  getKey,
  activeKey,
  onActiveChange,
  renderItem,
  itemHeight = 68,
  viewportHeight = 360,
  overscan = 4,
}: VirtualizedDataListProps<T>) {
  const [scrollTop, setScrollTop] = useState(0);
  const viewportRef = useRef<HTMLDivElement>(null);
  const visibleCount = Math.ceil(viewportHeight / itemHeight);
  const start = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
  const end = Math.min(items.length, start + visibleCount + overscan * 2);
  const visibleItems = useMemo(() => items.slice(start, end), [items, start, end]);
  const activeIndex = Math.max(0, items.findIndex((item) => getKey(item) === activeKey));

  useEffect(() => {
    if (!items.length || activeIndex < 0) return;
    const top = activeIndex * itemHeight;
    const bottom = top + itemHeight;
    if (top < scrollTop || bottom > scrollTop + viewportHeight) viewportRef.current?.scrollTo({ top, behavior: "auto" });
  }, [activeIndex, itemHeight, items.length, scrollTop, viewportHeight]);

  const moveActive = (nextIndex: number) => {
    const item = items[Math.min(items.length - 1, Math.max(0, nextIndex))];
    if (item) onActiveChange(item);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!items.length) return;
    if (event.key === "ArrowDown") { event.preventDefault(); moveActive(activeIndex + 1); }
    if (event.key === "ArrowUp") { event.preventDefault(); moveActive(activeIndex - 1); }
    if (event.key === "Home") { event.preventDefault(); moveActive(0); }
    if (event.key === "End") { event.preventDefault(); moveActive(items.length - 1); }
  };

  return <div
    ref={viewportRef}
    className="soc-virtual-list"
    role="listbox"
    aria-label={ariaLabel}
    aria-activedescendant={activeKey ? `virtual-row-${activeKey}` : undefined}
    tabIndex={0}
    onKeyDown={onKeyDown}
    onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    style={{ height: viewportHeight }}
  >
    <div style={{ height: items.length * itemHeight, position: "relative" }}>
      <div style={{ position: "absolute", top: start * itemHeight, left: 0, right: 0 }}>
        {visibleItems.map((item, index) => {
          const key = getKey(item);
          const itemIndex = start + index;
          const active = key === activeKey || (!activeKey && itemIndex === 0);
          return <div
            id={`virtual-row-${key}`}
            key={key}
            role="option"
            aria-selected={active}
            aria-posinset={itemIndex + 1}
            aria-setsize={items.length}
            className={`soc-virtual-list__row${active ? " is-selected" : ""}`}
            style={{ minHeight: itemHeight }}
            onClick={() => onActiveChange(item)}
          >{renderItem(item, active)}</div>;
        })}
      </div>
    </div>
  </div>;
}
