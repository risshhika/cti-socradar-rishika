import { useRef, useState, type CSSProperties, type ReactNode, type RefObject } from "react";
import { ImageDown, Table2 } from "lucide-react";
import clsx from "clsx";
import s from "./ChartCard.module.css";
import { Badge, EmptyState, ErrorState, Skeleton } from "./index";
import type { EChartHandle } from "../../charts/EChart";
import { fmtDay as fmtDate } from "../../lib/viz";

export interface TableTwin {
  columns: string[];
  rows: (string | number)[][];
}

interface QueryState {
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  isFetching?: boolean;
  refetch?: () => unknown;
}

interface Props {
  title: string;
  /** The analyst question this visual answers (shown as the subtitle). */
  question: string;
  source: string;
  asOf?: string | null;
  caveat?: ReactNode;
  stale?: boolean;
  query: QueryState;
  empty?: boolean;
  emptyText?: string;
  height: number;
  /** Accessible table twin of the chart (every chart has one). */
  table?: TableTwin;
  /** Render the visual; receive a handle to wire PNG export into the EChart. */
  render: (handle: RefObject<EChartHandle | null>) => ReactNode;
  actions?: ReactNode;
  style?: CSSProperties;
  pngName?: string;
  /** false for panels whose body is already a table/list */
  png?: boolean;
  className?: string;
}

export function ChartCard({
  title, question, source, asOf, caveat, stale, query, empty, emptyText, height, table, render, actions, style, pngName, png = true, className,
}: Props) {
  const [showTable, setShowTable] = useState(false);
  const handle = useRef<EChartHandle | null>(null);

  const savePng = () => {
    const url = handle.current?.toDataURL();
    if (!url) return;
    const a = Object.assign(document.createElement("a"), { href: url, download: `${pngName ?? title.toLowerCase().replace(/\W+/g, "-")}.png` });
    a.click();
  };

  let body: ReactNode;
  if (query.isLoading) body = <Skeleton height={height} />;
  else if (query.isError) body = <div style={{ minHeight: height }}><ErrorState error={query.error} onRetry={query.refetch ? () => query.refetch?.() : undefined} /></div>;
  else if (empty) body = <div style={{ minHeight: height, display: "grid" }}><EmptyState title={emptyText ?? "No data for this period"} /></div>;
  else if (showTable && table) body = <TableView table={table} height={height} />;
  else body = render(handle);

  return (
    <section className={clsx(s.card, className)} style={style} aria-label={title}>
      <div className={s.head}>
        <div className={s.titles}>
          <h2 className={s.title}>{title}</h2>
          <div className={s.question}>{question}</div>
        </div>
        <div className={s.actions}>
          {actions}
          {table && (
            <button
              className="icon-btn"
              aria-pressed={showTable}
              onClick={() => setShowTable((v) => !v)}
              title={showTable ? "Show chart" : "Show as table"}
              aria-label={showTable ? "Show chart" : "Show as table"}
            >
              <Table2 size={15} />
            </button>
          )}
          {png && (
            <button className="icon-btn" onClick={savePng} title="Save as PNG" aria-label="Save as PNG" disabled={showTable}>
              <ImageDown size={15} />
            </button>
          )}
        </div>
      </div>
      <div className={s.body} data-refetching={!!query.isFetching && !query.isLoading}>
        {body}
      </div>
      <div className={s.foot}>
        <span>
          Source: <b>{source}</b>
        </span>
        {asOf && <span className={s.sep}>as of {fmtDate(asOf)}</span>}
        {caveat && <span className={s.sep}>{caveat}</span>}
        {stale && (
          <span style={{ marginLeft: "auto" }}>
            <Badge tone="warn">Stale data</Badge>
          </span>
        )}
      </div>
    </section>
  );
}

function TableView({ table, height }: { table: TableTwin; height: number }) {
  return (
    <div className={s.tableView} style={{ minHeight: height, maxHeight: Math.max(height, 240) }}>
      <table>
        <thead>
          <tr>
            {table.columns.map((c) => (
              <th key={c} scope="col">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((r, i) => (
            <tr key={i}>
              {r.map((v, j) => (
                <td key={j}>{typeof v === "number" ? v.toLocaleString() : v}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
