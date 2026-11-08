/**
 * ECharts option builders. The first four (horizontalBars, columns, matrixHeatmap, calendarHeatmap) are ported from
 * Mintverse web/src/charts/options.ts; the rest extend the same rules:
 *   - categorical series use slots 1-8 in fixed order, a 9th+ series is "Other"
 *   - one sequential hue for every heatmap / calendar / map
 *   - severity colours are reserved for severity and always ship with a label
 *   - hairline axes, value labels in text ink (not series colour), 4px rounded data-ends
 * Every builder takes resolved theme tokens (ECharts can't read CSS variables).
 */
import type { Tokens } from "../theme/echartsTheme";
import { escapeHtml as e, fmtDay, fmtNum, fmtYm } from "../lib/viz";
import { ISO2_TO_MAP, countryName } from "./countries";

const alpha = (hex: string, a: number) => {
  const h = hex.trim();
  if (!h.startsWith("#") || (h.length !== 7 && h.length !== 4)) return h;
  const full = h.length === 4 ? `#${h[1]}${h[1]}${h[2]}${h[2]}${h[3]}${h[3]}` : h;
  return `${full}${Math.round(a * 255).toString(16).padStart(2, "0")}`;
};
/** Relative luminance of a #rrggbb colour (0 dark … 1 light); non-hex → 0.5. */
export const luminance = (hex: string) => {
  const h = hex.trim().replace('#', '')
  if (h.length < 6) return 0.5
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}
/** Ink that stays legible on a filled mark. */
export const inkOn = (fill: string) => (luminance(fill) > 0.55 ? '#0b0b0b' : '#ffffff')

/** Colour for series slot i (0-based); beyond slot 8 → "other". */
export const slot = (t: Tokens, i: number) => (i < t.series.length ? t.series[i] : t.other);

const axisTooltip = (t: Tokens) => ({ trigger: "axis" as const, axisPointer: { type: "line" as const, lineStyle: { color: t.axis } } });

// --------------------------------------------------------------------------- ported from Mintverse

export interface BarItem { label: string; value: number; color?: string }

/** Ranked horizontal bars: one colour unless the bars carry meaning; largest on top, value at the bar end. */
export function horizontalBars(items: BarItem[], t: Tokens, opts: { unit?: string; labelWidth?: number; selected?: string; color?: string } = {}) {
  const unit = opts.unit ?? "";
  const dim = (label: string) => (opts.selected && opts.selected !== label ? 0.3 : 1);
  return {
    animationDuration: 400,
    grid: { left: 8, right: 44, top: 4, bottom: 4, containLabel: true },
    xAxis: { type: "value", show: false, max: (v: { max: number }) => Math.max(1, v.max) },
    yAxis: {
      type: "category", inverse: true, data: items.map((i) => i.label), axisLine: { show: false },
      axisLabel: { color: t.text2, fontSize: 12, width: opts.labelWidth ?? 120, overflow: "truncate" },
    },
    tooltip: { trigger: "item", formatter: (p: { name: string; value: number }) => `${e(p.name)}<br/><b>${fmtNum(p.value)}</b>${unit ? ` ${unit}` : ""}` },
    series: [{
      type: "bar",
      data: items.map((i) => ({ value: i.value, itemStyle: { color: i.color ?? opts.color ?? t.accent, opacity: dim(i.label) } })),
      barMaxWidth: 16, barCategoryGap: "38%", itemStyle: { borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: "right", color: t.text2, fontSize: 11, formatter: (p: { value: number }) => fmtNum(p.value) },
      emphasis: { itemStyle: { opacity: 0.85 } }, cursor: "pointer",
    }],
  };
}

export interface ColumnItem { label: string; value: number; color?: string; title?: string }

/** Vertical columns (histograms, per-period counts) with optional dashed marker. */
export function columns(items: ColumnItem[], t: Tokens, opts: { unit?: string; selected?: string; markLabel?: string; markText?: string; labelInterval?: number; color?: string; showValues?: boolean } = {}) {
  const unit = opts.unit ?? "";
  return {
    animationDuration: 400,
    grid: { left: 8, right: 8, top: 18, bottom: 4, containLabel: true },
    xAxis: { type: "category", data: items.map((i) => i.label), axisLabel: { color: t.text3, fontSize: 11, interval: opts.labelInterval ?? "auto", hideOverlap: true } },
    yAxis: { type: "value", minInterval: 1, axisLabel: { color: t.text3, fontSize: 11 }, splitLine: { lineStyle: { color: t.grid } } },
    tooltip: { trigger: "item", formatter: (p: { dataIndex: number; value: number }) => `${e(items[p.dataIndex].title ?? items[p.dataIndex].label)}<br/><b>${fmtNum(p.value)}</b>${unit ? ` ${unit}` : ""}` },
    series: [{
      type: "bar", barMaxWidth: 28, barCategoryGap: "22%", itemStyle: { borderRadius: [4, 4, 0, 0] }, cursor: "pointer",
      label: opts.showValues ? { show: true, position: "top", color: t.text2, fontSize: 11 } : undefined,
      data: items.map((i) => ({ value: i.value, itemStyle: { color: i.color ?? opts.color ?? t.accent, opacity: opts.selected && opts.selected !== i.label ? 0.3 : 1 } })),
      markLine: opts.markLabel ? {
        silent: true, symbol: "none", lineStyle: { color: t.text2, type: "dashed", width: 1 },
        label: { formatter: opts.markText ?? "now", color: t.text2, fontSize: 10, position: "insideEndTop" }, data: [{ xAxis: opts.markLabel }],
      } : undefined,
    }],
  };
}

/** Category × category matrix of counts on the single-hue sequential ramp. */
export function matrixHeatmap(
  xs: string[], ys: string[], cells: [number, number, number][], t: Tokens,
  opts: { unit: string; xFormat?: (x: string) => string; yWidth?: number; showValues?: boolean; selected?: { x?: string; y?: string } },
) {
  const max = Math.max(1, ...cells.map((c) => c[2]));
  const sel = opts.selected ?? {};
  return {
    animation: false,
    grid: { left: 8, right: 8, top: 8, bottom: 40, containLabel: true },
    xAxis: { type: "category", data: xs, axisLine: { show: false }, axisLabel: { color: t.text3, fontSize: 11, formatter: opts.xFormat }, splitArea: { show: false } },
    yAxis: { type: "category", data: ys, inverse: true, axisLine: { show: false }, triggerEvent: true, axisLabel: { color: t.text2, fontSize: 11, width: opts.yWidth ?? 110, overflow: "truncate" } },
    tooltip: { formatter: (p: { value: [number, number, number] }) => `${e(ys[p.value[1]])} · ${e(opts.xFormat ? opts.xFormat(xs[p.value[0]]) : xs[p.value[0]])}<br/><b>${fmtNum(p.value[2])}</b> ${opts.unit}` },
    visualMap: {
      type: "continuous", min: 0, max, orient: "horizontal", left: "center", bottom: 0, itemWidth: 10, itemHeight: 140,
      calculable: false, text: [String(max), "0"], textStyle: { color: t.text3, fontSize: 11 }, inRange: { color: [t.seq[0], t.seq[2], t.seq[4], t.seq[6]] },
    },
    series: [{
      type: "heatmap",
      data: cells.map((c) => {
        const dimmed = (sel.x && xs[c[0]] !== sel.x) || (sel.y && ys[c[1]] !== sel.y);
        const stop = [t.seq[0], t.seq[2], t.seq[4], t.seq[6]][Math.min(3, Math.round((c[2] / max) * 3))];
        return { value: c, itemStyle: { opacity: dimmed ? 0.25 : 1 }, label: { color: inkOn(stop) } };
      }),
      label: opts.showValues ? { show: true, fontSize: 10, formatter: (p: { value: [number, number, number] }) => (p.value[2] ? String(p.value[2]) : "") } : undefined,
      itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: 3 },
      emphasis: { itemStyle: { borderColor: t.text, borderWidth: 1 } }, cursor: "pointer",
    }],
  };
}

/** GitHub-style calendar of daily counts on the single-hue sequential ramp. */
export function calendarHeatmap(days: [string, number][], range: [string, string] | string, t: Tokens, unit: string, cellHeight = 13) {
  const max = Math.max(1, ...days.map((d) => d[1]));
  const step = (f: number) => Math.max(1, Math.round(max * f));
  const a = step(0.15), b = step(0.35), c = step(0.6);
  const pieces = max <= 4
    ? [{ value: 1, label: "1", color: t.seq[2] }, { value: 2, label: "2", color: t.seq[3] }, { value: 3, label: "3", color: t.seq[5] }, { min: 4, label: "4+", color: t.seq[6] }]
    : [{ min: 1, max: a, label: `1–${a}`, color: t.seq[2] }, { min: a + 1, max: b, label: `${a + 1}–${b}`, color: t.seq[3] }, { min: b + 1, max: c, label: `${b + 1}–${c}`, color: t.seq[5] }, { min: c + 1, label: `${c + 1}+`, color: t.seq[6] }];
  return {
    animation: false,
    tooltip: { formatter: (p: { value: [string, number] }) => `${fmtDay(p.value[0], { weekday: "short", month: "short", day: "numeric", year: "numeric" })}<br/><b>${fmtNum(p.value[1])}</b> ${unit}` },
    visualMap: { type: "piecewise", orient: "horizontal", right: 8, bottom: 0, itemWidth: 12, itemHeight: 12, itemGap: 6, textStyle: { color: t.text3, fontSize: 11 }, pieces },
    calendar: {
      range, top: 20, left: 30, right: 8, bottom: 34, cellSize: ["auto", cellHeight],
      itemStyle: { color: t.seq[0], borderColor: t.surface, borderWidth: 2 }, splitLine: { show: false },
      dayLabel: { firstDay: 1, nameMap: ["", "Mon", "", "Wed", "", "Fri", ""], color: t.text3, fontSize: 10 },
      monthLabel: { color: t.text3, fontSize: 10 }, yearLabel: { show: false },
    },
    series: [{ type: "heatmap", coordinateSystem: "calendar", data: days, cursor: "pointer" }],
  };
}

// --------------------------------------------------------------------------- time series

export interface SeriesSpec {
  name: string;
  data: (number | null)[];
  color?: string;
  type?: "line" | "bar";
  area?: boolean;
  stack?: string;
  dashed?: boolean;
  yAxisIndex?: 0 | 1;
}

/**
 * Multi-series time chart (lines, areas, stacked areas or bars on a shared category axis).
 * `xFormat` turns raw period keys (YYYY-MM or YYYY-MM-DD) into axis labels.
 */
export function timeSeries(x: string[], series: SeriesSpec[], t: Tokens, opts: {
  xFormat?: (x: string) => string; unit?: string; legend?: boolean; zoom?: boolean; rightAxisName?: string; markX?: string; markText?: string; percent?: boolean;
} = {}) {
  const xf = opts.xFormat ?? ((s: string) => (s.length === 7 ? fmtYm(s) : s.length === 10 ? fmtDay(s, { month: "short", day: "numeric" }) : s));
  const dual = series.some((s) => s.yAxisIndex === 1);
  const legend = opts.legend ?? series.length > 1;
  return {
    animationDuration: 500,
    grid: { left: 8, right: dual ? 8 : 12, top: legend ? 34 : 14, bottom: opts.zoom ? 40 : 4, containLabel: true },
    legend: legend ? { type: "scroll", top: 0, left: 0, right: 0, data: series.map((s) => s.name) } : undefined,
    tooltip: {
      ...axisTooltip(t),
      formatter: (ps: { seriesName: string; value: number | null; color: string; axisValue: string }[]) =>
        `${e(xf(ps[0]?.axisValue ?? ""))}<br/>` + ps.map((p) => `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${p.color};margin-right:6px"></span>${e(p.seriesName)} <b style="float:right;margin-left:14px">${p.value == null ? "—" : opts.percent ? `${p.value}%` : fmtNum(p.value)}</b>`).join("<br/>"),
    },
    xAxis: { type: "category", data: x, boundaryGap: series.some((s) => s.type === "bar"), axisLabel: { color: t.text3, fontSize: 11, formatter: xf, hideOverlap: true } },
    yAxis: [
      { type: "value", min: 0, minInterval: 1, max: opts.percent ? 100 : undefined, splitLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.text3, fontSize: 11, formatter: opts.percent ? "{value}%" : undefined } },
      ...(dual ? [{ type: "value", min: 0, name: opts.rightAxisName, nameTextStyle: { color: t.text3, fontSize: 10 }, splitLine: { show: false }, axisLabel: { color: t.text3, fontSize: 11 } }] : []),
    ],
    dataZoom: opts.zoom ? [{ type: "inside" }, { type: "slider", height: 18, bottom: 6, borderColor: t.grid, fillerColor: alpha(t.accent, 0.15), handleStyle: { color: t.accent }, textStyle: { color: t.text3 } }] : undefined,
    series: series.map((s, i) => {
      const color = s.color ?? slot(t, i);
      if (s.type === "bar") {
        return { name: s.name, type: "bar", data: s.data, stack: s.stack, yAxisIndex: s.yAxisIndex ?? 0, barMaxWidth: 26, itemStyle: { color, borderRadius: s.stack ? 0 : [4, 4, 0, 0] }, emphasis: { focus: "series" } };
      }
      return {
        name: s.name, type: "line", data: s.data, stack: s.stack, yAxisIndex: s.yAxisIndex ?? 0, smooth: 0.25, showSymbol: false, symbolSize: 6,
        lineStyle: { width: 2, color, type: s.dashed ? "dashed" : "solid" }, itemStyle: { color },
        areaStyle: s.area || s.stack ? { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: alpha(color, s.stack ? 0.55 : 0.28) }, { offset: 1, color: alpha(color, s.stack ? 0.35 : 0) }] } } : undefined,
        emphasis: { focus: "series" },
        markLine: i === 0 && opts.markX ? { silent: true, symbol: "none", lineStyle: { color: t.text3, type: "dashed", width: 1 }, label: { formatter: opts.markText ?? "", color: t.text3, fontSize: 10 }, data: [{ xAxis: opts.markX }] } : undefined,
      };
    }),
  };
}

/** 100%-stacked share-of-total columns per period (composition over time). */
export function shareColumns(x: string[], series: { name: string; data: number[] }[], t: Tokens, opts: { xFormat?: (x: string) => string } = {}) {
  const totals = x.map((_, i) => series.reduce((a, s) => a + (s.data[i] ?? 0), 0) || 1);
  return timeSeries(x, series.map((s, i) => ({
    name: s.name, type: "bar" as const, stack: "share",
    color: s.name === "Other" ? t.other : slot(t, i),
    data: s.data.map((v, j) => Math.round(((v ?? 0) / totals[j]) * 1000) / 10),
  })), t, { ...opts, percent: true, legend: true });
}

// --------------------------------------------------------------------------- composition

export interface PieItem { name: string; value: number; color?: string }

/** Donut with the total in the hole. Slices beyond 8 should be folded into "Other" by the caller. */
export function donut(items: PieItem[], t: Tokens, opts: { centerLabel?: string; unit?: string; legend?: "right" | "bottom" | false } = {}) {
  const total = items.reduce((a, i) => a + i.value, 0);
  const legendPos = opts.legend ?? "right";
  return {
    animationDuration: 500,
    tooltip: { trigger: "item", formatter: (p: { name: string; value: number; percent: number }) => `${e(p.name)}<br/><b>${fmtNum(p.value)}</b>${opts.unit ? ` ${opts.unit}` : ""} · ${p.percent}%` },
    legend: legendPos ? (legendPos === "right"
      ? { type: "scroll", orient: "vertical", right: 0, top: "middle", bottom: 4, itemGap: 8, textStyle: { color: t.text2, fontSize: 11 }, formatter: (n: string) => { const it = items.find((i) => i.name === n); return `${n}  ${it ? fmtNum(it.value) : ""}`; } }
      : { bottom: 0, left: "center", textStyle: { color: t.text2, fontSize: 11 } }) : undefined,
    graphic: [{
      type: "group", left: legendPos === "right" ? "27%" : "center", top: legendPos === "bottom" ? "40%" : "middle", bounding: "raw",
      children: [
        { type: "text", style: { text: fmtNum(total), x: 0, y: -10, fill: t.text, font: `650 22px ${t.font}`, align: "center", verticalAlign: "middle" } },
        { type: "text", style: { text: opts.centerLabel ?? "total", x: 0, y: 12, fill: t.text3, font: `11px ${t.font}`, align: "center", verticalAlign: "middle" } },
      ],
    }],
    series: [{
      type: "pie", radius: ["52%", "78%"], center: [legendPos === "right" ? "28%" : "50%", legendPos === "bottom" ? "42%" : "50%"],
      avoidLabelOverlap: true, label: { show: false }, labelLine: { show: false }, padAngle: 1.5,
      itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: 4 },
      data: items.map((i, idx) => ({ ...i, itemStyle: { color: i.color ?? (i.name === "Other" || i.name === "unknown" ? t.other : slot(t, idx)) } })),
      emphasis: { scale: true, scaleSize: 4 },
    }],
  };
}

export interface TreeNode { name: string; value?: number; children?: TreeNode[]; itemStyle?: Record<string, unknown> }

/** Treemap: area = volume. Top-level nodes get categorical slots; children inherit a lighter tint. */
export function treemap(nodes: TreeNode[], t: Tokens, opts: { unit?: string; levels?: number } = {}) {
  const coloured = nodes.map((n, i) => ({ ...n, itemStyle: { color: n.name === "Other" ? t.other : slot(t, i), ...(n.itemStyle ?? {}) } }));
  return {
    animationDuration: 500,
    tooltip: { formatter: (p: { treePathInfo: { name: string }[]; value: number }) => `${p.treePathInfo.slice(1).map((x) => e(x.name)).join(" › ")}<br/><b>${fmtNum(p.value)}</b>${opts.unit ? ` ${opts.unit}` : ""}` },
    series: [{
      type: "treemap", roam: false, nodeClick: "zoomToNode", left: 0, right: 0, top: 0, bottom: 22, width: "100%", height: "auto",
      breadcrumb: { show: true, height: 18, bottom: 0, left: 0, itemStyle: { color: t.surface2, borderColor: t.border, textStyle: { color: t.text2 } }, emphasis: { itemStyle: { color: t.grid } } },
      label: { show: true, color: "#fff", fontSize: 12, fontWeight: 600, formatter: (p: { name: string; value: number }) => `${p.name}\n${fmtNum(p.value)}`, lineHeight: 15 },
      upperLabel: { show: true, height: 22, color: "#fff", fontSize: 11, fontWeight: 600 },
      itemStyle: { borderColor: t.surface, borderWidth: 2, gapWidth: 2, borderRadius: 4 },
      levels: [
        { itemStyle: { borderColor: t.surface, borderWidth: 0, gapWidth: 3 }, upperLabel: { show: false } },
        { itemStyle: { borderColor: t.surface, borderWidth: 3, gapWidth: 2 }, colorSaturation: [0.35, 0.6], upperLabel: { show: true } },
        { colorSaturation: [0.3, 0.55], itemStyle: { borderColorSaturation: 0.7, gapWidth: 1, borderWidth: 1 } },
      ],
      data: coloured,
    }],
  };
}

/** Sunburst: hierarchy as rings (e.g. region › country, sector › size). */
export function sunburst(nodes: TreeNode[], t: Tokens, opts: { unit?: string } = {}) {
  const coloured = nodes.map((n, i) => ({ ...n, itemStyle: { color: n.name === "Other" ? t.other : slot(t, i) } }));
  return {
    animationDuration: 500,
    tooltip: { formatter: (p: { treePathInfo: { name: string }[]; value: number }) => `${p.treePathInfo.slice(1).map((x) => e(x.name)).join(" › ")}<br/><b>${fmtNum(p.value)}</b>${opts.unit ? ` ${opts.unit}` : ""}` },
    series: [{
      type: "sunburst", radius: ["14%", "92%"], sort: "desc", nodeClick: "rootToNode", data: coloured,
      itemStyle: { borderColor: t.surface, borderWidth: 2, borderRadius: 3 },
      label: { color: "#fff", fontSize: 10, minAngle: 10, rotate: "radial" },
      levels: [{}, { r0: "14%", r: "52%", label: { fontSize: 11 } }, { r0: "52%", r: "92%", itemStyle: { opacity: 0.85 }, label: { position: "outside", color: t.text2, fontSize: 10, minAngle: 6, rotate: 0 } }],
      emphasis: { focus: "ancestor" },
    }],
  };
}

// --------------------------------------------------------------------------- flows & networks

export interface SankeyNode { name: string; depth?: number; color?: string }
export interface SankeyLink { source: string; target: string; value: number }

/** Sankey flow (actor → sector → region, brand → kit → hosting). Node colour by column. */
export function sankey(nodes: SankeyNode[], links: SankeyLink[], t: Tokens, opts: { unit?: string; nodeWidth?: number } = {}) {
  const depthColor = [t.series[0], t.series[1], t.series[2], t.series[3], t.series[6]];
  return {
    animationDuration: 600,
    tooltip: {
      trigger: "item",
      formatter: (p: { dataType: string; name: string; value: number; data: SankeyLink }) =>
        p.dataType === "edge" ? `${e(p.data.source)} → ${e(p.data.target)}<br/><b>${fmtNum(p.value)}</b>${opts.unit ? ` ${opts.unit}` : ""}` : `${e(p.name)}<br/><b>${fmtNum(p.value)}</b>${opts.unit ? ` ${opts.unit}` : ""}`,
    },
    series: [{
      type: "sankey", left: 4, right: 150, top: 8, bottom: 8, nodeWidth: opts.nodeWidth ?? 12, nodeGap: 7, draggable: false, layoutIterations: 64,
      emphasis: { focus: "adjacency" },
      label: { color: t.text2, fontSize: 11, width: 140, overflow: "truncate", formatter: (p: { name: string; value: number }) => `${p.name}  {v|${fmtNum(p.value)}}`, rich: { v: { color: t.text3, fontSize: 10 } } },
      lineStyle: { color: "gradient", curveness: 0.5, opacity: 0.32 },
      itemStyle: { borderWidth: 0, borderRadius: 2 },
      data: nodes.map((n) => ({ name: n.name, depth: n.depth, itemStyle: { color: n.color ?? depthColor[(n.depth ?? 0) % depthColor.length] } })),
      links,
    }],
  };
}

export interface GraphNode { id: string; name: string; category: number; value?: number; symbolSize?: number; label?: string }
export interface GraphLink { source: string; target: string; value?: number }

/** Force-directed infrastructure graph (campaign ↔ domain ↔ IP ↔ ASN ↔ kit). Categories map to series slots. */
export function networkGraph(nodes: GraphNode[], links: GraphLink[], categories: string[], t: Tokens, opts: { repulsion?: number; gravity?: number; edgeLength?: number | [number, number]; labelMin?: number } = {}) {
  const maxV = Math.max(1, ...nodes.map((n) => n.value ?? 1));
  return {
    animationDurationUpdate: 600,
    legend: { type: "scroll", top: 0, left: 0, right: 0, data: categories, textStyle: { color: t.text2, fontSize: 11 } },
    tooltip: { formatter: (p: { dataType: string; data: GraphNode & GraphLink }) => (p.dataType === "edge" ? `${e(p.data.source)} — ${e(p.data.target)}` : `${e(categories[p.data.category])}<br/><b>${e(p.data.name)}</b>${p.data.value ? `<br/>${fmtNum(p.data.value)} samples` : ""}`) },
    series: [{
      type: "graph", layout: "force", top: 30, bottom: 4, left: 4, right: 4, roam: "move", draggable: true,
      force: { repulsion: opts.repulsion ?? 70, edgeLength: opts.edgeLength ?? [18, 55], gravity: opts.gravity ?? 0.22, friction: 0.2 },
      categories: categories.map((c, i) => ({ name: c, itemStyle: { color: slot(t, i) } })),
      data: nodes.map((n) => ({
        ...n, symbolSize: n.symbolSize ?? 8 + 22 * Math.sqrt((n.value ?? 1) / maxV),
        label: { show: (n.value ?? 0) >= (opts.labelMin ?? Infinity), formatter: n.label ?? n.name, color: t.text2, fontSize: 10, position: "right" },
        itemStyle: { borderColor: t.surface, borderWidth: 1.5 },
      })),
      links: links.map((l) => ({ ...l, lineStyle: { width: Math.min(4, 0.8 + (l.value ?? 1) * 0.3) } })),
      lineStyle: { color: t.axis, opacity: 0.7, curveness: 0.08 },
      emphasis: { focus: "adjacency", lineStyle: { width: 2.5, color: t.text3 } },
      labelLayout: { hideOverlap: true },
    }],
  };
}

/** Stream graph (ThemeRiver): volume per category over time, good for "who rose, who faded". */
export function streamGraph(rows: [string, number, string][], names: string[], t: Tokens, opts: { unit?: string } = {}) {
  return {
    animationDuration: 600,
    legend: { type: "scroll", top: 0, left: 0, right: 0, data: names, textStyle: { color: t.text2, fontSize: 11 } },
    tooltip: { trigger: "axis", axisPointer: { type: "line", lineStyle: { color: t.axis } } },
    singleAxis: { type: "time", top: 36, bottom: 24, left: 8, right: 8, axisLabel: { color: t.text3, fontSize: 11 }, axisLine: { lineStyle: { color: t.axis } }, splitLine: { show: true, lineStyle: { color: t.grid } }, axisPointer: { animation: true, label: { show: true, color: t.text } } },
    series: [{
      type: "themeRiver", data: rows, label: { show: false }, emphasis: { focus: "series" },
      color: names.map((n, i) => (n === "Other" ? t.other : slot(t, i))),
      itemStyle: { opacity: 0.9 },
      tooltip: { valueFormatter: (v: number) => `${fmtNum(v)}${opts.unit ? ` ${opts.unit}` : ""}` },
    }],
  };
}

/** Bump chart: rank of each entity per period (1 = top), lines crossing show who overtook whom. */
export function bumpChart(periods: string[], series: { name: string; ranks: (number | null)[] }[], t: Tokens, opts: { xFormat?: (x: string) => string; maxRank?: number } = {}) {
  const xf = opts.xFormat ?? fmtYm;
  const maxRank = opts.maxRank ?? Math.max(...series.flatMap((s) => s.ranks.filter((r): r is number => r != null)), 1);
  return {
    animationDuration: 600,
    grid: { left: 8, right: 96, top: 12, bottom: 4, containLabel: true },
    tooltip: { trigger: "item", formatter: (p: { seriesName: string; value: number; dataIndex: number }) => `${e(p.seriesName)}<br/>${e(xf(periods[p.dataIndex]))}: <b>#${p.value}</b>` },
    xAxis: { type: "category", data: periods, boundaryGap: false, axisLabel: { color: t.text3, fontSize: 11, formatter: xf }, splitLine: { show: true, lineStyle: { color: t.grid } } },
    yAxis: { type: "value", inverse: true, min: 1, max: maxRank, interval: 1, axisLabel: { color: t.text3, fontSize: 11, formatter: "#{value}" }, splitLine: { show: false } },
    series: series.map((s, i) => ({
      name: s.name, type: "line", data: s.ranks, smooth: 0.3, connectNulls: false, symbol: "circle", symbolSize: 9,
      lineStyle: { width: 3, color: slot(t, i) }, itemStyle: { color: slot(t, i), borderColor: t.surface, borderWidth: 2 },
      emphasis: { focus: "series", lineStyle: { width: 4 } },
      endLabel: { show: true, formatter: "{a}", color: t.text2, fontSize: 11, distance: 6 },
    })),
  };
}

// --------------------------------------------------------------------------- geo

/** World choropleth on the sequential ramp; countries with zero recede to the base fill. */
const EUROPE_ISO = new Set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE GB UK NO CH IS LI UA MD BY RS ME MK AL BA XK AD MC SM VA GI JE GG IM FO AX".split(" "));

export function worldChoropleth(items: { iso2: string; value: number }[], t: Tokens, opts: { unit: string; highlight?: string[]; zoomTo?: "europe" | "world" } = {} as { unit: string }) {
  const byName = new Map<string, { value: number; iso: string[] }>();
  for (const it of items) {
    const name = ISO2_TO_MAP[it.iso2?.toUpperCase()];
    if (!name) continue;
    const cur = byName.get(name) ?? { value: 0, iso: [] };
    cur.value += it.value;
    cur.iso.push(it.iso2.toUpperCase());
    byName.set(name, cur);
  }
  // In the Europe view the scale is fitted to European countries, so a large US count does not flatten them.
  const visible = opts.zoomTo === "europe" ? [...byName.values()].filter((v) => v.iso.some((c) => EUROPE_ISO.has(c))) : [...byName.values()];
  const max = Math.max(1, ...visible.map((v) => v.value));
  const hl = new Set((opts.highlight ?? []).map((c) => ISO2_TO_MAP[c.toUpperCase()]).filter(Boolean));
  const europe = opts.zoomTo === "europe";
  return {
    animation: false,
    tooltip: { trigger: "item", formatter: (p: { name: string; value: number; data?: { iso: string[] } }) => `${e(p.data?.iso?.[0] ? countryName(p.data.iso[0]) : p.name)}<br/><b>${Number.isFinite(p.value) ? fmtNum(p.value) : 0}</b> ${opts.unit}` },
    visualMap: {
      type: "continuous", min: 0, max, left: 8, bottom: 8, itemWidth: 10, itemHeight: 110, calculable: false,
      text: [fmtNum(max), "0"], textStyle: { color: t.text3, fontSize: 11 }, inRange: { color: [t.seq[1], t.seq[3], t.seq[5], t.seq[6]] }, outOfRange: { color: t.seq[0] },
    },
    series: [{
      type: "map", map: "world", roam: "move", scaleLimit: { min: 1, max: 12 },
      center: europe ? [14, 52] : undefined, zoom: europe ? 4.2 : 1.15,
      itemStyle: { areaColor: t.seq[0], borderColor: t.surface, borderWidth: 0.6 },
      emphasis: { label: { show: false }, itemStyle: { areaColor: t.series[3], borderColor: t.text, borderWidth: 1 } },
      select: { disabled: true },
      data: [
        ...[...byName.entries()].map(([name, v]) => ({ name, value: v.value, iso: v.iso, itemStyle: hl.has(name) ? { borderColor: t.text, borderWidth: 1.2 } : undefined })),
      ],
      nameMap: {},
    }],
  };
}

// --------------------------------------------------------------------------- profiles & gauges

/** Radar: multi-dimension profile (e.g. actor sector mix, kit capability markers). */
export function radar(indicators: { name: string; max: number }[], series: { name: string; values: number[] }[], t: Tokens) {
  return {
    animationDuration: 500,
    legend: series.length > 1 ? { bottom: 0, left: "center", textStyle: { color: t.text2, fontSize: 11 } } : undefined,
    tooltip: { trigger: "item" },
    radar: {
      indicator: indicators, radius: "56%", center: ["50%", series.length > 1 ? "46%" : "52%"], splitNumber: 4,
      axisName: { color: t.text2, fontSize: 10 }, splitLine: { lineStyle: { color: t.grid } }, splitArea: { show: false }, axisLine: { lineStyle: { color: t.grid } },
    },
    series: [{
      type: "radar", symbolSize: 5,
      data: series.map((s, i) => ({ name: s.name, value: s.values, lineStyle: { color: slot(t, i), width: 2 }, itemStyle: { color: slot(t, i) }, areaStyle: { color: alpha(slot(t, i), 0.22) } })),
    }],
  };
}

/** Pipeline funnel (collected → fetched → featurised → clustered → fingerprinted). */
export function funnel(stages: { name: string; value: number }[], t: Tokens) {
  const top = Math.max(1, stages[0]?.value ?? 1);
  return {
    animationDuration: 500,
    tooltip: { trigger: "item", formatter: (p: { name: string; value: number }) => `${e(p.name)}<br/><b>${fmtNum(p.value)}</b> · ${Math.round((p.value / top) * 100)}% of collected` },
    series: [{
      type: "funnel", left: 4, right: 4, top: 6, bottom: 6, minSize: "18%", maxSize: "100%", sort: "none", gap: 3,
      label: { show: true, position: "inside", fontSize: 12, fontWeight: 600, formatter: (p: { name: string; value: number }) => `${p.name}  ${fmtNum(p.value)}` },
      itemStyle: { borderColor: t.surface, borderWidth: 1, borderRadius: 4 },
      data: stages.map((s, i) => {
        const fill = [t.seq[6], t.seq[5], t.seq[4], t.seq[3], t.seq[2]][Math.min(i, 4)];
        return { ...s, itemStyle: { color: fill }, label: { color: inkOn(fill) } };
      }),
    }],
  };
}

/** Half-ring gauge for a ratio 0..1 (coverage, precision). Colour is the accent, never a severity. */
export function ratioGauge(value: number | null, t: Tokens, opts: { label: string; color?: string }) {
  const v = value == null ? 0 : Math.round(value * 1000) / 10;
  return {
    animationDuration: 700,
    series: [{
      type: "gauge", startAngle: 200, endAngle: -20, min: 0, max: 100, radius: "88%", center: ["50%", "56%"],
      progress: { show: true, width: 12, roundCap: true, itemStyle: { color: opts.color ?? t.accent } },
      axisLine: { lineStyle: { width: 12, color: [[1, t.grid]] }, roundCap: true },
      pointer: { show: false }, axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
      anchor: { show: false }, title: { show: true, offsetCenter: [0, "62%"], color: t.text3, fontSize: 11 },
      detail: { valueAnimation: true, offsetCenter: [0, "0%"], fontSize: 24, fontWeight: 650, color: t.text, formatter: value == null ? "—" : "{value}%" },
      data: [{ value: v, name: opts.label }],
    }],
  };
}

/** Bubble scatter: x/y numeric, bubble size = weight, colour = category slot. */
export function bubbles(points: { x: number; y: number; size: number; name: string; category?: number }[], t: Tokens, opts: { xName: string; yName: string; xLog?: boolean; yLog?: boolean; xFormat?: (v: number) => string; yFormat?: (v: number) => string; categories?: string[] }) {
  const maxS = Math.max(1, ...points.map((p) => p.size));
  const cats = opts.categories ?? ["points"];
  return {
    animationDuration: 500,
    grid: { left: 8, right: 16, top: cats.length > 1 ? 34 : 14, bottom: 24, containLabel: true },
    legend: cats.length > 1 ? { top: 0, left: 0, data: cats } : undefined,
    tooltip: { trigger: "item", formatter: (p: { data: { name: string; value: [number, number, number] } }) => `<b>${e(p.data.name)}</b><br/>${e(opts.xName)}: ${opts.xFormat ? opts.xFormat(p.data.value[0]) : fmtNum(p.data.value[0])}<br/>${e(opts.yName)}: ${opts.yFormat ? opts.yFormat(p.data.value[1]) : fmtNum(p.data.value[1])}` },
    xAxis: { type: opts.xLog ? "log" : "value", name: opts.xName, nameLocation: "middle", nameGap: 26, nameTextStyle: { color: t.text3, fontSize: 11 }, splitLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.text3, fontSize: 11, formatter: opts.xFormat } },
    yAxis: { type: opts.yLog ? "log" : "value", name: opts.yName, nameTextStyle: { color: t.text3, fontSize: 11 }, splitLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.text3, fontSize: 11, formatter: opts.yFormat } },
    series: cats.map((c, ci) => ({
      name: c, type: "scatter",
      data: points.filter((p) => (p.category ?? 0) === ci).map((p) => ({ name: p.name, value: [p.x, p.y, p.size] })),
      symbolSize: (v: [number, number, number]) => 8 + 30 * Math.sqrt(v[2] / maxS),
      itemStyle: { color: alpha(slot(t, ci), 0.75), borderColor: slot(t, ci), borderWidth: 1 },
      emphasis: { focus: "series", itemStyle: { color: slot(t, ci) } },
    })),
  };
}

/** Box plot of a numeric distribution per category (e.g. access price by access type). */
export function boxplot(categories: string[], samples: number[][], t: Tokens, opts: { yName?: string; yFormat?: (v: number) => string; log?: boolean } = {}) {
  const q = (arr: number[], p: number) => {
    const a = [...arr].sort((x, y) => x - y);
    if (!a.length) return 0;
    const idx = (a.length - 1) * p;
    const lo = Math.floor(idx), hi = Math.ceil(idx);
    return a[lo] + (a[hi] - a[lo]) * (idx - lo);
  };
  const boxes = samples.map((s) => (s.length ? [Math.min(...s), q(s, 0.25), q(s, 0.5), q(s, 0.75), Math.max(...s)] : [0, 0, 0, 0, 0]));
  const points = samples.flatMap((s, ci) => s.map((v) => [ci, v]));
  return {
    animationDuration: 500,
    grid: { left: 8, right: 12, top: 14, bottom: 4, containLabel: true },
    tooltip: { trigger: "item", formatter: (p: { seriesType: string; name: string; value: number[]; data: number[] }) => p.seriesType === "boxplot" ? `${e(p.name)}<br/>min ${opts.yFormat?.(p.value[1]) ?? p.value[1]} · median <b>${opts.yFormat?.(p.value[3]) ?? p.value[3]}</b> · max ${opts.yFormat?.(p.value[5]) ?? p.value[5]}` : `${e(categories[p.data[0]])}: <b>${opts.yFormat?.(p.data[1]) ?? p.data[1]}</b>` },
    xAxis: { type: "category", data: categories, axisLabel: { color: t.text2, fontSize: 11, interval: 0, hideOverlap: true } },
    yAxis: { type: opts.log ? "log" : "value", name: opts.yName, nameTextStyle: { color: t.text3, fontSize: 11 }, splitLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.text3, fontSize: 11, formatter: opts.yFormat } },
    series: [
      { type: "boxplot", data: boxes, itemStyle: { color: alpha(t.accent, 0.18), borderColor: t.accent, borderWidth: 1.5 }, boxWidth: [10, 34] },
      { type: "scatter", data: points, symbolSize: 7, itemStyle: { color: t.series[3], opacity: 0.85, borderColor: t.surface, borderWidth: 1 }, z: 3 },
    ],
  };
}

/** Tiny inline sparkline (KPI tiles, table cells). SVG renderer recommended. */
export function sparkline(values: number[], t: Tokens, opts: { color?: string; area?: boolean; labels?: string[] } = {}) {
  const color = opts.color ?? t.accent;
  return {
    animation: false,
    grid: { left: 2, right: 2, top: 3, bottom: 2 },
    xAxis: { type: "category", show: false, data: opts.labels ?? values.map((_, i) => String(i)), boundaryGap: false },
    yAxis: { type: "value", show: false, min: 0 },
    tooltip: opts.labels ? { trigger: "axis", axisPointer: { type: "line", lineStyle: { color: t.axis } }, formatter: (p: { axisValue: string; value: number }[]) => `${e(opts.labels!.length && opts.labels![0].length === 7 ? fmtYm(p[0].axisValue) : p[0].axisValue)}<br/><b>${fmtNum(p[0].value)}</b>` } : undefined,
    series: [{
      type: "line", data: values, smooth: 0.25, showSymbol: false, symbolSize: 5, lineStyle: { width: 1.8, color }, itemStyle: { color },
      areaStyle: opts.area === false ? undefined : { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: alpha(color, 0.3) }, { offset: 1, color: alpha(color, 0) }] } },
    }],
  };
}

/** Fold a ranked list into top N + "Other". */
export function topN<T extends { name: string; value: number }>(items: T[], n = 8): { name: string; value: number }[] {
  const sorted = [...items].sort((a, b) => b.value - a.value);
  const head = sorted.slice(0, n).map(({ name, value }) => ({ name, value }));
  const rest = sorted.slice(n).reduce((a, i) => a + i.value, 0);
  return rest > 0 ? [...head, { name: "Other", value: rest }] : head;
}
