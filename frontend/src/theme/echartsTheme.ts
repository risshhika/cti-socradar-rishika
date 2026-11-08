// No ECharts import here: this module is used by the app shell, and ECharts
// should only load with the pages that draw charts.

/** Resolved token values (ECharts can't read CSS variables, so we resolve them). */
export interface Tokens {
  surface: string;
  surface2: string;
  border: string;
  text: string;
  text2: string;
  text3: string;
  grid: string;
  axis: string;
  accent: string;
  series: string[];
  other: string;
  seq: string[];
  sev: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN", string>;
  good: string;
  font: string;
}

/** Tokens as resolved on `el` (the root by default; a `.force-dark` subtree gives dark ones). */
export function readTokens(el: Element = document.documentElement): Tokens {
  const cs = getComputedStyle(el);
  const v = (name: string) => cs.getPropertyValue(name).trim();
  return {
    surface: v("--surface-1"),
    surface2: v("--surface-2"),
    border: v("--border-strong"),
    text: v("--text"),
    text2: v("--text-2"),
    text3: v("--text-3"),
    grid: v("--grid"),
    axis: v("--axis"),
    accent: v("--accent"),
    series: [1, 2, 3, 4, 5, 6, 7, 8].map((i) => v(`--series-${i}`)),
    other: v("--series-other"),
    seq: [0, 1, 2, 3, 4, 5, 6].map((i) => v(`--seq-${i}`)),
    sev: {
      CRITICAL: v("--sev-critical"),
      HIGH: v("--sev-high"),
      MEDIUM: v("--sev-medium"),
      LOW: v("--sev-low"),
      UNKNOWN: v("--sev-unknown"),
    },
    good: v("--good"),
    font: v("--font"),
  };
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
/** Deep merge; `over` wins, arrays are replaced. */
function merge(base: Obj, over: Obj): Obj {
  const out: Obj = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(out[k]) ? merge(out[k] as Obj, v) : v;
  return out;
}

/**
 * ECharts 6 changed its default theme (legend at the bottom, grid margins,
 * calendar label margins, bar gap, ...) and its axis layout. The charts were
 * designed on the v5 defaults, so these are restored underneath our theme: the
 * entries of `echarts/theme/v5.js` for the series and components we use (that
 * file is a UMD script, so it can't be imported through `echarts/core`).
 */
const v5Axis = (extra: Obj = {}) => ({
  axisLine: { lineStyle: { color: "#6E7079" } },
  splitLine: { lineStyle: { color: ["#E0E6F1"] } },
  splitArea: { areaStyle: { color: ["rgba(250,250,250,0.2)", "rgba(210,219,238,0.2)"] } },
  minorSplitLine: { color: "#F4F7FD" },
  // v6 moves axis names clear of labels and keeps bars' edge shapes inside the grid; v5 did neither
  nameMoveOverlap: false,
  containShape: false,
  ...extra,
});
const V5_DEFAULTS: Obj = {
  gradientColor: ["#f6efa6", "#d88273", "#bf444c"],
  // v6 rich-text segments inherit the plain label's font; v5 rich segments did not
  richInheritPlainLabel: false,
  bar: { defaultBarGap: "20%", select: { itemStyle: { borderColor: "#212121", borderWidth: 1 } } },
  graph: { lineStyle: { color: "#aaa" }, select: { itemStyle: { borderColor: "#212121" } } },
  heatmap: { select: { itemStyle: { borderColor: "#212121" } } },
  line: { symbolSize: 4 },
  sankey: { lineStyle: { color: "#314656" }, select: { itemStyle: { borderColor: "#212121" } } },
  scatter: { select: { itemStyle: { borderColor: "#212121" } } },
  treemap: {
    left: "center", top: "middle", width: "80%", height: "80%",
    scaleLimit: { max: null, min: null },
    breadcrumb: {
      top: "bottom", bottom: null,
      itemStyle: { color: "rgba(0,0,0,0.7)", textStyle: { color: "#fff" } },
      emphasis: { itemStyle: { color: "rgba(0,0,0,0.9)" } },
    },
  },
  timeAxis: v5Axis(),
  logAxis: v5Axis(),
  valueAxis: v5Axis(),
  categoryAxis: v5Axis({ axisTick: { show: true } }),
  axisPointer: {
    lineStyle: { color: "#B9BEC9" },
    shadowStyle: { color: "rgba(210,219,238,0.2)" },
    label: { backgroundColor: "auto", color: "#fff" },
    handle: { color: "#333", shadowBlur: 3, shadowColor: "#aaa", shadowOffsetX: 0, shadowOffsetY: 2 },
  },
  calendar: {
    splitLine: { lineStyle: { color: "#000" } },
    itemStyle: { borderColor: "#ccc" },
    dayLabel: { margin: "50%", color: "#000" },
    monthLabel: { margin: 5, color: "#000" },
    yearLabel: { margin: 30, color: "#ccc" },
  },
  geo: {
    defaultItemStyleColor: "#eee",
    label: { color: "#000" },
    itemStyle: { borderColor: "#444" },
    emphasis: { label: { color: "rgb(100,0,0)" }, itemStyle: { color: "rgba(255,215,0,0.8)" } },
    select: { label: { color: "rgb(100,0,0)" }, itemStyle: { color: "rgba(255,215,0,0.8)" } },
  },
  // v6 also shrinks the grid to keep axis labels on the canvas; v5 didn't
  grid: { left: "10%", top: 60, bottom: 70, borderColor: "#ccc", outerBoundsMode: "none" },
  legend: {
    top: 0, bottom: null,
    backgroundColor: "rgba(0,0,0,0)", borderColor: "#ccc", itemGap: 10,
    inactiveColor: "#ccc", inactiveBorderColor: "#ccc", lineStyle: { inactiveColor: "#ccc" },
    textStyle: { color: "#333" },
    selectorLabel: { color: "#666", borderColor: "#666" },
    emphasis: { selectorLabel: { color: "#eee", backgroundColor: "#666" } },
    pageIconColor: "#2f4554", pageIconInactiveColor: "#aaa", pageTextStyle: { color: "#333" },
  },
  tooltip: {
    axisPointer: { crossStyle: { color: "#999" } },
    textStyle: { color: "#666" },
    backgroundColor: "#fff",
    borderWidth: 1,
    defaultBorderColor: "#fff",
  },
  visualMap: {
    color: ["#bf444c", "#d88273", "#f6efa6"],
    inactive: ["rgba(0,0,0,0)"],
    indicatorStyle: { shadowColor: "rgba(0,0,0,0.2)" },
    backgroundColor: "rgba(0,0,0,0)", borderColor: "#ccc", contentColor: "#5793f3", inactiveColor: "#aaa",
    padding: 5,
    textStyle: { color: "#333" },
  },
};

/** ECharts theme object: recessive hairline axes, theme-aware tooltip. */
export function buildChartTheme(t: Tokens) {
  const axisCommon = {
    axisLine: { show: true, lineStyle: { color: t.axis } },
    axisTick: { show: false },
    axisLabel: { color: t.text3, fontSize: 11 },
    splitLine: { lineStyle: { color: t.grid, type: "solid" as const } },
    nameTextStyle: { color: t.text3 },
  };
  return merge(V5_DEFAULTS, {
    color: t.series,
    backgroundColor: "transparent",
    textStyle: { fontFamily: t.font, color: t.text2 },
    legend: { textStyle: { color: t.text2 }, icon: "roundRect", itemWidth: 10, itemHeight: 10 },
    tooltip: {
      backgroundColor: t.surface2,
      borderColor: t.border,
      borderWidth: 1,
      padding: [8, 10],
      textStyle: { color: t.text, fontSize: 12 },
      extraCssText: "border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.25);",
    },
    categoryAxis: { ...axisCommon, splitLine: { show: false } },
    valueAxis: { ...axisCommon, axisLine: { show: false } },
    timeAxis: axisCommon,
    calendar: {
      itemStyle: { color: t.seq[0], borderColor: t.surface, borderWidth: 2 },
      splitLine: { show: false },
      dayLabel: { color: t.text3, fontSize: 10 },
      monthLabel: { color: t.text3, fontSize: 10 },
      yearLabel: { show: false },
    },
  });
}
