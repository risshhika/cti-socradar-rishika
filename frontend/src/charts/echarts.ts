// Tree-shaken ECharts: register only what the platform draws. Pattern ported from Mintverse.
import * as echarts from "echarts/core";
import {
  BarChart, BoxplotChart, FunnelChart, GaugeChart, GraphChart, HeatmapChart, LineChart, MapChart, PieChart,
  RadarChart, SankeyChart, ScatterChart, SunburstChart, ThemeRiverChart, TreemapChart, EffectScatterChart,
} from "echarts/charts";
import {
  AriaComponent, CalendarComponent, DataZoomComponent, DatasetComponent, GeoComponent, GraphicComponent, GridComponent,
  LegendComponent, MarkAreaComponent, MarkLineComponent, MarkPointComponent, PolarComponent, RadarComponent,
  SingleAxisComponent, TitleComponent, TooltipComponent, VisualMapComponent,
} from "echarts/components";
import { LegacyGridContainLabel } from "echarts/features";
import { CanvasRenderer, SVGRenderer } from "echarts/renderers";

echarts.use([
  BarChart, BoxplotChart, FunnelChart, GaugeChart, GraphChart, HeatmapChart, LineChart, MapChart, PieChart, RadarChart,
  SankeyChart, ScatterChart, SunburstChart, ThemeRiverChart, TreemapChart, EffectScatterChart,
  AriaComponent, CalendarComponent, DataZoomComponent, DatasetComponent, GeoComponent, GraphicComponent, GridComponent,
  LegendComponent, MarkAreaComponent, MarkLineComponent, MarkPointComponent, PolarComponent, RadarComponent,
  SingleAxisComponent, TitleComponent, TooltipComponent, VisualMapComponent,
  LegacyGridContainLabel, CanvasRenderer, SVGRenderer,
]);

let worldPromise: Promise<void> | null = null;
/** World outline (Natural Earth via the ECharts 4 map pack), loaded once on first use of a map chart. */
export function ensureWorldMap(): Promise<void> {
  if (!worldPromise) {
    worldPromise = fetch("/geo/world.json")
      .then((r) => r.json())
      .then((geo) => { echarts.registerMap("world", geo); })
      .catch((e) => { worldPromise = null; throw e; });
  }
  return worldPromise;
}

export default echarts;
export type { EChartsCoreOption } from "echarts/core";
