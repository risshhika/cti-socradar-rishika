import { useEffect, useImperativeHandle, useRef, useState, type Ref } from "react";
import echarts, { ensureWorldMap, type EChartsCoreOption } from "./echarts";
import { useTheme } from "../theme/ThemeProvider";
import { buildChartTheme } from "../theme/echartsTheme";

export interface EChartHandle {
  /** PNG of the chart on the card surface, for "Save PNG". */
  toDataURL: () => string | undefined;
}

type Handler = (params: any) => void;

interface Props {
  option: EChartsCoreOption;
  height: number;
  renderer?: "canvas" | "svg";
  onEvents?: Record<string, Handler>;
  ariaLabel: string;
  handle?: Ref<EChartHandle | null>;
  /** set for charts that draw on the world map */
  needsWorld?: boolean;
}

/**
 * Thin ECharts binding (ported from Mintverse). ECharts can't swap themes on a live instance, so the chart is
 * disposed and re-created when the theme changes; option updates reuse the instance.
 */
export function EChart({ option, height, renderer = "canvas", onEvents, ariaLabel, handle, needsWorld }: Props) {
  const el = useRef<HTMLDivElement>(null);
  const inst = useRef<ReturnType<typeof echarts.init> | null>(null);
  const optRef = useRef(option);
  const evRef = useRef(onEvents);
  const { chartTheme, tokens } = useTheme();
  const [mapReady, setMapReady] = useState(!needsWorld);
  optRef.current = option;
  evRef.current = onEvents;

  useEffect(() => {
    if (!needsWorld) return;
    let live = true;
    ensureWorldMap().then(() => live && setMapReady(true)).catch(() => live && setMapReady(false));
    return () => { live = false; };
  }, [needsWorld]);

  useEffect(() => {
    if (!el.current || !mapReady) return;
    echarts.registerTheme(chartTheme, buildChartTheme(tokens));
    const chart = echarts.init(el.current, chartTheme, { renderer });
    inst.current = chart;
    chart.setOption(optRef.current);
    const names = Object.keys(evRef.current ?? {});
    names.forEach((n) => chart.on(n, (p: unknown) => evRef.current?.[n]?.(p)));
    let frame = 0;
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => chart.resize());
    });
    ro.observe(el.current);
    return () => {
      cancelAnimationFrame(frame);
      ro.disconnect();
      chart.dispose();
      inst.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chartTheme, tokens, renderer, mapReady]);

  useEffect(() => {
    inst.current?.setOption(option, { notMerge: true });
  }, [option]);

  useImperativeHandle(handle, () => ({
    toDataURL: () => inst.current?.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: tokens.surface }),
  }), [tokens.surface]);

  return <div ref={el} role="img" aria-label={ariaLabel} style={{ width: "100%", height }} />;
}
