"""PNG charts for client reports (embedded as data URIs, so they survive a Google Docs import).

Plain horizontal / vertical bars in the report's navy palette. Labels never name internal tools or feeds;
the caller's captions go through the same leak check as the rest of the report.
"""
from __future__ import annotations

import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

NAVY, ACCENT, GREY, INK = "#12305A", "#4FA3FF", "#B8C4D6", "#1F2733"
plt.rcParams.update({"font.family": ["Arial", "DejaVu Sans"], "font.size": 9, "text.color": INK,
                     "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK})


def _png(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return buf.getvalue()


def _frame(ax) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(GREY)
    ax.spines["bottom"].set_color(GREY)


def hbar(items: list[tuple[str, float]], title: str, unit: str = "pages", highlight: str | None = None,
         pct: bool = False) -> bytes:
    """Ranked horizontal bars, largest on top, value labelled at the bar end."""
    items = items[:10]
    labels = [l for l, _ in items][::-1]
    vals = [v for _, v in items][::-1]
    fig, ax = plt.subplots(figsize=(6.4, 0.34 * len(items) + 0.9))
    colors = [ACCENT if highlight and l == highlight else NAVY for l in labels]
    bars = ax.barh(labels, vals, color=colors, height=0.62)
    top = max(vals) if vals else 1
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + top * 0.01, b.get_y() + b.get_height() / 2,
                f"{v:.0%}" if pct else f"{int(v)}", va="center", fontsize=8)
    ax.set_xlim(0, top * 1.12)
    ax.set_xticks([])
    ax.set_title(title, loc="left", fontsize=10, fontweight="bold")
    _frame(ax)
    ax.spines["bottom"].set_visible(False)
    return _png(fig)


def paired_hbar(items: list[tuple[str, float, float]], title: str, a_label: str, b_label: str) -> bytes:
    """Two shares per row (this brand vs the whole dataset), as percentages."""
    items = items[:10][::-1]
    labels = [l for l, _, _ in items]
    a = [x for _, x, _ in items]
    b = [y for _, _, y in items]
    fig, ax = plt.subplots(figsize=(6.4, 0.42 * len(items) + 1.0))
    ys = range(len(items))
    ax.barh([y + 0.2 for y in ys], a, height=0.38, color=NAVY, label=a_label)
    ax.barh([y - 0.2 for y in ys], b, height=0.38, color=GREY, label=b_label)
    top = max(a + b) if items else 1
    for y, v in zip(ys, a):
        ax.text(v + top * 0.01, y + 0.2, f"{v:.0%}", va="center", fontsize=7.5)
    for y, v in zip(ys, b):
        ax.text(v + top * 0.01, y - 0.2, f"{v:.0%}", va="center", fontsize=7.5, color="#6B7685")
    ax.set_yticks(list(ys), labels)
    ax.set_xlim(0, top * 1.15)
    ax.set_xticks([])
    ax.set_title(title, loc="left", fontsize=10, fontweight="bold")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    _frame(ax)
    ax.spines["bottom"].set_visible(False)
    return _png(fig)


def daily(days: list[tuple[str, int]], title: str) -> bytes:
    fig, ax = plt.subplots(figsize=(6.4, 2.4))
    labels = [d[5:] for d, _ in days]
    vals = [n for _, n in days]
    bars = ax.bar(labels, vals, color=NAVY, width=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(), str(v), ha="center", va="bottom", fontsize=8)
    ax.set_yticks([])
    ax.set_title(title, loc="left", fontsize=10, fontweight="bold")
    _frame(ax)
    ax.spines["left"].set_visible(False)
    return _png(fig)
