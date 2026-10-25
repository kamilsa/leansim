"""Render summary.html and traffic-<node>.html from one analysis snapshot.

Both pages are white and screenshot-friendly, share one stylesheet, one
Plotly theme and one traffic-series builder, and are self-contained: Plotly
is inlined and the data is embedded as JSON, so nothing loads from the network.
"""

import html
import json
from pathlib import Path
from string import Template


# Host classes in display order: plural label, singular label, colour (ff-workshop palette).
CLASS_STYLE = {
    "supernode": ("Supernodes", "supernode", "#2a78d6"),
    "regular": ("Regular nodes", "regular node", "#e34948"),
    "unknown": ("Unclassified", "unclassified", "#898781"),
}
# Peers listed in a traffic page's peer table.
PEER_ROWS = 15


def json_data(value):
    """Serialize data safely for an application/json script element."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c").replace(
        ">", "\\u003e"
    ).replace("&", "\\u0026")


def seconds(ms):
    return "–" if ms is None else f"{ms / 1000:.2f} s"


def count(value):
    return "–" if value is None else f"{value:,}"


def share(part, whole):
    return f"{part * 100 / whole:.1f}%" if whole else "–"


def host_facts(card):
    """One line about a host: location, class, link rates, validators, role."""
    if not card:
        return "No manifest entry for this host"
    parts = [
        (card.get("country") or "unknown location").title(),
        CLASS_STYLE[card["class"]][1],
        f"↑ {count(card.get('uplink_mbps'))} / ↓ {count(card.get('downlink_mbps'))} Mbps",
        f"{count(card['validators'])} validator{'' if card['validators'] == 1 else 's'}",
    ]
    if card.get("role"):
        parts.append(card["role"].replace("_", " "))
    return " · ".join(parts)


def cdf_figure(metrics):
    """Signature propagation: first sighting anywhere, and delivery to each host class."""
    lines = metrics.get("signature_cdf") or {}
    series = [("first_seen", "First seen by any host", "#0b0b0b", "dot")]
    series += [(kind, "Delivered to " + label.lower(), color, "solid") for kind, (label, _, color) in CLASS_STYLE.items()]
    data = []
    for key, name, color, dash in series:
        points = lines.get(key) or []
        if points:
            data.append({
                "type": "scatter", "mode": "lines", "name": name,
                "x": [point[0] / 1000 for point in points], "y": [point[1] for point in points],
                "line": {"color": color, "width": 2.5, "dash": dash},
                "hovertemplate": "%{y:.1f}% by %{x:.3f} s<extra>" + name + "</extra>",
            })
    return {"data": data, "layout": {
        "xaxis": {"title": {"text": "time after the first signature was sent (s)"}, "rangemode": "tozero"},
        "yaxis": {"title": {"text": "signatures"}, "range": [0, 101], "ticksuffix": "%"},
        "legend": {"orientation": "h", "x": 0, "y": 1.12},
    }}


def arrival_figure(metrics):
    """Slide-8 style boxes: p5–p95 whiskers, p25–p75 box, median line, per message and host class."""
    rows = metrics.get("arrivals") or []
    data = []
    for kind, (label, _, color) in CLASS_STYLE.items():
        own = [row for row in rows if row["class"] == kind]
        if not own:
            continue
        data.append({
            "type": "box", "orientation": "h", "name": label, "y": [row["message"] for row in own],
            "lowerfence": [row["p5"] / 1000 for row in own], "q1": [row["p25"] / 1000 for row in own],
            "median": [row["p50"] / 1000 for row in own], "q3": [row["p75"] / 1000 for row in own],
            "upperfence": [row["p95"] / 1000 for row in own],
            "marker": {"color": color}, "line": {"color": color, "width": 1.5}, "fillcolor": color + "40",
            "hoverinfo": "skip",
        })
    messages = list(dict.fromkeys(row["message"] for row in rows))
    return {"data": data, "layout": {
        "boxmode": "group", "boxgroupgap": 0.25, "boxgap": 0.2,
        "xaxis": {"title": {"text": "time after the first signature was sent (s)"}, "rangemode": "tozero"},
        "yaxis": {"categoryorder": "array", "categoryarray": messages, "autorange": "reversed"},
        "legend": {"orientation": "h", "x": 0, "y": 1.1},
        "margin": {"l": 120},
    }}


def validators_figure(population):
    """Hosts per validator-count bin, stacked by class, with each bar's total above it."""
    bins = population["validators_per_host"]
    labels = [str(item["low"]) if item["low"] == item["high"] else f"{item['low']}–{item['high']}" for item in bins]
    data = [{
        "type": "bar", "name": label, "x": labels, "y": [item[kind] for item in bins],
        "marker": {"color": color}, "customdata": [item["validators"] for item in bins],
        "hovertemplate": "%{y} hosts with %{x} validators<br>%{customdata:,} validators in this bin<extra>" + label + "</extra>",
    } for kind, (label, _, color) in CLASS_STYLE.items() if any(item[kind] for item in bins)]
    totals = [item["supernode"] + item["regular"] + item["unknown"] for item in bins]
    annotations = [{"x": label, "y": total, "text": f"{total:,}", "showarrow": False, "yanchor": "bottom",
                    "font": {"size": 12, "color": "#52514e"}} for label, total in zip(labels, totals) if total]
    return {"data": data, "layout": {
        "barmode": "stack", "annotations": annotations,
        "xaxis": {"title": {"text": "validators on the host"}, "type": "category", "tickangle": -45},
        "yaxis": {"title": {"text": "hosts"}, "rangemode": "tozero"},
        "legend": {"orientation": "h", "x": 0, "y": 1.12, "traceorder": "normal"},
    }}


def countries_figure(population):
    """Hosts per country (stacked by class) beside validators per country, largest first."""
    rows = population["countries"]
    names = [row["country"].title() for row in rows]
    data = [{
        "type": "bar", "orientation": "h", "name": label, "y": names, "x": [row[kind] for row in rows],
        "marker": {"color": color}, "hovertemplate": "%{x} hosts<extra>" + label + "</extra>",
    } for kind, (label, _, color) in CLASS_STYLE.items() if any(row[kind] for row in rows)]
    data.append({
        "type": "bar", "orientation": "h", "name": "Validators", "y": names, "x": [row["validators"] for row in rows],
        "xaxis": "x2", "yaxis": "y", "marker": {"color": "#52514e"}, "showlegend": False,
        "hovertemplate": "%{x:,} validators<extra></extra>",
    })
    return {"data": data, "layout": {
        "barmode": "stack", "height": 26 * len(rows) + 110,
        "xaxis": {"domain": [0, 0.46], "title": {"text": "hosts"}},
        "xaxis2": {"domain": [0.54, 1], "anchor": "y", "title": {"text": "validators"}},
        "yaxis": {"autorange": "reversed"},
        "legend": {"orientation": "h", "x": 0, "y": 1.06, "traceorder": "normal"},
        "margin": {"l": 120},
    }}


PAGE_CSS = """
:root { color-scheme: light; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781; --grid: #e1e0d9; --axis: #c3c2b7; --link: #2a78d6; --font: system-ui, -apple-system, "Segoe UI", sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; background: #ffffff; color: var(--ink); font: 15px/1.5 var(--font); }
main { max-width: 1200px; margin: 0 auto; padding: 40px 40px 56px; }
a { color: var(--link); text-decoration: none; } a:hover { text-decoration: underline; }
header.page { border-bottom: 1px solid var(--grid); padding-bottom: 20px; margin-bottom: 28px; }
.eyebrow { color: var(--muted); font-size: 13px; margin: 0 0 4px; overflow-wrap: anywhere; }
h1 { font-size: 30px; font-weight: 650; letter-spacing: -0.01em; margin: 0 0 6px; overflow-wrap: anywhere; }
h2 { font-size: 21px; font-weight: 650; margin: 0 0 4px; }
h3 { font-size: 16px; font-weight: 600; margin: 0 0 2px; }
.facts { color: var(--ink-2); margin: 0; }
section { margin: 0 0 44px; }
.caption { color: var(--ink-2); font-size: 14px; margin: 0 0 12px; max-width: 860px; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 0 0 44px; }
.kpi { border: 1px solid var(--grid); border-radius: 10px; padding: 14px 16px; }
.kpi .label, .kpi .note { display: block; color: var(--ink-2); font-size: 13px; } .kpi .note { color: var(--muted); }
.kpi b { display: block; font-size: 26px; font-weight: 650; margin: 2px 0; font-variant-numeric: tabular-nums; }
.chart { width: 100%; height: 380px; } .chart.tall { height: 460px; }
.two { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 32px; align-items: start; }
table { width: 100%; border-collapse: collapse; font-size: 14px; font-variant-numeric: tabular-nums; margin: 4px 0 8px; }
th, td { padding: 8px 10px; text-align: right; border-bottom: 1px solid var(--grid); white-space: nowrap; }
th { color: var(--ink-2); font-weight: 600; } th:first-child, td:first-child, .arrivals td:nth-child(2), .arrivals th:nth-child(2) { text-align: left; }
.table-scroll { overflow-x: auto; }
.swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 8px; }
.previews { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 20px; }
.preview { border: 1px solid var(--grid); border-radius: 10px; padding: 14px 16px 10px; }
.preview .meta { color: var(--ink-2); font-size: 13px; margin: 0; }
.preview .totals { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; color: var(--muted); font-size: 13px; margin: 6px 0 0; }
.mini { width: 100%; height: 150px; margin-top: 8px; }
.host-strip { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 14px; color: var(--ink-2); font-size: 14px; margin: 0 0 24px; }
.host-strip a[aria-current="page"] { color: var(--ink); font-weight: 600; }
.stage-head { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; }
.toggle { color: var(--ink-2); font-size: 14px; cursor: pointer; white-space: nowrap; } .toggle input { margin: 0 6px 0 0; }
.readouts { color: var(--ink-2); margin: 0 0 4px; } .readouts b { color: var(--ink); font-variant-numeric: tabular-nums; }
.peer-ledger td:first-child { max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
.mix { display: flex; height: 6px; min-width: 90px; border-radius: 3px; background: var(--grid); overflow: hidden; } .mix i { height: 100%; }
.mix .out { background: #52514e; } .mix .in { background: #c3c2b7; }
details summary { cursor: pointer; font-weight: 600; } details p { color: var(--ink-2); max-width: 860px; }
footer.page { border-top: 1px solid var(--grid); padding-top: 14px; color: var(--muted); font-size: 13px; }
@media (max-width: 760px) { main { padding: 24px 16px 40px; } .kpis { grid-template-columns: 1fr 1fr; } .two { grid-template-columns: 1fr; } }
"""

COMMON_JS = r"""
const FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif';
const AXIS = {gridcolor: '#e1e0d9', linecolor: '#c3c2b7', tickcolor: '#c3c2b7', zeroline: false, automargin: true};
const PLOT_CONFIG = {responsive: true, displaylogo: false, modeBarButtonsToRemove: ['lasso2d', 'select2d', 'autoScale2d'],
  toImageButtonOptions: {format: 'png', scale: 2}};
function plotLayout(extra) {
  const layout = Object.assign({paper_bgcolor: '#ffffff', plot_bgcolor: '#ffffff',
    font: {family: FONT, size: 13, color: '#52514e'}, margin: {t: 36, r: 16, b: 52, l: 64},
    hoverlabel: {bgcolor: '#0b0b0b', bordercolor: '#0b0b0b', font: {color: '#ffffff', family: FONT, size: 13}}}, extra);
  layout.margin = Object.assign({t: 36, r: 16, b: 52, l: 64}, extra.margin);
  for (const key of ['xaxis', 'yaxis', ...Object.keys(layout).filter(key => /^[xy]axis\d+$/.test(key))]) {
    layout[key] = Object.assign({}, AXIS, layout[key]);
  }
  return layout;
}
const KIND_COLORS = {signature: '#0072B2', duplicate_signature: '#56B4E9', proof_payload: '#009E73',
  proof_announce: '#E69F00', proof_request: '#CC79A7', proof_control: '#999999'};
const KIND_NAMES = {signature: 'Signatures', duplicate_signature: 'Duplicate signatures', proof_payload: 'Proof payloads',
  proof_announce: 'Announcements', proof_request: 'Pull requests', proof_control: 'Proof control'};
const mb = bytes => bytes / 1e6;
// Sent above zero, received below, one stacked area per traffic kind, in MB/s per bucket.
// Idle gaps and the final bucket end get zero-valued frames so areas return to zero.
function trafficSeries(traffic) {
  const kinds = [...new Set(traffic.buckets.flatMap(bucket => [...Object.keys(bucket.inbound), ...Object.keys(bucket.outbound)]))].sort();
  const frames = [];
  let previousEnd = null;
  for (const bucket of traffic.buckets) {
    if (previousEnd !== null && bucket.start_ms > previousEnd) {
      frames.push({start_ms: previousEnd, inbound: {}, outbound: {}, width_ms: traffic.bucket_ms});
    }
    frames.push(bucket);
    previousEnd = bucket.start_ms + bucket.width_ms;
  }
  if (previousEnd !== null) frames.push({start_ms: previousEnd, inbound: {}, outbound: {}, width_ms: traffic.bucket_ms});
  const x = frames.map(bucket => bucket.start_ms / 1000);
  const rate = (bytes, bucket) => mb(bytes) * 1000 / bucket.width_ms;
  const traces = [];
  for (const [direction, field, sign] of [['sent', 'outbound', 1], ['received', 'inbound', -1]]) {
    for (const kind of kinds) {
      const values = frames.map(bucket => rate(bucket[field][kind] || 0, bucket));
      traces.push({name: KIND_NAMES[kind] || kind, type: 'scatter', mode: 'lines', x,
        y: values.map(value => value === 0 ? 0 : sign * value), customdata: values,
        stackgroup: direction, line: {color: '#ffffff', width: 0.6, shape: 'spline', smoothing: 0.65},
        fillcolor: KIND_COLORS[kind] || '#999999', legendgroup: kind, showlegend: direction === 'sent',
        hovertemplate: '%{customdata:.2f} MB/s ' + direction + ' at %{x:.1f} s<extra>' + (KIND_NAMES[kind] || kind) + '</extra>'});
    }
  }
  const peak = frames.reduce((best, bucket) => Math.max(best,
    rate(Object.values(bucket.inbound).reduce((a, b) => a + b, 0), bucket),
    rate(Object.values(bucket.outbound).reduce((a, b) => a + b, 0), bucket)), 0);
  return {traces, peak, end: (previousEnd || 0) / 1000};
}
function mirroredAxis(peak) {
  const extent = peak > 0 ? peak * 1.12 : 1;
  return {range: [-extent, extent], zeroline: true, zerolinecolor: '#898781', zerolinewidth: 1,
    tickvals: [-extent * 0.9, -extent * 0.45, 0, extent * 0.45, extent * 0.9],
    ticktext: [extent * 0.9, extent * 0.45, 0, extent * 0.45, extent * 0.9].map(value => value.toFixed(1))};
}
"""

SUMMARY_JS = r"""
const report = JSON.parse(document.getElementById('report-data').textContent);
for (const [id, figure] of Object.entries(report.figures)) {
  Plotly.newPlot(id, figure.data, plotLayout(figure.layout), PLOT_CONFIG);
}
// Previews share one time axis so hosts can be compared at a glance.
const previews = Object.entries(report.previews).map(([node, traffic]) => [node, trafficSeries(traffic)]);
const previewEnd = Math.max(1, ...previews.map(([, series]) => series.end));
for (const [node, series] of previews) {
  Plotly.newPlot('preview-' + node, series.traces, plotLayout({
    showlegend: false, margin: {t: 4, r: 8, b: 26, l: 40},
    xaxis: {range: [0, previewEnd], ticksuffix: ' s'},
    yaxis: mirroredAxis(series.peak),
  }), {staticPlot: true, responsive: true});
}
"""

TRAFFIC_JS = r"""
const data = JSON.parse(document.getElementById('traffic-data').textContent);
const traffic = data.traffic;
const series = trafficSeries(traffic);
const warmupSeconds = Number.isFinite(data.warmup_ms) && data.warmup_ms > 0 ? data.warmup_ms / 1000 : 0;
const milestones = (data.milestones || []).filter(point => Number.isFinite(point.time_ms));
const endSeconds = Math.max(series.end, warmupSeconds, ...milestones.map(point => point.time_ms / 1000), 1);
const shapes = warmupSeconds > 0 ? [{type: 'rect', xref: 'x', yref: 'paper', x0: 0, x1: warmupSeconds, y0: 0, y1: 1,
  fillcolor: '#898781', opacity: 0.08, line: {width: 0}, layer: 'below'}] : [];
const annotations = warmupSeconds > 0 ? [{xref: 'x', yref: 'paper', x: warmupSeconds / 2, y: 0.9,
  text: 'Warmup<br>traffic not<br>captured', showarrow: false, font: {color: '#898781', size: 12}, align: 'center'}] : [];
for (const [index, point] of milestones.entries()) {
  const at = point.time_ms / 1000;
  shapes.push({type: 'line', xref: 'x', yref: 'paper', x0: at, x1: at, y0: 0, y1: 1,
    line: {color: '#898781', width: 1, dash: 'dot'}, layer: 'below'});
  annotations.push({xref: 'x', yref: 'paper', x: at, y: index % 2 ? 1.14 : 1.01, yanchor: 'bottom',
    text: point.label + ' · ' + at.toFixed(2) + ' s', xanchor: index === milestones.length - 1 ? 'right' : 'center',
    showarrow: false, font: {color: '#52514e', size: 12}, align: 'center'});
}
Plotly.newPlot('timeline', series.traces, plotLayout({
  xaxis: {title: {text: 'time from run start (s)'}, range: [0, endSeconds], autorange: false},
  yaxis: Object.assign({title: {text: 'MB/s · sent above, received below'}}, mirroredAxis(series.peak)),
  shapes, annotations, margin: {t: 70, b: 90},
  legend: {orientation: 'h', x: 0, y: -0.2, groupclick: 'togglegroup'},
  uirevision: data.run + data.node,
}), PLOT_CONFIG);
document.getElementById('run').textContent = data.run + ' · ' + traffic.bucket_ms + ' ms buckets · ' + traffic.buckets.length + ' buckets with traffic';
document.getElementById('received').textContent = mb(traffic.received).toFixed(2) + ' MB';
document.getElementById('sent').textContent = mb(traffic.sent).toFixed(2) + ' MB';
document.getElementById('peak').textContent = series.peak.toFixed(2) + ' MB/s';
document.getElementById('raw-buckets').addEventListener('change', () => {
  const raw = document.getElementById('raw-buckets').checked;
  Plotly.restyle('timeline', {'line.shape': raw ? 'hv' : 'spline', 'line.smoothing': raw ? 0 : 0.65});
  document.getElementById('curve-note').textContent = raw
    ? 'Raw buckets: flat rate within each measured interval.'
    : 'Curved display: interpolation only; totals, peak and hover values use raw buckets.';
});
"""
