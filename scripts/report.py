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


def duty_text(duties):
    """One line naming the proofs a host aggregates, or None when the snapshot predates duties."""
    if duties is None:
        return None

    def which(noun, ids):
        if len(ids) <= 3:
            return f"{noun} {', '.join(map(str, ids))}" if len(ids) == 1 else f"{noun}s {', '.join(map(str, ids))}"
        return f"{len(ids)} {noun}s"

    parts = []
    if duties.get("subnets"):
        parts.append(f"Subnet aggregator ({which('subnet', duties['subnets'])})")
    for layer, groups in sorted((duties.get("layers") or {}).items(), key=lambda item: int(item[0])):
        parts.append(f"Layer {layer} aggregator ({which('group', groups)})")
    if duties.get("final"):
        parts.append("Final proof aggregator")
    return " · ".join(parts) or "Not an aggregator"


def duty_line(card):
    text = duty_text((card or {}).get("duties"))
    return f'<p class="duties">{html.escape(text)}</p>' if text else ""


def cdf_figure(metrics):
    """Signature propagation: first sighting anywhere, and delivery to each host class."""
    return cdf_figure_for(metrics.get("signature_cdf") or {})


def cdf_figure_for(lines):
    """The CDF plot used by the run summary and every subnet page."""
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


def subnet_proofs_figure(metrics):
    """One candle per subnet (first to last aggregator, p25–p75 box, median line)
    and one dot per aggregator's subnet proof, coloured by host class."""
    rows = metrics.get("subnet_proofs") or []
    if not rows:
        return None
    data = [{
        "type": "box", "orientation": "h", "name": "Aggregators", "y": [row["subnet"] for row in rows],
        "lowerfence": [row["min"] / 1000 for row in rows], "q1": [row["p25"] / 1000 for row in rows],
        "median": [row["p50"] / 1000 for row in rows], "q3": [row["p75"] / 1000 for row in rows],
        "upperfence": [row["max"] / 1000 for row in rows], "width": 0.7,
        "marker": {"color": "#52514e"}, "line": {"color": "#52514e", "width": 1.2}, "fillcolor": "#c3c2b780",
        "hoverinfo": "skip", "showlegend": False,
    }]
    # Alternate dots across the row so aggregators that finished together stay visible.
    offsets = (0, -0.2, 0.2)
    dots = {kind: {"x": [], "y": [], "text": [], "customdata": []} for kind in CLASS_STYLE}
    for row in rows:
        for rank, (time_ms, node_id, kind) in enumerate(row["proofs"]):
            dot = dots[kind if kind in dots else "unknown"]
            dot["x"].append(time_ms / 1000)
            dot["y"].append(round(row["subnet"] + offsets[rank % len(offsets)], 3))
            dot["text"].append("unknown node" if node_id is None else f"node {node_id}")
            dot["customdata"].append(row["subnet"])
    for kind, (label, _, color) in CLASS_STYLE.items():
        if dots[kind]["x"]:
            data.append({
                "type": "scatter", "mode": "markers", "name": label, **dots[kind],
                "marker": {"color": color, "size": 6, "opacity": 0.8, "line": {"color": "#ffffff", "width": 0.5}},
                "hovertemplate": "%{text} · subnet %{customdata} · %{x:.3f} s<extra>" + label + "</extra>",
            })
    subnets = [row["subnet"] for row in rows]
    return {"data": data, "layout": {
        "height": subnet_proofs_height(rows),
        "xaxis": {"title": {"text": "time after the first signature was sent (s)"}, "rangemode": "tozero"},
        "yaxis": {"autorange": "reversed", "tickvals": subnets, "ticktext": [f"subnet {subnet}" for subnet in subnets],
                  # SUMMARY_JS turns these labels into links to subnet-<n>.html.
                  "tickfont": {"size": 11, "color": "#2a78d6"}, "showgrid": False, "zeroline": False},
        "legend": {"orientation": "h", "x": 0, "y": 1.02, "yanchor": "bottom"},
        "margin": {"l": 90, "t": 40},
    }}


def subnet_proofs_height(rows):
    return 18 * len(rows) + 130


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


def subscribers_figure(info):
    """Hosts subscribed to one subnet, by country and class, with their validators."""
    return countries_figure({"countries": info["countries"]})


def subnet_info(metrics, subnet_id):
    """Subscriber info for one subnet; keys may be strings after a JSON round-trip."""
    hosts = metrics.get("subnet_hosts") or {}
    return hosts.get(subnet_id) or hosts.get(str(subnet_id)) or {"classes": {}, "countries": []}


def subnet_page_figures(metrics, subnet_id):
    """CDF of this subnet's signature deliveries, plus its subscriber breakdown."""
    info = subnet_info(metrics, subnet_id)
    by_subnet = metrics.get("signature_cdf_by_subnet") or {}
    lines = by_subnet.get(subnet_id) or by_subnet.get(str(subnet_id)) or {}
    return {
        "subnet-cdf": cdf_figure_for(lines),
        "subnet-subscribers": subscribers_figure(info),
    }


PAGE_CSS = r"""
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
.caption-list { padding-left: 20px; } .caption-list li { margin: 2px 0; } .caption-list b { color: var(--ink); font-weight: 600; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 0 0 44px; }
.kpi { border: 1px solid var(--grid); border-radius: 10px; padding: 14px 16px; }
.kpi .label, .kpi .note { display: block; color: var(--ink-2); font-size: 13px; } .kpi .note { color: var(--muted); }
.kpi b { display: block; font-size: 26px; font-weight: 650; margin: 2px 0; font-variant-numeric: tabular-nums; }
.chart { width: 100%; height: 380px; } .chart.tall { height: 460px; }
#subnet-proofs .ytick text { pointer-events: all; cursor: pointer; }
#subnet-proofs .ytick text:hover { text-decoration: underline; }
.two { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 32px; align-items: start; }
.config-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 20px; align-items: start; }
.config-card { border: 1px solid var(--grid); border-radius: 10px; padding: 14px 16px 4px; }
.config th { font-weight: 400; color: var(--ink-2); vertical-align: top; padding-left: 0; }
.config td { white-space: normal; padding-right: 0; } .config td b { font-weight: 600; white-space: nowrap; }
.config .note { display: block; color: var(--muted); font-size: 12px; }
.config tr:last-child th, .config tr:last-child td { border-bottom: 0; }
table { width: 100%; border-collapse: collapse; font-size: 14px; font-variant-numeric: tabular-nums; margin: 4px 0 8px; }
th, td { padding: 8px 10px; text-align: right; border-bottom: 1px solid var(--grid); white-space: nowrap; }
th { color: var(--ink-2); font-weight: 600; } th:first-child, td:first-child, .arrivals td:nth-child(2), .arrivals th:nth-child(2) { text-align: left; }
.table-scroll { overflow-x: auto; }
.swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 8px; }
.previews { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 20px; }
.preview { border: 1px solid var(--grid); border-radius: 10px; padding: 14px 16px 10px; }
.preview .meta { color: var(--ink-2); font-size: 13px; margin: 0; }
.duties { color: var(--ink); font-size: 13px; font-weight: 600; margin: 2px 0 0; } header.page .duties { font-size: 15px; margin-top: 4px; }
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
@media (max-width: 760px) { main { padding: 24px 16px 40px; } .kpis { grid-template-columns: 1fr 1fr; } .two, .config-grid { grid-template-columns: 1fr; } }
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

SUBNET_JS = r"""
const data = JSON.parse(document.getElementById('subnet-data').textContent);
for (const [id, figure] of Object.entries(data.figures)) {
  Plotly.newPlot(id, figure.data, plotLayout(figure.layout), PLOT_CONFIG);
}
"""

SUMMARY_JS = r"""
const report = JSON.parse(document.getElementById('report-data').textContent);
for (const [id, figure] of Object.entries(report.figures)) {
  Plotly.newPlot(id, figure.data, plotLayout(figure.layout), PLOT_CONFIG);
}
// Subnet labels open subnet-<n>.html. Plotly redraws ticks on resize, so listen on
// the chart container; PAGE_CSS gives the labels back their pointer events.
const subnetPlot = document.getElementById('subnet-proofs');
if (subnetPlot) {
  subnetPlot.addEventListener('click', event => {
    const tick = event.target.closest && event.target.closest('.ytick');
    const match = tick && tick.textContent.trim().match(/^subnet (\d+)$/);
    if (match) location.href = 'subnet-' + match[1] + '.html';
  });
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


def class_table(population):
    """Bandwidth classes: hosts, link rates and validators."""
    rows = []
    for item in population["classes"]:
        label, _, color = CLASS_STYLE[item["class"]]
        rows.append(
            f'<tr><td><span class="swatch" style="background:{color}"></span>{label}</td>'
            f'<td>{count(item["hosts"])}</td><td>{share(item["hosts"], population["hosts"])}</td>'
            f'<td>{count(item["uplink_mbps"])} Mbps</td><td>{count(item["downlink_mbps"])} Mbps</td>'
            f'<td>{count(item["validators"])}</td><td>{share(item["validators"], population["validators"])}</td></tr>'
        )
    if population.get("supernode_by_validator_count") is not None:
        rule = f'Supernodes are hosts running at least {population["supernode_by_validator_count"]:,} validators.'
    elif population.get("supernode_fraction") is not None:
        rule = f'Supernodes are {population["supernode_fraction"]:.0%} of hosts, sampled at random.'
    else:
        rule = ""
    return (
        '<div class="table-scroll"><table class="classes"><thead><tr><th>Class</th><th>Hosts</th><th>Share</th><th>Uplink</th>'
        '<th>Downlink</th><th>Validators</th><th>Share</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"
        + (f'<p class="caption">{html.escape(rule)}</p>' if rule else "")
    )


def arrival_table(metrics):
    """The numbers behind the arrival boxes."""
    rows = "".join(
        f'<tr><td>{html.escape(row["message"])}</td>'
        f'<td><span class="swatch" style="background:{CLASS_STYLE[row["class"]][2]}"></span>{CLASS_STYLE[row["class"]][0]}</td>'
        f'<td>{count(row["count"])}</td>' + "".join(f"<td>{seconds(row[key])}</td>" for key in ("p5", "p25", "p50", "p75", "p95"))
        + "</tr>"
        for row in metrics.get("arrivals") or []
    )
    return (
        '<table class="arrivals"><thead><tr><th>Message</th><th>Host class</th><th>Samples</th><th>p5</th><th>p25</th>'
        "<th>Median</th><th>p75</th><th>p95</th></tr></thead><tbody>" + rows + "</tbody></table>"
    )


def config_groups(config, metrics):
    """The run's main settings as [(group, [(label, value, note), ...])]; settings
    missing from the manifest are left out, and so are empty groups."""
    def has(*keys):
        return all(config.get(key) is not None for key in keys)

    signatures, aggregation, gossip = [], [], []
    committee = config["validator_count"] // config["subnet_count"] if has("validator_count", "subnet_count") and config["subnet_count"] else None
    if has("signature_payload_bytes"):
        signatures.append(("Signature size", f'{config["signature_payload_bytes"]:,} B', ""))
    if has("signature_aggregation_rate"):
        rate = config["signature_aggregation_rate"]
        note = ""
        if committee and has("local_threshold"):
            # The simulator truncates the threshold count, as in analyze.build_snapshot.
            needed = int(committee * config["local_threshold"])
            note = (f'a {config["local_threshold"]:.0%} proof of a {committee:,}-validator committee '
                    f"({needed:,} signatures) takes {needed * 1000 / rate:,.0f} ms")
        signatures.append(("Aggregation rate", f"{rate:,} signatures/s", note))
    if has("local_threshold"):
        signatures.append(("Local threshold", f'{config["local_threshold"]:.0%}', "of a committee's signatures per subnet proof"))
    if has("burst_time_ms", "burst_jitter_ms"):
        start = config["burst_time_ms"]
        signatures.append(("Signing", f'{start:,}–{start + config["burst_jitter_ms"]:,} ms after warmup',
                           f'warmup {config["mesh_warmup_ms"]:,} ms' if has("mesh_warmup_ms") else ""))

    if committee is not None:
        aggregation.append(("Committees", f'{config["subnet_count"]:,} × {committee:,} validators', "one committee per subnet"))
    if has("local_aggregators_per_subnet"):
        count = config["local_aggregators_per_subnet"]
        if config.get("committee_aggregators"):
            aggregation.append(("Subnet aggregators", f"~{count:,} per committee", "is_aggregator lottery"))
        else:
            aggregation.append(("Subnet aggregators", f"{count:,} per subnet", "promoted among subnet subscribers"))
    if config.get("recursive_aggregation"):
        arity = config.get("recursive_aggregation_arity")
        layers = len((metrics.get("recursive_aggregation") or {}).get("layers") or {})
        aggregation.append(("Recursive aggregation", f"{arity}-to-1",
                            f"{layers} layer{'' if layers == 1 else 's'} above the subnet proofs" if layers else ""))
        if has("recursive_aggregation_time_ms"):
            aggregation.append(("Recursive proof time", f'{config["recursive_aggregation_time_ms"]:,} ms', f"per {arity}-to-1 proof"))
        if has("recursive_group_size"):
            aggregation.append(("Group size", f'~{config["recursive_group_size"]:,} members', "lottery target per group"))
        if has("aggregate_proof_bytes"):
            size = config["aggregate_proof_bytes"]
            aggregation.append(("Proof size", f"{size:,} B", f"{size / 1024:,.0f} KiB, every subnet and recursive proof"))
    elif "recursive_aggregation" in config:
        aggregation.append(("Recursive aggregation", "off", "subnet proofs are logged, not sent"))

    if has("gossipsub_mesh_n"):
        bounds = f'low {config["gossipsub_mesh_n_low"]}, high {config["gossipsub_mesh_n_high"]}' if has("gossipsub_mesh_n_low", "gossipsub_mesh_n_high") else ""
        gossip.append(("Mesh degree", str(config["gossipsub_mesh_n"]), bounds))
    if has("gossipsub_heartbeat_interval_ms"):
        gossip.append(("Heartbeat", f'{config["gossipsub_heartbeat_interval_ms"]:,} ms', ""))
    if has("subnet_subscriptions_per_node"):
        gossip.append(("Subnet subscriptions", f'{config["subnet_subscriptions_per_node"]} per host',
                       "plus the subnets its validators sign in" if config.get("subscribe_to_duty_subnets") else ""))
    for key, label in (("gossipsub_flood_publish", "Flood publish"), ("gossipsub_idontwant", "IDONTWANT")):
        if key in config:
            gossip.append((label, "on" if config[key] else "off", ""))
    return [(title, rows) for title, rows in (("Signatures", signatures), ("Aggregation", aggregation), ("Gossip", gossip)) if rows]


def config_section(config, metrics):
    groups = config_groups(config or {}, metrics)
    if not groups:
        return ""
    cards = "".join(
        f'<div class="config-card"><h3>{title}</h3><table class="config"><tbody>'
        + "".join(
            f'<tr><th scope="row">{html.escape(label)}</th><td><b>{html.escape(value)}</b>'
            + (f'<span class="note">{html.escape(note)}</span>' if note else "") + "</td></tr>"
            for label, value, note in rows
        )
        + "</tbody></table></div>"
        for title, rows in groups
    )
    return ('<section aria-labelledby="config"><h2 id="config">Configuration</h2>'
            '<p class="caption">Main settings of this run, from run-manifest.json.</p>'
            f'<div class="config-grid">{cards}</div></section>')


def kpis(metrics):
    population = metrics.get("population") or {}
    supernodes = sum(item["hosts"] for item in population.get("classes", []) if item["class"] == "supernode")
    signature_p95 = {row["class"]: row["p95"] for row in metrics.get("arrivals") or [] if row["message"] == "Signatures"}
    final = (metrics.get("recursive_aggregation") or {}).get("final_proof_ms")
    cells = [
        ("Hosts", count(population.get("hosts")), f"{supernodes:,} supernodes" if population else ""),
        ("Validators", count(population.get("validators") or metrics.get("unique_validators")), f'{count(metrics.get("signing_hosts"))} signing hosts'),
        ("Signature delivery p95", seconds(signature_p95.get("regular", signature_p95.get("unknown"))),
         f'regular nodes · supernodes {seconds(signature_p95.get("supernode"))}'),
        ("Final proof", seconds(final - metrics["t0_ms"]) if final is not None else "–", "first host to hold it"),
    ]
    return '<div class="kpis">' + "".join(
        f'<div class="kpi"><span class="label">{label}</span><b>{value}</b><span class="note">{html.escape(note)}</span></div>'
        for label, value, note in cells
    ) + "</div>"


def preview_cards(traffic):
    cards = []
    for node_id in sorted(traffic, key=int):
        logged = traffic[node_id]
        node = html.escape(node_id)
        cards.append(
            f'<article class="preview"><h3><a href="traffic-{node}.html">Node {node}</a></h3>'
            f'<p class="meta">{html.escape(host_facts(logged.get("host")))}</p>'
            + duty_line(logged.get("host")) +
            f'<div class="mini" id="preview-{node}" role="img" aria-label="Traffic of node {node}: sent above, received below"></div>'
            f'<p class="totals"><span>↑ {logged["sent"] / 1e6:,.1f} MB sent · ↓ {logged["received"] / 1e6:,.1f} MB received</span>'
            f'<a href="traffic-{node}.html">Open traffic profile →</a></p></article>'
        )
    return '<div class="previews">' + "".join(cards) + "</div>"

SUMMARY_TEMPLATE = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim summary: $run</title><style>$css</style></head><body><main>
<header class="page"><p class="eyebrow">leanSim run summary</p><h1>$run</h1><p class="facts">$facts</p></header>
$kpis
$config
$network
<section aria-labelledby="propagation"><h2 id="propagation">Signature propagation</h2>
<p class="caption">Share of signatures received by time t. The dotted line counts each validator's signature once, when the first host saw it. The solid lines count every delivery to a host of that class. Hosts receive only the subnets they subscribe to.</p>
<div class="chart" id="cdf"></div></section>
<section aria-labelledby="arrivals"><h2 id="arrivals">Arrival times across hosts</h2>
<p class="caption">Each row shows, across hosts, when a host first held a message. Whiskers span p5 to p95, the box p25 to p75, and the line is the median.</p>
<ul class="caption caption-list">
<li><b>Signatures:</b> one sample per receiving host and validator, at the first copy the host received.</li>
<li><b>Subnet proofs and layer proofs:</b> one sample per host and proof, at the moment the host finished building it or finished fetching it, whichever came first.</li>
<li><b>Final proof:</b> one sample per root-group member, at the moment it finished building the final proof. No host fetches the final proof, so this row is not when the root members received their input proofs; those fetches are in the row of the layer below.</li>
</ul>
<div class="chart" id="arrival" style="height:${arrival_height}px"></div>
<div class="table-scroll">$arrival_table</div></section>
$subnet_proofs
$previews
<footer class="page">Generated $generated from $output_dir. Times are simulated; t = 0 is the first signature sent ($t0).</footer>
</main><script id="report-data" type="application/json">$data</script><script>$plotly</script><script>$common</script><script>$script</script></body></html>
""")

TRAFFIC_TEMPLATE = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim traffic: node $node</title><style>$css</style></head><body><main>
<header class="page"><p class="eyebrow"><a href="summary.html">← Run summary</a> · <span id="run"></span></p>
<h1>Node $node traffic</h1><p class="facts">$facts</p>$duties</header>
<nav class="host-strip" aria-label="Logged hosts"><span>Tracked hosts:</span>$host_links</nav>
<section class="traffic-stage" aria-labelledby="traffic-heading">
<div class="stage-head"><h2 id="traffic-heading">Sent and received traffic</h2><label class="toggle"><input type="checkbox" id="raw-buckets" aria-describedby="curve-note">Raw buckets</label></div>
<p class="readouts">↑ Sent <b id="sent"></b> · ↓ Received <b id="received"></b> · Peak bucket rate <b id="peak"></b></p>
<div class="chart tall" id="timeline" role="img" aria-label="Traffic timeline. Sent traffic above zero, received traffic below. Warmup is unmeasured."></div>
<p class="caption" id="curve-note">Curved display: interpolation only; totals, peak and hover values use raw buckets.</p></section>
<section aria-labelledby="peers-heading"><h2 id="peers-heading">Peer exchanges</h2><p class="caption">$peer_caption</p>
<div class="table-scroll"><table class="peer-ledger"><thead><tr><th>Peer</th><th>Sent ↑</th><th>Received ↓</th><th>Traffic mix</th></tr></thead><tbody>$peer_rows</tbody></table></div></section>
<section><details><summary>Measurement notes</summary>
<p>Application-level traffic, not wire bandwidth. Outgoing gossip is estimated as one copy per mesh peer. IHAVE/IWANT, transport overhead and retransmissions are not measured.</p>
<p>Proof bytes are counted when a message is handled, not spread over the transfer, so peaks can exceed the link rate.</p>
<p>Warmup traffic (connections, subscriptions) is not captured. Decimal MB: 1 MB = 1,000,000 bytes.</p></details></section>
</main><script id="traffic-data" type="application/json">$data</script><script>$plotly</script><script>$common</script><script>$script</script></body></html>
""")


SUBNET_TEMPLATE = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim subnet $subnet</title><style>$css</style></head><body><main>
<header class="page"><p class="eyebrow"><a href="summary.html">← Run summary</a> · <span>$run</span></p>
<h1>Subnet $subnet</h1><p class="facts">$facts</p></header>
<section aria-labelledby="propagation-heading"><h2 id="propagation-heading">Signature propagation in subnet $subnet</h2>
<p class="caption">Delivery of this subnet's signatures to the hosts that received them. <b>First seen</b> is the first arrival of each signature on any host; the other lines are the first arrival on a host of each class. t = 0 is the first signature sent in the run.</p>
<div class="chart tall" id="subnet-cdf" role="img" aria-label="CDF of signature delivery in this subnet"></div></section>
<section aria-labelledby="subscribers-heading"><h2 id="subscribers-heading">Subscribed hosts</h2>
<p class="caption">Hosts subscribed to this subnet by country (stacked by host class), with the validators they run. The left bars are hosts, the right bars validators.</p>
<div class="chart" id="subnet-subscribers" style="height:${subscribers_height}px"></div></section>
</main><script id="subnet-data" type="application/json">$data</script><script>$plotly</script><script>$common</script><script>$script</script></body></html>
""")


def network_section(population):
    if not population:
        return '<section><h2>Network</h2><p class="caption">run-manifest.json has no node list, so host classes, validators per host and locations are unavailable.</p></section>'
    return (
        '<section aria-labelledby="network"><h2 id="network">Network</h2>'
        f'<p class="caption">{population["hosts"]:,} hosts run {population["validators"]:,} validators.</p>'
        + class_table(population)
        + '<div class="two"><div><h3>Validators per host</h3><div class="chart" id="validators"></div></div>'
        '<div><h3>Hosts and validators by country</h3>'
        f'<div class="chart" id="countries" style="height:{26 * len(population["countries"]) + 110}px"></div></div></div></section>'
    )


def milestones_for(snapshot):
    """Run-wide markers for traffic timelines, in ms from run start."""
    metrics = snapshot.get("metrics", {})
    recursive = metrics.get("recursive_aggregation") or {}
    local_firsts = [stats["min"] for stats in metrics.get("local_proof_latency_ms_by_subnet", {}).values() if stats]
    candidates = (
        ("Signature burst", metrics.get("stage_medians_ms", {}).get("signatures_sent")),
        ("First subnet proof", min(local_firsts, default=None)),
        ("Final proof", recursive.get("final_proof_ms")),
    )
    return [{"label": label, "time_ms": value} for label, value in candidates
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0]


def generate_traffic_html(snapshot, directory, plotly_js):
    """One white dashboard per host that kept traffic logs."""
    traffic = snapshot.get("metrics", {}).get("traffic") or {}
    run = Path(snapshot.get("output_dir", "")).name
    milestones = milestones_for(snapshot)
    for node_id, logged in traffic.items():
        host_links = " ".join(
            f'<a href="traffic-{html.escape(host)}.html"' + (' aria-current="page"' if host == node_id else "")
            + f">Node {html.escape(host)}</a>"
            for host in sorted(traffic, key=int)
        )
        leaders = logged["peers"][:PEER_ROWS]
        largest = max((peer["inbound"] + peer["outbound"] for peer in leaders), default=1) or 1
        rows = []
        for peer in leaders:
            label = html.escape(peer["peer"])
            if str(peer.get("node_id")) in traffic:
                label = f'<a href="traffic-{peer["node_id"]}.html">{label}</a>'
            rows.append(
                f'<tr><td title="{html.escape(peer["peer"], quote=True)}">{label}</td>'
                f'<td>{peer["outbound"] / 1e6:,.2f} MB</td><td>{peer["inbound"] / 1e6:,.2f} MB</td>'
                f'<td><span class="mix" aria-hidden="true"><i class="out" style="width:{peer["outbound"] / largest * 100:.3f}%"></i>'
                f'<i class="in" style="width:{peer["inbound"] / largest * 100:.3f}%"></i></span></td></tr>'
            )
        document = TRAFFIC_TEMPLATE.substitute(
            node=html.escape(node_id),
            css=PAGE_CSS,
            facts=html.escape(host_facts(logged.get("host"))),
            duties=duty_line(logged.get("host")),
            host_links=host_links,
            peer_caption=f'Top {len(leaders)} of {len(logged["peers"])} retained peer records, by bytes exchanged.',
            peer_rows="".join(rows) or '<tr><td colspan="4">No per-peer records in this trace.</td></tr>',
            data=json_data({"node": node_id, "run": run, "traffic": logged, "milestones": milestones,
                            "warmup_ms": snapshot.get("metadata", {}).get("mesh_warmup_ms")}),
            plotly=plotly_js,
            common=COMMON_JS,
            script=TRAFFIC_JS,
        )
        (directory / f"traffic-{node_id}.html").write_text(document, encoding="utf-8")


def generate_subnet_html(snapshot, directory, plotly_js):
    """One white page per subnet: its signature CDF and its subscribers."""
    metrics = snapshot.get("metrics", {})
    rows = metrics.get("subnet_proofs") or []
    if not rows:
        return
    run = Path(snapshot.get("output_dir", "")).name
    for row in rows:
        subnet_id = row["subnet"]
        info = subnet_info(metrics, subnet_id)
        hosts = sum(info["classes"].values())
        validators = sum(country["validators"] for country in info["countries"])
        facts = [
            f"{count(hosts)} subscribed host" + ("s" if hosts != 1 else ""),
            f"{count(validators)} validators on them",
            f"{count(row['count'])} subnet aggregator" + ("s" if row["count"] != 1 else ""),
        ]
        figures = subnet_page_figures(metrics, subnet_id)
        document = SUBNET_TEMPLATE.substitute(
            subnet=subnet_id,
            css=PAGE_CSS,
            facts=html.escape(" · ".join(facts)),
            run=html.escape(run),
            subscribers_height=figures["subnet-subscribers"]["layout"]["height"],
            data=json_data({"subnet": subnet_id, "info": info, "figures": figures}),
            plotly=plotly_js,
            common=COMMON_JS,
            script=SUBNET_JS,
        )
        (directory / f"subnet-{subnet_id}.html").write_text(document, encoding="utf-8")


def generate_html(snapshot, output):
    """Write summary.html for one snapshot, plus traffic-<node>.html beside it."""
    try:
        from plotly.offline import get_plotlyjs
    except ImportError as error:
        raise RuntimeError("Plotly is required to generate summary.html; run with the analyze dependency group") from error
    plotly_js = get_plotlyjs().replace("</script", "<\\/script")
    metrics = snapshot["metrics"]
    metadata = snapshot.get("metadata", {})
    population = metrics.get("population")
    traffic = metrics.get("traffic") or {}
    run = metadata.get("run_id") or Path(snapshot["output_dir"]).name
    figures = {"cdf": cdf_figure(metrics), "arrival": arrival_figure(metrics)}
    subnet_proofs = subnet_proofs_figure(metrics)
    subnet_section = ""
    if subnet_proofs:
        figures["subnet-proofs"] = subnet_proofs
        rows = metrics["subnet_proofs"]
        subnet_section = (
            '<section aria-labelledby="subnet-proofs-heading"><h2 id="subnet-proofs-heading">Subnet proof times</h2>'
            f'<p class="caption">When each aggregator of a subnet finished its subnet proof: {sum(row["count"] for row in rows):,} proofs '
            f'over {len(rows)} subnets. Whiskers span the first to the last aggregator, the box p25 to p75, and the line is the median. '
            'Each dot is one aggregator, coloured by host class; hover a dot for its node. '
            'Click a subnet label to open its page.</p>'
            f'<div class="chart" id="subnet-proofs" style="height:{subnet_proofs_height(rows)}px"></div></section>'
        )
    if population:
        figures["validators"] = validators_figure(population)
        figures["countries"] = countries_figure(population)
    facts = [f"seed {metadata['seed']}" if metadata.get("seed") is not None else None,
             f"local threshold {metadata['local_threshold']:.0%}" if metadata.get("local_threshold") else None,
             f"recursive aggregation, arity {metrics['recursive_aggregation']['arity']}" if (metrics.get("recursive_aggregation") or {}).get("arity") else None]
    previews = ""
    if traffic:
        previews = ('<section aria-labelledby="traffic"><h2 id="traffic">Traffic profiles</h2>'
                    '<p class="caption">Hosts that kept traffic logs. Sent above zero, received below, in MB/s from run start. Open a profile for the full timeline and its peers.</p>'
                    + preview_cards(traffic) + "</section>")
    messages = len({row["message"] for row in metrics.get("arrivals") or []})
    document = SUMMARY_TEMPLATE.substitute(
        run=html.escape(str(run)),
        css=PAGE_CSS,
        facts=html.escape(" · ".join(fact for fact in facts if fact)),
        kpis=kpis(metrics),
        config=config_section(metadata.get("config"), metrics),
        network=network_section(population),
        arrival_height=max(260, 70 * messages + 110),
        arrival_table=arrival_table(metrics),
        subnet_proofs=subnet_section,
        previews=previews,
        generated=html.escape(snapshot.get("generated_at", "")[:19].replace("T", " ") + " UTC"),
        output_dir=html.escape(snapshot["output_dir"]),
        t0=html.escape(seconds(metrics.get("t0_ms")) + " after run start"),
        data=json_data({"figures": figures, "previews": traffic}),
        plotly=plotly_js,
        common=COMMON_JS,
        script=SUMMARY_JS,
    )
    output.write_text(document, encoding="utf-8")
    generate_traffic_html(snapshot, output.parent, plotly_js)
    generate_subnet_html(snapshot, output.parent, plotly_js)
