"""Render summary.html and traffic-<node>.html from one analysis snapshot.

Both pages are white and screenshot-friendly, share one stylesheet, one
Plotly theme and one traffic-series builder, and are self-contained: Plotly
is inlined and the data is embedded as JSON, so nothing loads from the network.
"""

import html
import json
import math
from collections import Counter
from pathlib import Path
from string import Template


# Host classes in display order: plural label, singular label, colour (ff-workshop palette).
CLASS_STYLE = {
    "supernode": ("Supernodes", "supernode", "#2a78d6"),
    "regular": ("Regular nodes", "regular node", "#e34948"),
    "unknown": ("Unclassified", "unclassified", "#898781"),
}
SINGULAR_LABEL = {kind: singular.capitalize() for kind, (_, singular, _) in CLASS_STYLE.items()}
# A class's churny hosts are reported apart from its stable ones, as "<class>_churny".
CHURNY = "_churny"
GROUPS = tuple(group for kind in CLASS_STYLE for group in (kind, kind + CHURNY))
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
    if card.get("churn"):
        parts.append(f'churny, {plural(card["churn"]["crashes"], "crash", "crashes")}')
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


def group_styles(present):
    """{group: (label, colour, churny)} for the host groups in `present`, in
    display order. A class's churny hosts keep its colour; when a class has
    both, its other hosts are labelled stable."""
    present = set(present)
    styles = {}
    for group in GROUPS:
        if group not in present:
            continue
        kind = group.removesuffix(CHURNY)
        label, _, color = CLASS_STYLE[kind]
        churny = group.endswith(CHURNY)
        if churny:
            label += " (churny)"
        elif kind + CHURNY in present:
            label += " (stable)"
        styles[group] = (label, color, churny)
    return styles


def swatch(color, churny=False):
    """A colour key for a table cell; hollow for churny hosts."""
    style = f"background:#ffffff;border:2px solid {color}" if churny else f"background:{color}"
    return f'<span class="swatch" style="{style}"></span>'


def cdf_figure(metrics):
    """Signature propagation: first sighting anywhere, and delivery to each host class."""
    return cdf_figure_for(metrics.get("signature_cdf") or {})


def cdf_figure_for(lines):
    """The CDF plot used by the run summary and every subnet page."""
    series = [("first_seen", "First seen by any host", "#0b0b0b", "dot")]
    series += [(group, "Delivered to " + label[0].lower() + label[1:], color, "dash" if churny else "solid")
               for group, (label, color, churny) in group_styles(lines).items()]
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
    layout = {
        "xaxis": {"title": {"text": "time after the first signature was sent (s)"}, "rangemode": "tozero"},
        "yaxis": {"title": {"text": "signatures"}, "range": [0, 101], "ticksuffix": "%"},
        "legend": {"orientation": "h", "x": 0, "y": 1.12},
    }
    if len(data) > 3:
        # Churny hosts add lines: the legend wraps, so it grows upwards into a taller margin.
        layout["legend"] = {"orientation": "h", "x": 0, "y": 1.02, "yanchor": "bottom"}
        layout["margin"] = {"t": 64}
    return {"data": data, "layout": layout}


def arrival_figure(metrics):
    """Slide-8 style boxes: p5–p95 whiskers, p25–p75 box, median line, per message and host class."""
    rows = metrics.get("arrivals") or []
    data = []
    for group, (label, color, churny) in group_styles(row["class"] for row in rows).items():
        own = [row for row in rows if row["class"] == group]
        data.append({
            "type": "box", "orientation": "h", "name": label, "y": [row["message"] for row in own],
            "lowerfence": [row["p5"] / 1000 for row in own], "q1": [row["p25"] / 1000 for row in own],
            "median": [row["p50"] / 1000 for row in own], "q3": [row["p75"] / 1000 for row in own],
            "upperfence": [row["p95"] / 1000 for row in own],
            "marker": {"color": color}, "line": {"color": color, "width": 1.5},
            # Churny hosts get a hollow box.
            "fillcolor": "#ffffff" if churny else color + "40",
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
    dots = {group: {"x": [], "y": [], "text": [], "customdata": []} for group in GROUPS}
    for row in rows:
        for rank, (time_ms, node_id, group) in enumerate(row["proofs"]):
            dot = dots[group if group in dots else "unknown"]
            dot["x"].append(time_ms / 1000)
            dot["y"].append(round(row["subnet"] + offsets[rank % len(offsets)], 3))
            dot["text"].append("unknown node" if node_id is None else f"node {node_id}")
            dot["customdata"].append(row["subnet"])
    for group, (label, color, churny) in group_styles(group for group in GROUPS if dots[group]["x"]).items():
        # Churny aggregators are hollow dots.
        marker = ({"color": color, "size": 7, "symbol": "circle-open", "line": {"color": color, "width": 1.5}} if churny
                  else {"color": color, "size": 6, "opacity": 0.8, "line": {"color": "#ffffff", "width": 0.5}})
        data.append({
            "type": "scatter", "mode": "markers", "name": label, **dots[group], "marker": marker,
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


def bin_figure(bins, x_title, hover_unit):
    """Hosts per bin, stacked by class, with each bar's total above it."""
    labels = [str(item["low"]) if item["low"] == item["high"] else f"{item['low']}–{item['high']}" for item in bins]
    data = [{
        "type": "bar", "name": label, "x": labels, "y": [item[kind] for item in bins],
        "marker": {"color": color}, "customdata": [item["validators"] for item in bins],
        "hovertemplate": "%{y} hosts with %{x} " + hover_unit + "<br>%{customdata:,} validators in this bin<extra>" + label + "</extra>",
    } for kind, (label, _, color) in CLASS_STYLE.items() if any(item[kind] for item in bins)]
    totals = [item["supernode"] + item["regular"] + item["unknown"] for item in bins]
    annotations = [{"x": label, "y": total, "text": f"{total:,}", "showarrow": False, "yanchor": "bottom",
                    "font": {"size": 12, "color": "#52514e"}} for label, total in zip(labels, totals) if total]
    return {"data": data, "layout": {
        "barmode": "stack", "annotations": annotations,
        "xaxis": {"title": {"text": x_title}, "type": "category", "tickangle": -45},
        "yaxis": {"title": {"text": "hosts"}, "rangemode": "tozero"},
        "legend": {"orientation": "h", "x": 0, "y": 1.12, "traceorder": "normal"},
    }}


def validators_figure(population):
    """Hosts per validator-count bin, stacked by class, with each bar's total above it."""
    return bin_figure(population["validators_per_host"], "validators on the host", "validators")


def subnet_counts_figure(aggregators):
    """Hosts per bin of how many subnets they aggregate, stacked by class."""
    return bin_figure(aggregators["subnets_per_host"], "subnets aggregated on the host", "subnets")


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


def plural(number, singular, many=None):
    return f"{number:,} {singular if number == 1 else many or singular + 's'}"


def aggregator_table(info, row, logged):
    """One row per aggregator of a subnet, ordered by when it finished the subnet proof
    (aggregators without one last); node ids link to traffic pages when logged."""
    aggregators = info.get("aggregators") or []
    if not aggregators:
        return ""
    proof_ms = {node_id: time_ms for time_ms, node_id, _ in (row or {}).get("proofs") or []}
    ordered = sorted(aggregators, key=lambda host: (host["node"] not in proof_ms, proof_ms.get(host["node"], 0), host["node"]))
    # Runs with churn say which aggregators churn and how often they crashed.
    churn = info.get("churn") is not None
    rows = []
    for host in ordered:
        _, _, color = CLASS_STYLE.get(host["class"], CLASS_STYLE["unknown"])
        node = str(host["node"])
        cell = f'<a href="traffic-{node}.html">{node}</a>' if node in logged else node
        finished = f'{proof_ms[host["node"]] / 1000:.2f} s' if host["node"] in proof_ms else "–"
        churned = ""
        if churn:
            churned = f'<td>{plural(host["crashes"], "crash", "crashes") if "crashes" in host else "stable"}</td>'
        rows.append(
            f'<tr><td>{cell}</td><td>{html.escape((host.get("country") or "unknown").title())}</td>'
            f'<td><span class="swatch" style="background:{color}"></span>{SINGULAR_LABEL[host["class"]]}</td>'
            f'<td>{count(host.get("uplink_mbps"))} Mbps</td><td>{count(host.get("downlink_mbps"))} Mbps</td>'
            f'<td>{count(host["validators"])}</td>{churned}<td>{finished}</td></tr>'
        )
    return ('<div class="table-scroll"><table class="aggregators"><thead><tr><th>Node</th><th>Country</th><th>Class</th>'
            '<th>Uplink</th><th>Downlink</th><th>Validators</th>' + ("<th>Churn</th>" if churn else "")
            + '<th>Subnet proof</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def aggregator_section(info, row, logged, height):
    """Where this subnet's aggregators are and what kind of host they are."""
    aggregators = info.get("aggregators") or []
    if not aggregators:
        return ""
    classes = Counter(host["class"] for host in aggregators)
    split = [plural(classes["supernode"], "supernode"), plural(classes["regular"], "regular node")]
    if classes["unknown"]:
        split.append(f'{classes["unknown"]:,} unclassified')
    countries = len(info.get("aggregator_countries") or [])
    verb = "aggregates" if len(aggregators) == 1 else "aggregate"
    return (
        '<section aria-labelledby="aggregators-heading"><h2 id="aggregators-heading">Aggregators</h2>'
        f'<p class="caption">{plural(len(aggregators), "host")} {verb} this subnet: {", ".join(split)}, '
        f'in {plural(countries, "country", "countries")}. The chart shows aggregators per country (stacked by host class) '
        'and the validators they run. The table lists each aggregator, earliest subnet proof first; times are after the first '
        'signature was sent.</p>'
        f'<div class="chart" id="subnet-aggregators" style="height:{height}px"></div>'
        + aggregator_table(info, row, logged) + "</section>"
    )


def subnet_info(metrics, subnet_id):
    """Subscriber info for one subnet; keys may be strings after a JSON round-trip."""
    hosts = metrics.get("subnet_hosts") or {}
    return hosts.get(subnet_id) or hosts.get(str(subnet_id)) or {"classes": {}, "countries": []}


def subnet_page_figures(metrics, subnet_id):
    """CDF of this subnet's signature deliveries, plus its subscriber breakdown."""
    info = subnet_info(metrics, subnet_id)
    by_subnet = metrics.get("signature_cdf_by_subnet") or {}
    lines = by_subnet.get(subnet_id) or by_subnet.get(str(subnet_id)) or {}
    figures = {
        "subnet-cdf": cdf_figure_for(lines),
        "subnet-subscribers": subscribers_figure(info),
    }
    if info.get("aggregators"):
        figures["subnet-aggregators"] = countries_figure({"countries": info["aggregator_countries"]})
    return figures


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
.kpis.five { grid-template-columns: repeat(5, minmax(0, 1fr)); }
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
.aggregators td:nth-child(-n+3), .aggregators th:nth-child(-n+3) { text-align: left; }
.churn .note { color: var(--muted); font-size: 12px; margin-left: 4px; }
.transport td.note { text-align: left; color: var(--muted); font-size: 12px; white-space: normal; }
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
@media (max-width: 760px) { main { padding: 24px 16px 40px; } .kpis, .kpis.five { grid-template-columns: 1fr 1fr; } .two, .config-grid { grid-template-columns: 1fr; } }
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
  // A churny host exchanged nothing while offline: pin the areas to zero at both
  // edges of each offline window, so no curve spans it.
  for (const [start, end] of traffic.offline_ms || []) {
    for (const at of [start, end]) {
      if (!frames.some(frame => frame.start_ms <= at && at < frame.start_ms + frame.width_ms)) {
        frames.push({start_ms: at, inbound: {}, outbound: {}, width_ms: traffic.bucket_ms});
      }
    }
  }
  frames.sort((a, b) => a.start_ms - b.start_ms);
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
// Red bands over the stretches a churny host was offline.
function offlineShapes(traffic) {
  return (traffic.offline_ms || []).map(([start, end]) => ({type: 'rect', xref: 'x', yref: 'paper',
    x0: start / 1000, x1: end / 1000, y0: 0, y1: 1, fillcolor: '#e34948', opacity: 0.1, line: {width: 0}, layer: 'below'}));
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
const previews = Object.entries(report.previews).map(([node, traffic]) => [node, trafficSeries(traffic), traffic]);
const previewEnd = Math.max(1, ...previews.map(([, series]) => series.end));
for (const [node, series, traffic] of previews) {
  Plotly.newPlot('preview-' + node, series.traces, plotLayout({
    showlegend: false, margin: {t: 4, r: 8, b: 26, l: 40}, shapes: offlineShapes(traffic),
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
shapes.push(...offlineShapes(traffic));
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
    arrivals = metrics.get("arrivals") or []
    styles = group_styles(row["class"] for row in arrivals)
    rows = "".join(
        f'<tr><td>{html.escape(row["message"])}</td>'
        f'<td>{swatch(styles[row["class"]][1], styles[row["class"]][2])}{styles[row["class"]][0]}</td>'
        f'<td>{count(row["count"])}</td>' + "".join(f"<td>{seconds(row[key])}</td>" for key in ("p5", "p25", "p50", "p75", "p95"))
        + "</tr>"
        for row in arrivals
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
    for key, label in (("gossipsub_flood_publish", "Flood publish"), ("gossipsub_gossip", "IHAVE/IWANT gossip"),
                       ("gossipsub_idontwant", "IDONTWANT")):
        if key in config:
            gossip.append((label, "on" if config[key] else "off", ""))
    if "gossipsub_idontwant_threshold_bytes" in config:
        threshold = config["gossipsub_idontwant_threshold_bytes"]
        gossip.append(("IDONTWANT", f"over {threshold:,} B" if threshold else "off", "gossipsub v1.2, backported"))
    if "signature_sync" in config:
        mode = config["signature_sync"]
        names = {"none": "gossip only", "bitmap_pull": "bitmap pull", "coded_repair": "coded repair"}
        note = ""
        if mode != "none" and has("sync_interval_ms", "sync_grace_ms"):
            note = f'bitmaps every {config["sync_interval_ms"]:,} ms, {config["sync_grace_ms"]:,} ms grace'
            if mode == "coded_repair" and has("sync_coded_degree", "sync_coded_redundancy"):
                degree = config["sync_coded_degree"] or "log2(gaps)+2"
                note += f', degree {degree}, redundancy {config["sync_coded_redundancy"]}'
        gossip.append(("Signature sync", names.get(mode, str(mode)), note))
    def bundle_note(note):
        if has("bundle_tick_ms", "bundle_max_signatures"):
            tick = config["bundle_tick_ms"]
            note = (f'{"every arrival" if tick == 0 else f"every {tick:,} ms"}, '
                    f'at most {config["bundle_max_signatures"]} a bundle; {note}')
        if config.get("bundle_stagger_ms"):
            note += f'; one end of each link waits {config["bundle_stagger_ms"]:,} ms'
            if config.get("bundle_announce"):
                note += " and announces"
        if config.get("bundle_request_delay_ms"):
            note += f'; requests wait {config["bundle_request_delay_ms"]:,} ms'
        return note

    if config.get("signature_transport") == "waggle":
        push = config.get("waggle_push_peers")
        if config.get("waggle_push_selection") == "hashed":
            note = ("a hash of each signature and the two peer ids names the end of a link that sends it; "
                    + ("pushed to every subscriber it names this host for" if not push
                       else f"pushed to at most {push:,} of the subscribers it names this host for"))
        else:
            note = "" if push is None else ("pushes to every subscriber of a subnet" if push == 0
                                            else f"pushes to {push:,} subscribers of a subnet")
        if config.get("waggle_gossip_peers"):
            interval = config.get("waggle_gossip_interval_ms") or config.get("gossipsub_heartbeat_interval_ms")
            note += (f'{"; " if note else ""}advertises to {config["waggle_gossip_peers"]:,} others'
                     + (f" every {interval:,} ms" if interval else ""))
        gossip.append(("Transport", "waggle", note))
        if config.get("waggle_bundled", True):
            gossip.append(("Propagation", "bundled", bundle_note("EIP-8334 over waggle")))
        else:
            gossip.append(("Propagation", "single", "one waggle message per signature, forwarded on receipt"))
    elif config.get("signature_propagation") == "bundled":
        gossip.append(("Propagation", "bundled", bundle_note("EIP-8334 over gossipsub partial messages")))
    elif "signature_propagation" in config:
        gossip.append(("Propagation", "gossipsub", "one message per signature"))
    churn = []
    tick = config.get("churn_tick_ms") or 100
    for kind in ("supernode", "regular"):
        fraction = config.get(f"{kind}_churn_fraction")
        if fraction is None:
            continue
        label = CLASS_STYLE[kind][0]
        if not fraction:
            churn.append((label, "stable", "never offline"))
            continue
        leave = config.get(f"{kind}_churn_leave_probability") or 0
        rejoin = config.get(f"{kind}_churn_rejoin_probability") or 0
        note = f"a churny host crashes with probability {leave:g} a tick and rejoins with {rejoin:g}"
        if leave and rejoin:
            note += (f": {tick / leave / 1000:.1f} s sessions, {tick / rejoin / 1000:.1f} s gaps, "
                     f"online {rejoin / (leave + rejoin):.0%} of the time")
        churn.append((label, f"{fraction * 100:g}% churny", note))
    if any(value != "stable" for _, value, _ in churn):
        idle = ((metrics.get("churn") or {}).get("idle_timeout_ms") or 10_000) / 1000
        churn.append(("Tick", f"{tick:,} ms", ""))
        churn.append(("Crash", "silent", f"all state lost but the peer table; peers hold the dead connection up to {idle:g} s"))
    else:
        churn = []
    groups = (("Signatures", signatures), ("Aggregation", aggregation), ("Gossip", gossip), ("Churn", churn))
    return [(title, rows) for title, rows in groups if rows]


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


TRANSPORT_LABELS = (
    ("gossip_signatures", "Gossiped signatures", "every copy received, duplicates included"),
    ("pulled_signatures", "Pulled signatures", "answers to bitmap pulls"),
    ("bundled_signatures", "Bundled signatures", "every copy received with its index, duplicates included"),
    ("bundle_framing", "Bundle framing", "what bundle frames add to their signatures"),
    ("parts_metadata", "Parts metadata", "validator indices advertised to gossip peers and requested"),
    ("coded_packets", "Coded repair packets", "one signature-sized payload each"),
    ("bitmaps", "Bitmaps", "held-signature bitmaps to mesh neighbours"),
    ("pull_requests", "Pull requests", ""),
    ("gossip_control", "Gossipsub control ids", "IHAVE, IWANT, IDONTWANT"),
    ("sync_acks", "Sync acks", ""),
)


def mesh_facts(mesh):
    """Mesh degree and copies per mesh link, as caption sentences."""
    if not mesh or not mesh.get("degree"):
        return []
    sample = mesh.get("links_sampled_at")
    degree = mesh["degree"].get(sample) or next(iter(mesh["degree"].values()))
    facts = [f'mesh degree {degree["mean"]:.1f} on average ({degree["min"]}–{degree["max"]}) at {sample}']
    if mesh.get("copies_per_link") is not None:
        facts.append(f'{mesh["copies_per_link"]:.2f} copies of a signature per mesh link; one per link would leave '
                     f'{mesh["one_copy_per_link_duplicates_per_first_copy"]:.2f} pushed duplicates per first copy '
                     f'instead of {mesh["push_duplicates_per_first_copy"]:.2f}')
    return facts


def transport_section(metrics):
    """Deliveries by path and the wire-byte ledger of signature transport."""
    transport = metrics.get("signature_transport")
    if not transport:
        return ""
    wire = transport["wire_bytes"]
    total = wire.get("total") or 0
    hosts = transport.get("hosts") or 1
    rows = "".join(
        f'<tr><td>{label}</td><td>{wire.get(key, 0) / 1e6:,.1f} MB</td><td>{share(wire.get(key, 0), total)}</td>'
        f'<td>{wire.get(key, 0) / hosts / 1e3:,.0f} kB</td><td class="note">{html.escape(note)}</td></tr>'
        for key, label, note in TRANSPORT_LABELS
        if wire.get(key)
    )
    rows += (f'<tr><th scope="row">Total</th><td><b>{total / 1e6:,.1f} MB</b></td><td></td>'
             f'<td><b>{total / hosts / 1e3:,.0f} kB</b></td><td></td></tr>')
    deliveries = transport["deliveries"]
    # With churn: signatures a host got again after losing them in a crash, by path.
    relearned = ((metrics.get("churn") or {}).get("counters") or {}).get("relearned")
    delivery_rows = "".join(
        f'<tr><td>{name}</td><td>{count(deliveries[via]["unique"])}</td><td>{count(deliveries[via]["duplicate"])}</td>'
        + (f"<td>{count(relearned.get(via, 0))}</td>" if relearned is not None else "") + "</tr>"
        for via, name in (("gossip", "Gossip"), ("pull", "Pull"), ("coded", "Coded repair"),
                          ("bundle", "Bundle push"), ("backlog", "Bundle backlog"),
                          ("requested", "Bundle request"))
        if via in deliveries and (deliveries[via]["unique"] or deliveries[via]["duplicate"] or (relearned or {}).get(via))
    )
    c = transport["counters"]
    facts = [f'{count(c["idontwant_ids_sent"])} IDONTWANT sent, {count(c["forwards_suppressed"] + c.get("queued_forwards_dropped", 0))} forwards avoided']
    if c.get("iwant_responses"):
        facts.append(f'{count(c["iwant_responses"])} IWANT responses, {count(c.get("iwant_response_duplicates", 0))} already held on arrival')
    if c.get("bundles_sent"):
        facts.append(f'{count(c["bundle_sigs_sent"])} signatures sent in {count(c["bundles_sent"])} bundles, '
                     f'{count(c.get("pushes_avoided", 0))} pushes avoided by waiting for the tick'
                     + (f', {count(c["backlog_sigs_sent"])} pushed as backlog to new mesh peers' if c.get("backlog_sigs_sent") else "")
                     + (f', {count(c["lazy_sigs_sent"])} pushed after the stagger ran out' if c.get("lazy_sigs_sent") else "")
                     + (f', {count(c["announce_ids_sent"])} announced to mesh peers' if c.get("announce_ids_sent") else ""))
    if c.get("metadata_sent"):
        facts.append(f'{count(c["metadata_sent"])} parts metadata, {count(c.get("available_ids_sent", 0))} indices advertised, '
                     f'{count(c.get("request_ids_sent", 0))} requested, {count(c.get("requested_sigs_served", 0))} served'
                     + (f', {count(c["requests_suppressed"])} not re-requested while in flight' if c.get("requests_suppressed") else "")
                     + (f', {count(c["requests_avoided"])} arrived during the request delay' if c.get("requests_avoided") else ""))
    if c.get("invalid_partials"):
        facts.append(f'{count(c["invalid_partials"])} malformed bundles or metadata dropped')
    if c.get("frames_unsent"):
        facts.append(f'{count(c["frames_unsent"])} bundles or metadata turned away by a full send queue and sent again')
    facts.extend(mesh_facts(metrics.get("mesh")))
    if c["have_sent"]:
        facts.append(f'{count(c["have_sent"])} bitmaps')
    if c["want_sent"]:
        facts.append(f'{count(c["want_ids_sent"])} signatures pulled in {count(c["want_sent"])} requests, {count(c["pulled_duplicates"])} already held on arrival')
    if c["coded_sent"]:
        facts.append(f'{count(c["coded_sent"])} coded packets, {count(c["coded_innovative"])} innovative, {count(c["coded_decoded"])} signatures decoded'
                     + (f', {count(c["coded_mismatches"])} decode mismatches' if c["coded_mismatches"] else ""))
    return (
        '<section aria-labelledby="transport"><h2 id="transport">Signature transport</h2>'
        '<p class="caption">Bytes spent moving subnet signatures, summed over hosts (application-level sizes; QUIC and libp2p framing excluded). '
        'Per host divides by the hosts that logged transport stats.</p>'
        '<div class="table-scroll"><table class="transport"><thead><tr><th>Traffic</th><th>Bytes</th><th>Share</th><th>Per host</th><th></th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div>'
        '<div class="table-scroll"><table class="deliveries"><thead><tr><th>Delivered by</th><th>First copies</th><th>Duplicates</th>'
        + ("<th>Got again after a crash</th>" if relearned is not None else "") + '</tr></thead>'
        f'<tbody>{delivery_rows}</tbody></table></div>'
        f'<p class="caption">{html.escape("; ".join(facts))}.</p></section>'
    )


def kpis(metrics):
    population = metrics.get("population") or {}
    supernodes = sum(item["hosts"] for item in population.get("classes", []) if item["class"] == "supernode")
    signature_p95 = {row["class"]: row["p95"] for row in metrics.get("arrivals") or [] if row["message"] == "Signatures"}
    final = (metrics.get("recursive_aggregation") or {}).get("final_proof_ms")
    churn = metrics.get("churn")
    # With churn the class rows are the hosts that never go offline.
    stable = "stable " if churn else ""
    cells = [
        ("Hosts", count(population.get("hosts")), f"{supernodes:,} supernodes" if population else ""),
        ("Validators", count(population.get("validators") or metrics.get("unique_validators")), f'{count(metrics.get("signing_hosts"))} signing hosts'),
        ("Signature delivery p95", seconds(signature_p95.get("regular", signature_p95.get("unknown"))),
         f'{stable}regular nodes · {stable}supernodes {seconds(signature_p95.get("supernode"))}'),
        ("Final proof", seconds(final - metrics["t0_ms"]) if final is not None else "–", "first host to hold it"),
    ]
    if churn and churn.get("online_at_signing") is not None:
        offline = churn["hosts"] - churn["online_at_signing"]
        cells.insert(2, ("Online at signing", share(churn["online_at_signing"], churn["hosts"]),
                         f'{offline:,} of {churn["hosts"]:,} hosts offline · {churn["missed_signatures"]:,} signatures missed'))
    return f'<div class="kpis{" five" if len(cells) == 5 else ""}">' + "".join(
        f'<div class="kpi"><span class="label">{label}</span><b>{value}</b><span class="note">{html.escape(note)}</span></div>'
        for label, value, note in cells
    ) + "</div>"


def availability_figure(churn, milestones, t0):
    """Share of hosts online over the run, all hosts and each class with churny ones."""
    series = [("all", "All hosts", "#0b0b0b", "dot")]
    series += [(kind, label, color, "solid") for kind, (label, _, color) in CLASS_STYLE.items()]
    data = []
    lowest = 100
    for key, name, color, dash in series:
        points = churn["availability"].get(key) or []
        if not points:
            continue
        lowest = min(lowest, min(point[1] for point in points))
        data.append({
            "type": "scatter", "mode": "lines", "name": name,
            "x": [point[0] / 1000 for point in points], "y": [point[1] for point in points],
            "line": {"color": color, "width": 2, "dash": dash, "shape": "hv"},
            "hovertemplate": "%{y:.1f}% online at %{x:.1f} s<extra>" + name + "</extra>",
        })
    shapes, annotations = [], []
    for index, point in enumerate(milestones):
        at = (point["time_ms"] - t0) / 1000
        shapes.append({"type": "line", "xref": "x", "yref": "paper", "x0": at, "x1": at, "y0": 0, "y1": 1,
                       "line": {"color": "#898781", "width": 1, "dash": "dot"}, "layer": "below"})
        annotations.append({"xref": "x", "yref": "paper", "x": at, "y": 1.14 if index % 2 else 1.01, "yanchor": "bottom",
                            "text": f'{point["label"]} · {at:.2f} s', "showarrow": False, "xanchor": "left",
                            "font": {"color": "#52514e", "size": 12}})
    return {"data": data, "layout": {
        "xaxis": {"title": {"text": "time after the first signature was sent (s)"}},
        "yaxis": {"title": {"text": "hosts online"}, "range": [max(0, math.floor(lowest - 2)), 100.5], "ticksuffix": "%"},
        "legend": {"orientation": "h", "x": 0, "y": -0.22},
        "shapes": shapes, "annotations": annotations, "margin": {"t": 64, "b": 84},
    }}


def catch_up_figure(churn):
    """Share of rejoins that held their subnet's signatures again, by time since the rejoin."""
    data = []
    for kind, (label, _, color) in CLASS_STYLE.items():
        points = (churn["catch_up"].get(kind) or {}).get("cdf") or []
        if points:
            data.append({
                "type": "scatter", "mode": "lines", "name": label,
                "x": [0] + [point[0] / 1000 for point in points], "y": [0] + [point[1] for point in points],
                "line": {"color": color, "width": 2.5, "shape": "hv"},
                "hovertemplate": "%{y:.1f}% within %{x:.2f} s<extra>" + label + "</extra>",
            })
    return {"data": data, "layout": {
        "xaxis": {"title": {"text": "time after the host rejoined (s)"}, "rangemode": "tozero"},
        "yaxis": {"title": {"text": "rejoins caught up"}, "range": [0, 101], "ticksuffix": "%"},
        "legend": {"orientation": "h", "x": 0, "y": 1.12},
    }}


def churn_class_table(churn):
    rows = []
    for item in churn["classes"]:
        label, _, color = CLASS_STYLE[item["class"]]
        online = item["online_at_signing"]
        rows.append(
            f'<tr><td>{swatch(color)}{label}</td><td>{count(item["hosts"])}</td>'
            f'<td>{count(item["churny"])} <span class="note">{share(item["churny"], item["hosts"])}</span></td>'
            f'<td>{count(online)}' + (f' <span class="note">{share(online, item["hosts"])}</span>' if online is not None else "") + '</td>'
            f'<td>{count(item["crashes"])}</td><td>{count(item["rejoins"])}</td>'
            f'<td>{count(item["churny_validators"])} <span class="note">of {count(item["validators"])}</span></td>'
            f'<td>{count(item["missed_signatures"])} <span class="note">{share(item["missed_signatures"], item["validators"])}</span></td></tr>'
        )
    return ('<div class="table-scroll"><table class="churn"><thead><tr><th>Class</th><th>Hosts</th><th>Churny</th>'
            '<th>Online at signing</th><th>Crashes</th><th>Rejoins</th><th>Validators on churny hosts</th>'
            '<th>Signatures missed</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def catch_up_table(churn):
    rows = "".join(
        f'<tr><td>{swatch(color)}{label}</td><td>{count(row["rejoins"])}</td>'
        f'<td>{count(row["caught_up"])} <span class="note">{share(row["caught_up"], row["rejoins"])}</span></td>'
        f'<td>{seconds(row["p50"])}</td><td>{seconds(row["p95"])}</td></tr>'
        for kind, (label, _, color) in CLASS_STYLE.items()
        for row in [churn["catch_up"].get(kind)] if row
    )
    return ('<div class="table-scroll"><table class="churn"><thead><tr><th>Class</th><th>Rejoins × subnets</th><th>Caught up</th>'
            '<th>Median</th><th>p95</th></tr></thead><tbody>' + rows + "</tbody></table></div>")


def completion_table(churn):
    """Subnet completion of the hosts that never go offline beside the churny ones."""
    rows = []
    for key, label in (("stable", "Stable hosts"), ("churny", "Churny hosts")):
        row = (churn.get("completion") or {}).get(key)
        if not row:
            continue
        cells = "".join(
            f'<td>{count(row[level]["reached"])} <span class="note">{share(row[level]["reached"], row["pairs"])}</span></td>'
            f'<td>{seconds(row[level]["p50"])}</td><td>{seconds(row[level]["p95"])}</td>'
            for level in ("90pct", "100pct")
        )
        rows.append(f'<tr><td>{label}</td><td>{count(row["pairs"])}</td>{cells}</tr>')
    if not rows:
        return ""
    return ('<h3>Subnet completion</h3>'
            '<p class="caption">Per host and subscribed subnet: when the host first held 90% and all of the subnet\'s signatures that '
            'were sent, after the first signature. A churny host counts from its first copy of each signature, even if a crash '
            'took it away later. Percentiles count pairs that never got there as never.</p>'
            '<div class="table-scroll"><table class="churn"><thead><tr><th>Hosts</th><th>Host × subnet pairs</th>'
            '<th>Held 90%</th><th>Median</th><th>p95</th><th>Held 100%</th><th>Median</th><th>p95</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>")


def churn_facts(churn):
    """Caption sentences about what the crashes cost."""
    counters = churn.get("counters") or {}
    facts = []
    if counters.get("relearned_total"):
        facts.append(f'{counters["relearned_total"]:,} signatures were received again by hosts that had lost them in a crash')
    if counters.get("restart_notices_sent"):
        facts.append(f'rejoining hosts told {counters["restart_notices_sent"]:,} peers they had restarted, and '
                     f'{counters.get("restart_reconnects", 0):,} of those still held a dead connection and reconnected')
    failed = [plural(counters[key], noun) for key, noun in (("sync_failures", "sync request"), ("failed_proof_pulls", "proof pull"))
              if counters.get(key)]
    if failed:
        facts.append(" and ".join(failed) + " failed")
    if counters.get("repeated_proofs"):
        facts.append(f'{plural(counters["repeated_proofs"], "subnet proof")} built again by an aggregator back from a crash '
                     'are not counted')
    return facts


def churn_section(metrics, milestones):
    """The Churn section and its figures; ("", {}) for a run without churn."""
    churn = metrics.get("churn")
    if not churn:
        return "", {}
    figures = {"churn-availability": availability_figure(churn, milestones, metrics.get("t0_ms") or 0)}
    idle = churn["idle_timeout_ms"] / 1000
    facts = "; ".join(churn_facts(churn))
    catch_up = ""
    if churn.get("catch_up"):
        figures["churn-catch-up"] = catch_up_figure(churn)
        catch_up = (
            '<h3>Catching up after a rejoin</h3>'
            f'<p class="caption">For every host that came online after the last signature was sent, and each subnet it subscribes '
            f'to: how long until it held {churn["catch_up_fraction"]:.0%} of the subnet\'s signatures, starting from none. '
            'A rejoin that crashed again or ran into the end of the run first never caught up.</p>'
            '<div class="chart" id="churn-catch-up"></div>' + catch_up_table(churn)
        )
    return (
        '<section aria-labelledby="churn"><h2 id="churn">Churn</h2>'
        f'<p class="caption">{churn["churny_hosts"]:,} of {churn["hosts"]:,} hosts churn. A churny host crashes without a word, '
        f'loses all state but its peer table, and dials its peers again when it rejoins. Its peers keep sending to it until '
        f'QUIC\'s idle timeout ({idle:g} s) closes the connection, unless the host is back sooner. A host that is offline '
        'when its validators should sign misses the slot.</p>'
        + churn_class_table(churn)
        + (f'<p class="caption">{html.escape(facts[0].upper() + facts[1:])}.</p>' if facts else "")
        + '<h3>Hosts online</h3>'
        '<p class="caption">Share of hosts online over the run, from the hosts\' own logs. Stable hosts are always online, '
        'so a class dips by its churny hosts that are offline.</p>'
        '<div class="chart" id="churn-availability"></div>'
        + catch_up + completion_table(churn) + '</section>'
    ), figures


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
$churn
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
$transport
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
<p class="caption" id="curve-note">Curved display: interpolation only; totals, peak and hover values use raw buckets.</p>$offline_note</section>
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
$aggregators
<section aria-labelledby="subscribers-heading"><h2 id="subscribers-heading">Subscribed hosts</h2>
<p class="caption">Hosts subscribed to this subnet by country (stacked by host class), with the validators they run. The left bars are hosts, the right bars validators.</p>
<div class="chart" id="subnet-subscribers" style="height:${subscribers_height}px"></div></section>
</main><script id="subnet-data" type="application/json">$data</script><script>$plotly</script><script>$common</script><script>$script</script></body></html>
""")


def aggregator_network_section(aggregators):
    """Where the run's subnet aggregators are and how many subnets each covers."""
    classes = Counter(host["class"] for host in aggregators["classes"] for _ in range(host["hosts"]))
    split = [plural(classes["supernode"], "supernode"), plural(classes["regular"], "regular node")]
    if classes["unknown"]:
        split.append(f'{classes["unknown"]:,} unclassified')
    countries = len(aggregators["countries"])
    return (
        '<h3>Subnet aggregators</h3>'
        f'<p class="caption">{plural(aggregators["hosts"], "host")} aggregates subnets: {", ".join(split)}, '
        f'over {plural(aggregators["subnets"], "subnet")}, in {plural(countries, "country", "countries")}. '
        'The left chart is hosts per number of subnets aggregated, stacked by host class; the right one is '
        'aggregators and their validators per country.</p>'
        + class_table(aggregators)
        + '<div class="two"><div><h3>Subnets per aggregator</h3><div class="chart" id="subnet-counts"></div></div>'
        '<div><h3>Aggregators by country</h3>'
        f'<div class="chart" id="aggregator-countries" style="height:{26 * countries + 110}px"></div></div></div>'
    )


def network_section(population, aggregators=None):
    if not population:
        return '<section><h2>Network</h2><p class="caption">run-manifest.json has no node list, so host classes, validators per host and locations are unavailable.</p></section>'
    return (
        '<section aria-labelledby="network"><h2 id="network">Network</h2>'
        f'<p class="caption">{population["hosts"]:,} hosts run {population["validators"]:,} validators.</p>'
        + class_table(population)
        + '<div class="two"><div><h3>Validators per host</h3><div class="chart" id="validators"></div></div>'
        '<div><h3>Hosts and validators by country</h3>'
        f'<div class="chart" id="countries" style="height:{26 * len(population["countries"]) + 110}px"></div></div></div>'
        + (aggregator_network_section(aggregators) if aggregators else "")
        + '</section>'
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
        offline = logged.get("offline_ms") or []
        offline_note = ""
        if offline:
            offline_note = (f'<p class="caption">Red bands: the host was offline, {plural(len(offline), "time")} for '
                            f'{sum(end - start for start, end in offline) / 1000:,.1f} s in all. It lost all state each time.</p>')
        document = TRAFFIC_TEMPLATE.substitute(
            node=html.escape(node_id),
            offline_note=offline_note,
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
    logged = {str(node_id) for node_id in metrics.get("traffic") or {}}
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
        churn = info.get("churn")
        if churn:
            facts.append(f"{count(churn['churny'])} churny")
            if churn.get("online_at_signing") is not None:
                facts.append(f"{count(churn['online_at_signing'])} online at signing")
            if churn.get("missed_signatures") is not None:
                facts.append(f"{count(churn['missed_signatures'])} signatures missed")
        figures = subnet_page_figures(metrics, subnet_id)
        document = SUBNET_TEMPLATE.substitute(
            subnet=subnet_id,
            css=PAGE_CSS,
            facts=html.escape(" · ".join(facts)),
            run=html.escape(run),
            subscribers_height=figures["subnet-subscribers"]["layout"]["height"],
            aggregators=aggregator_section(info, row, logged,
                                           figures.get("subnet-aggregators", {}).get("layout", {}).get("height")),
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
    churn_html, churn_figures = churn_section(metrics, milestones_for(snapshot))
    figures.update(churn_figures)
    subnet_proofs = subnet_proofs_figure(metrics)
    subnet_section = ""
    if subnet_proofs:
        figures["subnet-proofs"] = subnet_proofs
        rows = metrics["subnet_proofs"]
        churn_note = ""
        if metrics.get("churn"):
            duties = sum(len(info.get("aggregators") or []) for info in (metrics.get("subnet_hosts") or {}).values())
            proofs = sum(row["count"] for row in rows)
            churn_note = " Hollow dots are churny hosts."
            if duties > proofs:
                churn_note += f" {duties - proofs:,} of {duties:,} aggregators never finished a subnet proof."
        subnet_section = (
            '<section aria-labelledby="subnet-proofs-heading"><h2 id="subnet-proofs-heading">Subnet proof times</h2>'
            f'<p class="caption">When each aggregator of a subnet finished its subnet proof: {sum(row["count"] for row in rows):,} proofs '
            f'over {len(rows)} subnets. Whiskers span the first to the last aggregator, the box p25 to p75, and the line is the median. '
            f'Each dot is one aggregator, coloured by host class; hover a dot for its node.{churn_note} '
            'Click a subnet label to open its page.</p>'
            f'<div class="chart" id="subnet-proofs" style="height:{subnet_proofs_height(rows)}px"></div></section>'
        )
    aggregators = metrics.get("aggregators")
    if population:
        figures["validators"] = validators_figure(population)
        figures["countries"] = countries_figure(population)
    if aggregators:
        figures["subnet-counts"] = subnet_counts_figure(aggregators)
        figures["aggregator-countries"] = countries_figure({"countries": aggregators["countries"]})
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
        network=network_section(population, aggregators),
        churn=churn_html,
        arrival_height=max(260, 70 * messages + 110),
        arrival_table=arrival_table(metrics),
        subnet_proofs=subnet_section,
        transport=transport_section(metrics),
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
