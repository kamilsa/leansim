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
