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
