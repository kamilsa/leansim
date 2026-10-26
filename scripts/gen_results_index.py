#!/usr/bin/env python3
"""Generate leansim-html/index.html listing every published run directory.

Usage:
    python3 scripts/gen_results_index.py [results_dir]

Scans <results_dir> (default: leansim-html/ next to the repo root) for
subdirectories containing a run-manifest.json, and (re)writes index.html
with one row per run. Re-run this after copying new run directories into
the results folder, then commit and push: GitHub Pages serves the folder
verbatim, so index.html is the landing page.

Stdlib only; deterministic output for the same directory contents.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

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
.facts { color: var(--ink-2); margin: 0; }
section { margin: 0 0 44px; }
.caption { color: var(--ink-2); font-size: 14px; margin: 0 0 12px; max-width: 860px; }
.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin: 0 0 44px; }
.kpi { border: 1px solid var(--grid); border-radius: 10px; padding: 14px 16px; }
.kpi .label, .kpi .note { display: block; color: var(--ink-2); font-size: 13px; } .kpi .note { color: var(--muted); }
.kpi b { display: block; font-size: 26px; font-weight: 650; margin: 2px 0; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; font-size: 14px; font-variant-numeric: tabular-nums; margin: 4px 0 8px; }
th, td { padding: 8px 10px; text-align: right; border-bottom: 1px solid var(--grid); white-space: nowrap; }
th { color: var(--ink-2); font-weight: 600; } th:first-child, td:first-child { text-align: left; }
td.run a { font-weight: 600; }
td .muted { color: var(--muted); font-size: 13px; margin-left: 8px; }
.table-scroll { overflow-x: auto; }
footer.page { border-top: 1px solid var(--grid); padding-top: 14px; color: var(--muted); font-size: 13px; }
@media (max-width: 760px) { main { padding: 24px 16px 40px; } .kpis { grid-template-columns: 1fr 1fr; } }
"""

CONFIG_KEYS = (
    "validator_count",
    "subnet_count",
    "node_map",
    "local_aggregators_per_subnet",
    "local_threshold",
    "signature_payload_bytes",
    "recursive_aggregation",
    "recursive_aggregation_arity",
    "committee_aggregators",
    "subscribe_to_duty_subnets",
)


def load_run(run_dir: Path) -> dict | None:
    manifest_path = run_dir / "run-manifest.json"
    if not manifest_path.exists():
        return None
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"warning: skipping {run_dir.name}: {exc}", file=sys.stderr)
        return None
    experiment = manifest.get("experiment") or {}
    nodes = manifest.get("nodes") or []
    subnets = experiment.get("subnet_count")
    aggregators = experiment.get("local_aggregators_per_subnet")
    return {
        "dir": run_dir.name,
        "run_id": manifest.get("run_id") or experiment.get("run_id") or run_dir.name,
        "seed": manifest.get("seed"),
        "runner": manifest.get("runner"),
        "hosts": len(nodes),
        "validators": experiment.get("validator_count"),
        "subnets": subnets,
        "aggregators": aggregators,
        "threshold": experiment.get("local_threshold"),
        "mode": mode_label(experiment),
        "subnet_pages": len(list(run_dir.glob("subnet-*.html"))),
        "traffic_pages": len(list(run_dir.glob("traffic-*.html"))),
        "has_summary": (run_dir / "summary.html").exists(),
        "config": {k: experiment.get(k) for k in CONFIG_KEYS},
    }


def mode_label(experiment: dict) -> str:
    parts = []
    if experiment.get("committee_aggregators"):
        parts.append("committee")
    if experiment.get("recursive_aggregation"):
        arity = experiment.get("recursive_aggregation_arity")
        parts.append(f"recursive (arity {arity})" if arity else "recursive")
    return ", ".join(parts) if parts else "subnet aggregators"


def fmt(value) -> str:
    if value is None:
        return "—"
    return format(value, ",d") if isinstance(value, int) and not isinstance(value, bool) else html.escape(str(value))


def render(runs: list[dict], generated_note: str) -> str:
    e = html.escape
    rows = []
    for run in sorted(runs, key=lambda r: r["dir"]):
        name_cell = (
            f'<td class="run"><a href="{e(run["dir"])}/summary.html">{e(run["run_id"])}</a></td>'
            if run["has_summary"]
            else f'<td class="run">{e(run["run_id"])}<span class="muted">no summary</span></td>'
        )
        rows.append(
            "<tr>"
            + name_cell
            + f'<td>{fmt(run["seed"])}</td>'
            f'<td>{fmt(run["validators"])}</td>'
            f'<td>{fmt(run["hosts"])}</td>'
            f'<td>{fmt(run["subnets"])}</td>'
            f'<td>{fmt(run["aggregators"])}</td>'
            f'<td>{fmt(run["threshold"])}</td>'
            f'<td>{e(run["mode"])}</td>'
            f'<td>{run["subnet_pages"]} + {run["traffic_pages"]} traffic</td>'
            f'<td><a href="{e(run["dir"])}/run-manifest.json">manifest</a></td>'
            "</tr>"
        )
    total_subnet = sum(r["subnet_pages"] for r in runs)
    total_traffic = sum(r["traffic_pages"] for r in runs)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim results</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<main>
<header class="page">
  <p class="eyebrow">leanSim</p>
  <h1>Simulation results</h1>
  <p class="facts">{len(runs)} published run{"" if len(runs) == 1 else "s"} · {total_subnet} subnet pages · {total_traffic} traffic pages</p>
</header>
<section>
  <h2>Runs</h2>
  <p class="caption">One row per run directory. <b>Pages</b> counts subnet-*.html and traffic-*.html
  files in the directory; every run links to its full summary.</p>
  <div class="table-scroll">
  <table>
    <thead><tr>
      <th>Run</th><th>Seed</th><th>Validators</th><th>Hosts</th><th>Subnets</th>
      <th>Aggr./subnet</th><th>Threshold</th><th>Mode</th><th>Pages</th><th></th>
    </tr></thead>
    <tbody>
    {''.join(rows)}
    </tbody>
  </table>
  </div>
</section>
<footer class="page">{generated_note} — regenerate with <code>python3 scripts/gen_results_index.py</code>.</footer>
</main>
</body>
</html>
"""


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else repo_root / "leansim-html"
    if not results_dir.is_dir():
        sys.exit(f"results dir not found: {results_dir}")

    runs = [r for d in sorted(results_dir.iterdir()) if d.is_dir() for r in [load_run(d)] if r]
    if not runs:
        sys.exit(f"no run directories with run-manifest.json under {results_dir}")

    import datetime as dt

    note = f"Generated {dt.date.today().isoformat()} from run-manifest.json files"
    out = results_dir / "index.html"
    out.write_text(render(runs, note))
    print(f"wrote {out} ({len(runs)} runs)")


if __name__ == "__main__":
    main()
