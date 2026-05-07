#!/usr/bin/env python3
"""leanSim experiment runner for parameter sweeps.

Uses proper TOML parsing (Python 3.11+ tomllib).
Generates experiment configs from a TOML template with parameter overrides,
runs Shadow simulations, and collects results into CSV.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib

SHADOW_BIN = os.path.expanduser("~/.local/bin/shadow")
LEANSIM_BIN = "./target/release/leansim"


def run_single_experiment(
    overrides: dict,
    template_path: str,
    work_dir: str,
    run_id: str,
) -> dict | None:
    """Generate config, run Shadow, summarize, return metrics dict."""
    project_root = Path(__file__).parent.parent
    os.makedirs(work_dir, exist_ok=True)

    # Load template and apply overrides
    with open(template_path, "rb") as f:
        config = tomllib.load(f)

    config["run_id"] = run_id
    for k, v in overrides.items():
        # Support nested keys like "network_defaults.uplink_mbps"
        if "." in k:
            parts = k.split(".")
            target = config
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = v
        else:
            config[k] = v

    # Write experiment TOML
    exp_path = os.path.join(work_dir, "experiment.toml")
    toml_str = dict_to_toml(config)
    with open(exp_path, "w") as f:
        f.write(toml_str)

    # Generate shadow config
    shadow_yaml = os.path.join(work_dir, "shadow.yaml")
    result = subprocess.run(
        [LEANSIM_BIN, "gen-shadow", "--experiment", exp_path, "--out", shadow_yaml],
        capture_output=True, text=True, cwd=str(project_root),
    )
    if result.returncode != 0:
        print(f"  gen-shadow failed: {result.stderr}", file=sys.stderr)
        return None

    # Run Shadow from the work dir so relative paths (topology.gml, configs/) resolve
    shadow_log = os.path.join(work_dir, "shadow.log")
    import shutil

    # Clean up existing shadow.data
    work_shadow_data = os.path.join(work_dir, "shadow.data")
    if os.path.exists(work_shadow_data):
        shutil.rmtree(work_shadow_data, ignore_errors=True)

    # shadow.yaml is in work_dir; run Shadow from there
    start = time.time()
    result = subprocess.run(
        [SHADOW_BIN, "shadow.yaml"],
        capture_output=True, text=True, cwd=work_dir,
    )
    elapsed = time.time() - start

    work_shadow = os.path.join(work_dir, "shadow.data")
    with open(shadow_log, "w") as f:
        f.write(result.stdout)
        f.write(result.stderr)

    if result.returncode != 0 and "Failed to initialize" in result.stderr:
        print(f"  Shadow init failed: {result.stderr[-200:]}", file=sys.stderr)
        return None

    # Summarize
    metrics_path = os.path.join(work_dir, "metrics.json")
    if not os.path.exists(work_shadow):
        print(f"  No shadow.data found", file=sys.stderr)
        return None
    result = subprocess.run(
        [LEANSIM_BIN, "summarize", "--shadow-data", work_shadow, "--out", metrics_path],
        capture_output=True, text=True, cwd=str(project_root),
    )
    if result.returncode != 0:
        print(f"  summarize failed: {result.stderr}", file=sys.stderr)
        return None

    if not os.path.exists(metrics_path):
        return None

    with open(metrics_path) as f:
        metrics = json.load(f)

    metrics["wall_clock_secs"] = round(elapsed, 1)
    metrics["run_id"] = run_id
    for k, v in overrides.items():
        metrics[f"param_{k}"] = v

    return metrics


def dict_to_toml(d, prefix="") -> str:
    """Convert a nested dict to TOML string (handles top-level tables)."""
    lines = []
    tables = {}

    for k, v in d.items():
        if isinstance(v, dict):
            tables[k] = v
        elif isinstance(v, str):
            lines.append(f'{k} = "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{k} = {str(v).lower()}")
        else:
            lines.append(f"{k} = {v}")

    result = "\n".join(lines)

    for table_name, table_dict in tables.items():
        result += f"\n\n[{table_name}]\n"
        for k, v in table_dict.items():
            if isinstance(v, str):
                result += f'{k} = "{v}"\n'
            else:
                result += f"{k} = {v}\n"

    return result


def run_parameter_sweep(
    template_path: str,
    sweep_param: str,
    sweep_values: list,
    output_csv: str,
    base_dir: str = "experiments/runs",
    fixed_overrides: dict | None = None,
):
    """Run a parameter sweep: vary one parameter across values."""
    results = []
    os.makedirs(base_dir, exist_ok=True)

    for i, val in enumerate(sweep_values):
        overrides = (fixed_overrides or {}).copy()
        overrides[sweep_param] = val
        run_id = f"sweep-{sweep_param}-{val}".replace(" ", "_").replace("/", "_")

        print(f"[{i+1}/{len(sweep_values)}] {sweep_param}={val} ...", end=" ", flush=True)
        work_dir = os.path.join(base_dir, run_id)
        metrics = run_single_experiment(overrides, template_path, work_dir, run_id)

        if metrics:
            results.append(metrics)
            lat = metrics.get("local_aggregation_latency_ms", "N/A")
            dupes = metrics.get("avg_duplicates_per_unique", "N/A")
            print(f"lat={lat}ms dupes={dupes}")
        else:
            print("FAILED")

    # Write CSV
    if results:
        import csv
        all_keys = set()
        for r in results:
            all_keys.update(r.keys())
        sorted_keys = sorted(all_keys)

        with open(output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=sorted_keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"\nResults written to {output_csv} ({len(results)} rows)")
    else:
        print("\nNo successful results.")


def main():
    parser = argparse.ArgumentParser(description="leanSim experiment runner")
    parser.add_argument("--template", required=True, help="Base experiment TOML template")
    parser.add_argument("--sweep", help="Parameter to sweep (e.g. signature_payload_bytes)")
    parser.add_argument("--values", nargs="+", help="Values for the sweep parameter")
    parser.add_argument("--output", default="results.csv", help="Output CSV file")
    parser.add_argument("--base-dir", default="experiments/runs", help="Working directory")
    parser.add_argument("--override", action="append", nargs=2,
                        metavar=("KEY", "VALUE"), help="Fixed override for all runs")
    args = parser.parse_args()

    # Parse --override into dict
    fixed = {}
    if args.override:
        for k, v in args.override:
            try:
                fixed[k] = int(v)
            except ValueError:
                try:
                    fixed[k] = float(v)
                except ValueError:
                    fixed[k] = v

    if not args.sweep:
        # Single run mode
        work_dir = os.path.join(args.base_dir, "single")
        metrics = run_single_experiment(fixed, args.template, work_dir, "single")
        if metrics:
            print(json.dumps(metrics, indent=2))
        return

    if args.sweep:
        values = []
        for v in args.values:
            try:
                values.append(int(v))
            except ValueError:
                try:
                    values.append(float(v))
                except ValueError:
                    values.append(v)
        run_parameter_sweep(args.template, args.sweep, values, args.output, args.base_dir, fixed)


if __name__ == "__main__":
    main()
