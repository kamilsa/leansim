#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run a Cartesian parameter sweep through shadow-sim.py."""

import argparse
import csv
import itertools
import json
import math
import os
import subprocess
import sys
import tempfile
import tomllib
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def toml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            die("TOML values must be finite")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_scalar(item) for item in value) + "]"
    die(f"unsupported TOML value: {type(value).__name__}")


def write_toml(path: Path, data: dict) -> None:
    lines: list[str] = []

    def table(value: dict, prefix: tuple[str, ...] = ()) -> None:
        if prefix:
            lines.append("[" + ".".join(prefix) + "]")
        for key, item in value.items():
            if not isinstance(item, dict):
                lines.append(f"{key} = {toml_scalar(item)}")
        lines.append("")
        for key, item in value.items():
            if isinstance(item, dict):
                table(item, (*prefix, key))

    table(data)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def parse_value(raw: str) -> object:
    try:
        return tomllib.loads("value = " + raw)["value"]
    except tomllib.TOMLDecodeError:
        return raw


def parse_params(raw_params: list[str]) -> list[tuple[str, list[object]]]:
    params = []
    for raw in raw_params:
        if "=" not in raw:
            die(f"--param must use key=value1,value2 syntax, got {raw!r}")
        key, values = raw.split("=", 1)
        parsed = [parse_value(value) for value in values.split(",") if value]
        if not key or not parsed:
            die(f"--param must include a key and at least one value, got {raw!r}")
        params.append((key, parsed))
    return params


def set_value(config: dict, dotted_key: str, value: object) -> None:
    target = config
    parts = dotted_key.split(".")
    for key in parts[:-1]:
        child = target.setdefault(key, {})
        if not isinstance(child, dict):
            die(f"cannot set {dotted_key}: {key} is not a TOML table")
        target = child
    target[parts[-1]] = value


def latest_snapshot(output_dir: Path) -> dict:
    try:
        history = json.loads((output_dir / "runs-history.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    snapshots = history.get("snapshots") if isinstance(history, dict) else history
    return snapshots[-1] if isinstance(snapshots, list) and snapshots and isinstance(snapshots[-1], dict) else {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a leansim parameter sweep.")
    parser.add_argument("config", nargs="?", default="experiments/geo-128.toml", help="template experiment TOML")
    parser.add_argument("--param", action="append", required=True, metavar="KEY=VALUES", help="repeatable values, e.g. signature_payload_bytes=1024,3072")
    parser.add_argument("--output", default="sweep-output", help="directory for per-point results and results.csv")
    parser.add_argument("--rebuild", action="store_true", help="rebuild the Docker image before the first point")
    args = parser.parse_args()

    template_path = Path(args.config)
    if not template_path.is_absolute():
        template_path = (REPO_ROOT / template_path).resolve()
    try:
        with template_path.open("rb") as handle:
            template = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        die(f"reading {template_path}: {error}")
    params = parse_params(args.param)
    output_root = Path(args.output)
    if not output_root.is_absolute():
        output_root = (REPO_ROOT / output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, values in enumerate(itertools.product(*(values for _, values in params))):
        config = deepcopy(template)
        for (key, _), value in zip(params, values):
            set_value(config, key, value)
        config["run_id"] = f"{config.get('run_id', 'sweep')}-{index:03d}"
        config.setdefault("output", {})["dir"] = str(output_root / f"run-{index:03d}")
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False, dir=output_root) as handle:
            config_path = Path(handle.name)
        try:
            write_toml(config_path, config)
            command = ["uv", "run", "shadow-sim.py", str(config_path), "--clean"]
            if args.rebuild and index == 0:
                command.append("--rebuild")
            environment = os.environ.copy()
            environment.pop("VIRTUAL_ENV", None)
            subprocess.run(command, cwd=REPO_ROOT, check=True, env=environment)
        finally:
            config_path.unlink(missing_ok=True)
        row = latest_snapshot(Path(config["output"]["dir"]))
        row.update({f"param_{key}": value for (key, _), value in zip(params, values)})
        rows.append(row)
    columns = sorted({key for row in rows for key in row})
    with (output_root / "results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {output_root / 'results.csv'}")


if __name__ == "__main__":
    main()
