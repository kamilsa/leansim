#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate and run a leansim Shadow experiment."""

import argparse
import json
import math
import os
import random
import shutil
import subprocess
import sys
import tomllib
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_EXPERIMENT = REPO_ROOT / "experiments" / "geo-128.toml"
LEANSIM_BIN_DOCKER = "/opt/leansim/leansim"
LEANSIM_BIN_NATIVE = REPO_ROOT / "target" / "release" / "leansim"
SEED_PEER_COUNT = 50
RUNNER_SECTIONS = {"run", "docker", "output"}


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def log(message: str) -> None:
    print(f"[shadow-sim] {message}")


def as_int(value: object, name: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        die(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        die(f"{name} must be at least {minimum}")
    return value


def as_number(value: object, name: str, *, minimum: float | None = None, maximum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        die(f"{name} must be a finite number")
    if minimum is not None and value < minimum:
        die(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        die(f"{name} must be at most {maximum}")
    return float(value)


def setting(config: dict, key: str, default: object) -> object:
    return config.get(key, default)


def validate_experiment(config: dict) -> None:
    run_id = config.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        die("run_id must be a non-empty string")
    validators = as_int(config.get("validator_count"), "validator_count", minimum=1)
    subnets = as_int(config.get("subnet_count"), "subnet_count", minimum=1)
    if validators % subnets:
        die("validator_count must be divisible by subnet_count")
    as_int(setting(config, "run_timeout_secs", 120), "run_timeout_secs", minimum=1)
    local_aggregators = as_int(
        setting(config, "local_aggregators_per_subnet", 1),
        "local_aggregators_per_subnet",
        minimum=0,
    )
    if local_aggregators > validators // subnets:
        die("local_aggregators_per_subnet must not exceed validators_per_subnet")
    explicit_aggregators = as_int(
        setting(config, "gossipsub_explicit_aggregator_count", 0),
        "gossipsub_explicit_aggregator_count",
        minimum=0,
    )
    if explicit_aggregators and explicit_aggregators >= local_aggregators:
        die("gossipsub_explicit_aggregator_count must be less than local_aggregators_per_subnet")
    as_int(setting(config, "global_aggregator_count", 1), "global_aggregator_count", minimum=0)
    as_number(setting(config, "local_threshold", 0.9), "local_threshold", minimum=0.0000001, maximum=1)
    as_number(setting(config, "global_proof_target", 0.66), "global_proof_target", minimum=0.0000001, maximum=1)
    for key, default in (
        ("burst_time_ms", 2000),
        ("burst_jitter_ms", 500),
        ("signature_aggregation_rate", 1000),
        ("global_aggregation_rate", 10),
        ("signature_payload_bytes", 3072),
        ("proof_payload_bytes", 131072),
        ("gossipsub_mesh_n_low", 2),
        ("gossipsub_mesh_n", 4),
        ("gossipsub_mesh_n_high", 8),
        ("gossipsub_mesh_outbound_min", 1),
        ("gossipsub_heartbeat_interval_ms", 1000),
        ("geo_seed", 42),
        ("supernode_uplink_mbps", 1000),
        ("supernode_downlink_mbps", 1000),
        ("topology_degree", 0),
    ):
        as_int(setting(config, key, default), key, minimum=0)
    if as_int(setting(config, "signature_aggregation_rate", 1000), "signature_aggregation_rate") == 0:
        die("signature_aggregation_rate must be greater than zero")
    if as_int(setting(config, "global_aggregation_rate", 10), "global_aggregation_rate") == 0:
        die("global_aggregation_rate must be greater than zero")
    if as_int(setting(config, "signature_payload_bytes", 3072), "signature_payload_bytes") == 0:
        die("signature_payload_bytes must be greater than zero")
    if as_int(setting(config, "proof_payload_bytes", 131072), "proof_payload_bytes") == 0:
        die("proof_payload_bytes must be greater than zero")
    if not isinstance(setting(config, "gossipsub_flood_publish", False), bool):
        die("gossipsub_flood_publish must be a boolean")
    as_number(setting(config, "geo_jitter", 0.0), "geo_jitter", minimum=0)
    as_number(setting(config, "supernode_fraction", 0.05), "supernode_fraction", minimum=0, maximum=1)
    network = config.get("network_defaults", {})
    if not isinstance(network, dict):
        die("[network_defaults] must be a table")
    for key, default in (("uplink_mbps", 50), ("downlink_mbps", 50), ("latency_ms", 50)):
        as_int(setting(network, key, default), f"network_defaults.{key}", minimum=1)


def scalar_toml(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            die("TOML values must be finite")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(scalar_toml(item) for item in value) + "]"
    die(f"unsupported TOML value: {type(value).__name__}")


def write_toml(path: Path, value: dict) -> None:
    lines: list[str] = []

    def write_table(table: dict, prefix: tuple[str, ...] = ()) -> None:
        if prefix:
            lines.append("[" + ".".join(prefix) + "]")
        for key, item in table.items():
            if not isinstance(item, dict):
                lines.append(f"{key} = {scalar_toml(item)}")
        if prefix or any(not isinstance(item, dict) for item in table.values()):
            lines.append("")
        for key, item in table.items():
            if isinstance(item, dict):
                write_table(item, (*prefix, key))

    write_table(value)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def experiment_defaults(experiment: dict) -> dict:
    defaults = {
        "run_timeout_secs": 120,
        "local_aggregators_per_subnet": 1,
        "global_aggregator_count": 1,
        "local_threshold": 0.9,
        "global_proof_target": 0.66,
        "burst_time_ms": 2000,
        "burst_jitter_ms": 500,
        "signature_aggregation_rate": 1000,
        "global_aggregation_rate": 10,
        "signature_payload_bytes": 3072,
        "proof_payload_bytes": 131072,
        "gossipsub_mesh_n_low": 2,
        "gossipsub_mesh_n": 4,
        "gossipsub_mesh_n_high": 8,
        "gossipsub_mesh_outbound_min": 1,
        "gossipsub_heartbeat_interval_ms": 1000,
        "gossipsub_explicit_aggregator_count": 0,
        "gossipsub_flood_publish": False,
        "use_geo_latency": False,
        "geo_seed": 42,
        "geo_jitter": 0.0,
        "supernode_fraction": 0.05,
        "supernode_uplink_mbps": 1000,
        "supernode_downlink_mbps": 1000,
        "topology_degree": 0,
    }
    merged = deepcopy(experiment)
    for key, value in defaults.items():
        merged.setdefault(key, value)
    network = merged.setdefault("network_defaults", {})
    network.setdefault("uplink_mbps", 50)
    network.setdefault("downlink_mbps", 50)
    network.setdefault("latency_ms", 50)
    return merged


def load_geo_data() -> tuple[dict, list[tuple[str, float]]]:
    try:
        latency = json.loads((REPO_ROOT / "data" / "country_latencies.json").read_text(encoding="utf-8"))
        weights = json.loads((REPO_ROOT / "data" / "weights.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        die(f"reading geo data: {error}")
    if not isinstance(latency, dict) or not isinstance(weights, dict):
        die("geo data must contain JSON objects")
    ordered_weights = [(country, float(weights[country])) for country in sorted(weights)]
    return latency, ordered_weights


def assign_countries(count: int, seed: int) -> tuple[list[str], dict]:
    latency, weights = load_geo_data()
    total = sum(weight for _, weight in weights)
    if total <= 0:
        die("country weights must sum to a positive number")
    rng = random.Random(seed)
    countries = []
    for _ in range(count):
        sample = rng.random() * total
        cumulative = 0.0
        for country, weight in weights:
            cumulative += weight
            if sample <= cumulative:
                countries.append(country)
                break
        else:
            countries.append(weights[-1][0])
    return countries, latency


def country_latency(latency: dict, source: str, target: str) -> float:
    source_row = latency.get(source)
    if isinstance(source_row, dict) and isinstance(source_row.get(target), (int, float)):
        return float(source_row[target])
    if isinstance(source_row, dict) and isinstance(source_row.get("default"), (int, float)):
        return float(source_row["default"])
    target_row = latency.get(target)
    if isinstance(target_row, dict) and isinstance(target_row.get(source), (int, float)):
        return float(target_row[source])
    if isinstance(target_row, dict) and isinstance(target_row.get("default"), (int, float)):
        return float(target_row["default"])
    return 100.0


def subnet_ip(subnet: int, local_id: int) -> str:
    return f"10.{subnet}.{local_id // 254}.{local_id % 254 + 1}"


def global_aggregator_ip(node_id: int) -> str:
    return f"10.255.{node_id // 254}.{node_id % 254 + 1}"


def assign_nodes(experiment: dict) -> list[dict]:
    nodes: list[dict] = []
    validators_per_subnet = experiment["validator_count"] // experiment["subnet_count"]
    for subnet in range(experiment["subnet_count"]):
        for validator in range(validators_per_subnet):
            role = "local_aggregator" if validator < experiment["local_aggregators_per_subnet"] else "validator"
            nodes.append({"node_id": len(nodes), "role": role, "subnet_id": subnet, "ip": subnet_ip(subnet, validator)})
    for _ in range(experiment["global_aggregator_count"]):
        nodes.append({"node_id": len(nodes), "role": "global_aggregator", "subnet_id": 0, "ip": global_aggregator_ip(len(nodes))})
    for node in nodes:
        node["listen_addr"] = f"/ip4/{node['ip']}/udp/9090/quic-v1"

    explicit_count = experiment["gossipsub_explicit_aggregator_count"]
    for node in nodes:
        node["explicit_peer_addrs"] = set()
        node["selected_aggregator_ids"] = []

    if explicit_count:
        for subnet in range(experiment["subnet_count"]):
            signing_nodes = [node for node in nodes if node["subnet_id"] == subnet and node["role"] != "global_aggregator"]
            aggregators = [node for node in signing_nodes if node["role"] == "local_aggregator"]
            for node in signing_nodes:
                candidates = [aggregator for aggregator in aggregators if aggregator["node_id"] != node["node_id"]]
                rng = random.Random(experiment["geo_seed"] + node["node_id"])
                rng.shuffle(candidates)
                selected = candidates[:explicit_count]
                node["selected_aggregator_ids"] = [aggregator["node_id"] for aggregator in selected]
                for aggregator in selected:
                    node["explicit_peer_addrs"].add(aggregator["listen_addr"])
                    # Explicit peers must be configured on both ends to avoid mesh GRAFT/PRUNE churn.
                    aggregator["explicit_peer_addrs"].add(node["listen_addr"])

    all_addresses = [node["listen_addr"] for node in nodes]
    for node in nodes:
        explicit_addrs = sorted(node["explicit_peer_addrs"])
        candidates = [
            address for address in all_addresses
            if address != node["listen_addr"] and address not in node["explicit_peer_addrs"]
        ]
        rng = random.Random(experiment["geo_seed"] + node["node_id"])
        rng.shuffle(candidates)
        node["explicit_peer_addrs"] = explicit_addrs
        node["seed_addrs"] = explicit_addrs + candidates[:max(0, SEED_PEER_COUNT - len(explicit_addrs))]
    return nodes


def sample_supernodes(nodes: list[dict], experiment: dict) -> set[int]:
    count = math.ceil(len(nodes) * experiment["supernode_fraction"])
    if not count:
        return set()
    return set(random.Random(experiment["geo_seed"] + 1).sample(range(len(nodes)), count))


def gml_edges(count: int, degree: int, rng: random.Random):
    if 0 < degree < count - 1:
        edges: set[tuple[int, int]] = set()
        for source in range(count):
            candidates = [target for target in range(count) if target != source]
            rng.shuffle(candidates)
            for target in candidates[:degree]:
                edges.add((min(source, target), max(source, target)))
        yield from sorted(edges)
        return
    for source in range(count):
        for target in range(source + 1, count):
            yield source, target


def write_topology(path: Path, nodes: list[dict], experiment: dict, countries: list[str] | None, latency: dict | None) -> None:
    jitter_rng = random.Random(experiment["geo_seed"] + 2)
    with path.open("w", encoding="utf-8") as output:
        output.write("graph [\n  directed 0\n")
        for node in nodes:
            output.write(f'  node [\n    id {node["node_id"]}\n    hostname "node-{node["node_id"]}"\n  ]\n')
        for node in nodes:
            output.write(f'  edge [\n    source {node["node_id"]}\n    target {node["node_id"]}\n    latency "1 ms"\n  ]\n')
        for source, target in gml_edges(len(nodes), experiment["topology_degree"], jitter_rng):
            if countries is not None and latency is not None:
                value = country_latency(latency, countries[source], countries[target])
                if experiment["geo_jitter"]:
                    spread = value * experiment["geo_jitter"]
                    value = max(0.5, value + jitter_rng.uniform(-spread, spread))
            else:
                value = experiment["network_defaults"]["latency_ms"]
            output.write(f'  edge [\n    source {source}\n    target {target}\n    latency "{value:.0f} ms"\n  ]\n')
        output.write("]\n")


def yaml_quote(value: str) -> str:
    return json.dumps(value)


def write_shadow_yaml(path: Path, nodes: list[dict], experiment: dict, binary: str) -> None:
    lines = [
        "general:",
        f'  stop_time: "{experiment["run_timeout_secs"] + 10}s"',
        "network:",
        "  graph:",
        "    type: gml",
        "    file:",
        "      path: topology.gml",
        "hosts:",
    ]
    for node in sorted(nodes, key=lambda item: f"node-{item['node_id']}"):
        process_args = f"node --config {node['config_path']}"
        lines.extend(
            [
                f"  node-{node['node_id']}:",
                f"    network_node_id: {node['node_id']}",
                f"    ip_addr: {node['ip']}",
                f'    bandwidth_up: "{node["uplink_mbps"]} Mbit"',
                f'    bandwidth_down: "{node["downlink_mbps"]} Mbit"',
                "    processes:",
                f"    - path: {yaml_quote(binary)}",
                f"      args: {yaml_quote(process_args)}",
                '      start_time: "1s"',
                "      expected_final_state: {exited: 0}",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_run(experiment: dict, output_dir: Path, binary: str, run_index: int, runner: str) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    configs_dir = output_dir / "configs"
    shutil.rmtree(configs_dir, ignore_errors=True)
    configs_dir.mkdir()
    nodes = assign_nodes(experiment)
    countries: list[str] | None = None
    latency: dict | None = None
    if experiment["use_geo_latency"]:
        countries, latency = assign_countries(len(nodes), experiment["geo_seed"])
    supernodes = sample_supernodes(nodes, experiment)
    for index, node in enumerate(nodes):
        node["country"] = countries[index] if countries is not None else None
        node["supernode"] = node["node_id"] in supernodes
        node["uplink_mbps"] = experiment["supernode_uplink_mbps"] if node["supernode"] else experiment["network_defaults"]["uplink_mbps"]
        node["downlink_mbps"] = experiment["supernode_downlink_mbps"] if node["supernode"] else experiment["network_defaults"]["downlink_mbps"]
        config_path = (configs_dir / f"node_{node['node_id']}.toml").resolve()
        node["config_path"] = str(config_path)
        write_toml(
            config_path,
            {
                "node_id": node["node_id"],
                "role": node["role"],
                "subnet_id": node["subnet_id"],
                "listen_addr": node["listen_addr"],
                "seed_addrs": node["seed_addrs"],
                "explicit_peer_addrs": node["explicit_peer_addrs"],
                "selected_aggregator_addrs": [nodes[node_id]["listen_addr"] for node_id in node["selected_aggregator_ids"]],
                "experiment": experiment,
            },
        )
    write_topology(output_dir / "topology.gml", nodes, experiment, countries, latency)
    write_shadow_yaml(output_dir / "shadow.yaml", nodes, experiment, binary)
    manifest = {
        "run_id": experiment["run_id"],
        "seed": experiment["geo_seed"],
        "run_index": run_index,
        "runner": runner,
        "experiment": experiment,
        "nodes": [{key: value for key, value in node.items() if key not in {"listen_addr", "seed_addrs", "config_path", "ip"}} for node in nodes],
    }
    (output_dir / "run-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def image_exists(image: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0


def docker_build(image: str, shadow_image: str) -> None:
    log(f"building Docker image {image} on {shadow_image}")
    subprocess.run(
        ["docker", "build", "--no-cache", "--platform", "linux/arm64", "-f", str(REPO_ROOT / "docker" / "Dockerfile"), "--build-arg", f"SHADOW_IMAGE={shadow_image}", "-t", image, str(REPO_ROOT)],
        check=True,
    )


def cargo_build_release() -> None:
    if shutil.which("cargo") is None:
        die("cargo is not on PATH; it is required for [run].runner = \"native\"")
    log("building leansim with cargo build --release")
    subprocess.run(["cargo", "build", "--release"], cwd=REPO_ROOT, check=True)


def native_run_shadow(output_dir: Path, parallelism: int) -> None:
    if shutil.which("shadow") is None:
        die('shadow is not on PATH; install Shadow or set [run].runner = "docker"')
    log("running Shadow natively")
    subprocess.run(["shadow", "-d", "shadow.data", "--progress", "true", "--parallelism", str(parallelism), "shadow.yaml"], cwd=output_dir, check=True)


def docker_run_shadow(image: str, output_dir: Path, parallelism: int) -> None:
    subprocess.run(["docker", "rm", "-f", "leansim-shadow-run"], check=False, capture_output=True)
    log("running Shadow in Docker")
    command = f"shadow -d shadow.data --progress true --parallelism {parallelism} shadow.yaml"
    subprocess.run(
        ["docker", "run", "--rm", "--name", "leansim-shadow-run", "--platform", "linux/arm64", "--security-opt", "seccomp=unconfined", "--shm-size", "4g", "-v", f"{output_dir}:{output_dir}", "-w", str(output_dir), "--entrypoint", "/bin/bash", image, "-c", command],
        check=True,
    )


def write_run_meta(output_dir: Path, manifest: dict) -> None:
    (output_dir / "run-meta.json").write_text(json.dumps({key: manifest[key] for key in ("run_id", "seed", "run_index", "runner")}, indent=2) + "\n", encoding="utf-8")


def analyze(output_dir: Path, overlays: list[Path], *, serve: bool, append: bool) -> None:
    script = REPO_ROOT / "scripts" / "analyze.py"
    if not script.is_file():
        log("scripts/analyze.py is missing; skipping analysis")
        return
    command = ["uv", "run", "--group", "analyze", "python3", str(script)]
    if serve:
        command.append("--serve")
    if append:
        command.append("--append")
    command.extend(str(path) for path in [output_dir, *overlays])
    log("writing interactive summary")
    environment = os.environ.copy()
    # A PEP 723 launcher has its own temporary environment; nested uv should use
    # this project's dependency-group environment instead.
    environment.pop("VIRTUAL_ENV", None)
    subprocess.run(command, cwd=REPO_ROOT, check=False, env=environment)


def netviz(output_dir: Path, runner: str, image: str | None) -> None:
    trace = output_dir / "netviz-trace.bctrace"
    args = ["netviz", "--manifest", "run-manifest.json", "--shadow-data", "shadow.data", "--out", trace.name]
    log(f"writing {trace}")
    if runner == "native":
        subprocess.run([str(LEANSIM_BIN_NATIVE), *args], cwd=output_dir, check=True)
    else:
        assert image is not None
        subprocess.run(["docker", "run", "--rm", "--platform", "linux/arm64", "-v", f"{output_dir}:{output_dir}", "-w", str(output_dir), "--entrypoint", LEANSIM_BIN_DOCKER, image, *args], check=True)


def clean_output(output_dir: Path) -> None:
    for name in ("shadow.data", "configs"):
        shutil.rmtree(output_dir / name, ignore_errors=True)
    for name in ("runs-history.json", "summary.html", "netviz-trace.bctrace", "run-meta.json", "run-manifest.json"):
        (output_dir / name).unlink(missing_ok=True)


def resolve_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (REPO_ROOT / path).resolve()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate and run leansim under Shadow.")
    parser.add_argument("config", nargs="?", default=str(DEFAULT_EXPERIMENT), help="experiment TOML path (default: experiments/geo-128.toml)")
    parser.add_argument("--dry-run", action="store_true", help="generate Shadow artifacts only")
    parser.add_argument("--rebuild", action="store_true", help="force a Docker image rebuild")
    parser.add_argument("--clean", action="store_true", help="remove prior run data and summary history")
    parser.add_argument("--summary-only", action="store_true", help="rebuild the summary without simulating")
    parser.add_argument("--serve", "-s", action="store_true", help="run, summarize, and serve http://0.0.0.0:4321/summary.html")
    parser.add_argument("--serve-only", action="store_true", help="serve existing summary history without simulating")
    parser.add_argument("--netviz", action="store_true", help="write netviz-trace.bctrace after each run")
    parser.add_argument("--overlay", action="append", default=[], metavar="DIR", help="additional output directory to merge into summary history")
    args = parser.parse_args()

    config_path = resolve_path(args.config)
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        die(f"reading {config_path}: {error}")
    if not isinstance(config, dict):
        die("experiment TOML must be a table")
    experiment = experiment_defaults({key: value for key, value in config.items() if key not in RUNNER_SECTIONS})
    validate_experiment(experiment)
    run = config.get("run", {})
    docker = config.get("docker", {})
    output = config.get("output", {})
    if not all(isinstance(section, dict) for section in (run, docker, output)):
        die("[run], [docker], and [output] must be TOML tables")
    runner = str(run.get("runner", "docker")).lower()
    if runner == "local":
        runner = "native"
    if runner not in {"docker", "native"}:
        die(f'[run].runner must be "docker" or "native", got {runner!r}')
    runs = as_int(run.get("runs", 1), "run.runs", minimum=1)
    parallelism = as_int(run.get("parallelism", 10), "run.parallelism", minimum=1)
    output_dir = resolve_path(str(output.get("dir", "output")))
    overlays = [resolve_path(path) for path in args.overlay]

    if args.clean:
        clean_output(output_dir)
    if args.summary_only:
        analyze(output_dir, overlays, serve=False, append=False)
        return
    if args.serve_only:
        analyze(output_dir, overlays, serve=True, append=False)
        return
    output_dir.mkdir(parents=True, exist_ok=True)

    image = str(docker.get("image_name", "leansim-shadow:local")) if runner == "docker" else None
    binary = LEANSIM_BIN_DOCKER if runner == "docker" else str(LEANSIM_BIN_NATIVE)
    if not args.dry_run:
        if runner == "docker":
            shadow_image = str(docker.get("shadow_image", "kamilsa/shadow-arm:latest"))
            if args.rebuild or docker.get("rebuild") is True or not image_exists(image):
                docker_build(image, shadow_image)
            else:
                log(f"reusing Docker image {image}; pass --rebuild to rebuild")
        else:
            cargo_build_release()

    base_seed = experiment["geo_seed"] or 42
    for run_index in range(runs):
        run_experiment = deepcopy(experiment)
        run_experiment["geo_seed"] = base_seed + run_index
        manifest = generate_run(run_experiment, output_dir, binary, run_index, runner)
        if args.dry_run:
            log(f"generated Shadow artifacts in {output_dir}")
            continue
        shutil.rmtree(output_dir / "shadow.data", ignore_errors=True)
        if runner == "docker":
            docker_run_shadow(image, output_dir, parallelism)
        else:
            native_run_shadow(output_dir, parallelism)
        write_run_meta(output_dir, manifest)
        analyze(output_dir, overlays, serve=False, append=True)
        if args.netviz:
            netviz(output_dir, runner, image)
    if args.serve:
        analyze(output_dir, overlays, serve=True, append=False)
    elif not args.dry_run:
        log(f"results: {output_dir}")
        log(f"summary: {output_dir / 'summary.html'}")


if __name__ == "__main__":
    main()
