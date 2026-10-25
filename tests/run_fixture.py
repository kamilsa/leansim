"""A three-host run directory for analyzer and report tests.

Host 0 is a supernode in Finland with validators 0-2 that aggregates subnet 0;
host 1 is a regular node in Germany with validator 3 and a traffic log; host 2
is a regular relay in Germany that fetches the subnet proof. The first
signature is sent at 1000 ms, so every summary time below is ts_ms - 1000.
"""

import json
from pathlib import Path

NODES = [
    {"node_id": 0, "role": "local_aggregator", "validator_ids": [0, 1, 2], "country": "finland",
     "supernode": True, "uplink_mbps": 1000, "downlink_mbps": 1000, "subscribed_subnets": [0]},
    {"node_id": 1, "role": "validator", "validator_ids": [3], "country": "germany",
     "supernode": False, "uplink_mbps": 50, "downlink_mbps": 100, "subscribed_subnets": [0]},
    {"node_id": 2, "role": "relay", "validator_ids": [], "country": "germany",
     "supernode": False, "uplink_mbps": 50, "downlink_mbps": 100},
]

EVENTS = [
    {"event": "SigSent", "node_id": 0, "validator_id": 0, "subnet_id": 0, "ts_ms": 1000},
    {"event": "SigSent", "node_id": 0, "validator_id": 1, "subnet_id": 0, "ts_ms": 1000},
    {"event": "SigSent", "node_id": 0, "validator_id": 2, "subnet_id": 0, "ts_ms": 1010},
    {"event": "SigSent", "node_id": 1, "validator_id": 3, "subnet_id": 0, "ts_ms": 1005},
    {"event": "SigReceived", "node_id": 1, "from_id": 0, "validator_id": 0, "subnet_id": 0, "duplicate": False, "ts_ms": 1100},
    {"event": "SigReceived", "node_id": 1, "from_id": 0, "validator_id": 1, "subnet_id": 0, "duplicate": False, "ts_ms": 1200},
    {"event": "SigReceived", "node_id": 1, "from_id": 0, "validator_id": 2, "subnet_id": 0, "duplicate": False, "ts_ms": 1300},
    {"event": "SigReceived", "node_id": 1, "from_id": 0, "validator_id": 0, "subnet_id": 0, "duplicate": True, "ts_ms": 1350},
    {"event": "SigReceived", "node_id": 0, "from_id": 1, "validator_id": 3, "subnet_id": 0, "duplicate": False, "ts_ms": 1050},
    {"event": "SigReceived", "node_id": 2, "from_id": 1, "validator_id": 3, "subnet_id": 0, "duplicate": False, "ts_ms": 1400},
    {"event": "LocalProofGenerated", "node_id": 0, "subnet_id": 0, "sig_count": 4, "latency_ms": 2000},
    {"event": "ProofFetched", "node_id": 2, "from_id": 0, "layer": 0, "index": 0, "duplicate": False, "ts_ms": 2300, "byte_size": 100},
    {"event": "ProofFetched", "node_id": 2, "from_id": 1, "layer": 0, "index": 0, "duplicate": True, "ts_ms": 2400, "byte_size": 100},
    {"event": "RecursiveProofGenerated", "node_id": 2, "layer": 1, "index": 0, "inputs": 1, "is_final": True, "ts_ms": 3000},
    {"event": "RecursiveProofGenerated", "node_id": 0, "layer": 1, "index": 0, "inputs": 1, "is_final": True, "ts_ms": 3200},
    {"event": "TrafficBucket", "node_id": 1, "start_ms": 1000, "width_ms": 100,
     "inbound": {"signature": 2400}, "outbound": {"signature": 1200}},
    {"event": "TrafficPeer", "node_id": 1, "peer": "node:0", "inbound_bytes": 2400, "outbound_bytes": 1200,
     "inbound_msgs": 2, "outbound_msgs": 1},
]


EXPERIMENT = {
    "local_threshold": 1.0, "mesh_warmup_ms": 900, "supernode_by_validator_count": 2, "supernode_fraction": 0.05,
    "validator_count": 4, "subnet_count": 1, "subnet_subscriptions_per_node": 2, "burst_time_ms": 100,
    "burst_jitter_ms": 10, "signature_payload_bytes": 1200, "signature_aggregation_rate": 1000,
    "committee_aggregators": True, "local_aggregators_per_subnet": 1, "recursive_aggregation": True,
    "recursive_aggregation_arity": 2, "recursive_aggregation_time_ms": 276, "recursive_group_size": 16,
    "recursive_proofs_per_child": 1, "aggregate_proof_bytes": 262144, "gossipsub_mesh_n": 8,
    "gossipsub_mesh_n_low": 4, "gossipsub_mesh_n_high": 12, "gossipsub_heartbeat_interval_ms": 300,
    "gossipsub_flood_publish": False, "node_map": "nodes_small.csv",
}


def write_fixture_run(directory: Path) -> Path:
    """Write the fixture run into `directory` and return it."""
    stdout = directory / "shadow.data" / "hosts" / "node-0" / "leansim.1000.stdout"
    stdout.parent.mkdir(parents=True)
    stdout.write_text("\n".join(json.dumps(event) for event in EVENTS) + "\n", encoding="utf-8")
    manifest = {
        "run_id": "fixture",
        "experiment": EXPERIMENT,
        "nodes": NODES,
    }
    (directory / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (directory / "aggregation-plan.json").write_text(
        json.dumps({"arity": 2, "groups": [{"layer": 1, "index": 0, "children": [0], "members": [0, 2]}]}),
        encoding="utf-8",
    )
    return directory
