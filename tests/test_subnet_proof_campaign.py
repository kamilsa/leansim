import json
import runpy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

CAMPAIGN = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "subnet-proof-campaign.py"))


class SubnetProofCampaignTest(unittest.TestCase):
    def test_mixed_placement_keeps_the_existing_overlay_and_uses_validator_producers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "map.csv").write_text(
                "peer_key,node_type,validator_count\n" +
                "".join(f"large{i},validator,10\n" for i in range(4)) +
                "".join(f"relay{i},no_validator,0\n" for i in range(5))
            )
            config = path / "network.toml"
            config.write_text('run_id = "fixture"\nnode_map = "map.csv"\nall_hosts = true\n'
                              'validator_count = 32\nsubnet_count = 2\nlocal_aggregators_per_subnet = 0\n'
                              'subnet_subscriptions_per_node = 2\npeer_count = 4\nsupernode_by_validator_count = 10\n'
                              '[network_defaults]\nuplink_mbps = 50\ndownlink_mbps = 100\nlatency_ms = 50\n')
            args = SimpleNamespace(network_config=config, subnets=2, seconds=15, proof_bytes=200_000,
                                   idontwant_bytes=1000)
            exp, nodes, _, proofs, edges = CAMPAIGN["make_case"](args, 42, 2)
            self.assertEqual(len(nodes), 9)
            self.assertEqual(len(edges), 18)
            self.assertEqual({n["uplink_mbps"] for n in nodes}, {50, 1000})
            self.assertEqual(exp["validator_count"], 32)
            self.assertEqual(len(proofs), 4)
            self.assertEqual(proofs[:2], CAMPAIGN["make_case"](args, 42, 1)[3])
            self.assertEqual(len({proof["producer"] for proof in proofs}), 4)
            for proof in proofs:
                self.assertIn(proof["subnet"], nodes[proof["producer"]]["signing_subnets"])

            # Subnet peering is derived from the original mesh target. Overriding
            # the runtime mesh must not regenerate those seed connections.
            config.write_text(config.read_text().replace('peer_count = 4\n',
                              'random_peer_count = 0\ngossipsub_mesh_n = 8\npublish_subnet_peer_count = 8\n'))
            baseline = CAMPAIGN["make_case"](args, 42, 2)
            args.gossip_mesh = (3, 4, 6)
            exp, *unchanged = CAMPAIGN["make_case"](args, 42, 2)
            self.assertEqual(tuple(unchanged), baseline[1:])
            self.assertEqual(exp, dict(baseline[0], gossipsub_mesh_n_low=3,
                                       gossipsub_mesh_n=4, gossipsub_mesh_n_high=6))

    def test_all_arms_share_the_network_and_producers(self):
        args = SimpleNamespace(nodes=16, subnets=4, seconds=15, proof_bytes=200_000, dials=3,
                               idontwant_bytes=1000, release_ms=5000, stagger_ms=0,
                               commitment_lead_ms=500, chunks=64)
        case = CAMPAIGN["make_case"](args, 42, 2)
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / mode for mode in CAMPAIGN["MODES"]]
            for path in paths:
                CAMPAIGN["generate"](path, path.name, case, args)
            first = paths[0]
            settings = []
            for path in paths:
                for file in ("network.json", "topology.gml", "node-0.toml"):
                    self.assertEqual((first / file).read_bytes(), (path / file).read_bytes())
                config = json.loads((path / "proof-settings.json").read_text())
                self.assertEqual(config.pop("mode"), path.name)
                settings.append(config)
            self.assertTrue(all(setting == settings[0] for setting in settings))
            self.assertEqual(len(settings[0]["producers"]), 8)

    def test_readiness_uses_first_complete_proof_per_subnet_and_counts_misses(self):
        exp = {"subnet_count": 2, "geo_seed": 42, "aggregate_proof_bytes": 100}
        nodes = [{"node_id": node, "seed_addrs": []} for node in range(3)]
        proofs = [{"subnet": s, "producer": p} for s, p in [(0, 0), (0, 1), (1, 2)]]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            CAMPAIGN["json_write"](path / "network.json", {"experiment": exp, "edges": [], "nodes": nodes})
            CAMPAIGN["json_write"](path / "proof-settings.json", {"mode": "gossipsub", "producers": proofs})
            events = {
                0: [("proof_release", 0, 0, 5000), ("proof_complete", 0, 0, 5000), ("proof_complete", 1, 2, 7000)],
                1: [("proof_release", 0, 1, 5000), ("proof_complete", 0, 1, 5000)],
                2: [("proof_release", 1, 2, 6000), ("proof_complete", 1, 2, 6000),
                    ("proof_complete", 0, 0, 5500), ("proof_complete", 0, 1, 8000)],
            }
            for node, entries in events.items():
                host = path / "shadow.data" / "hosts" / f"node-{node}"
                host.mkdir(parents=True)
                rows = [dict(event=kind, node_id=node, subnet=s, producer=p, ms=ms) for kind, s, p, ms in entries]
                rows.append(dict(event="proof_traffic", node_id=node, bytes=200, peers=0, pending_fetches=0))
                (host / "leansim.1.stdout").write_text("\n".join(map(json.dumps, rows)))
            result = CAMPAIGN["summarize"](path)
            self.assertEqual(result["ready"], 2)
            self.assertEqual(result["ready_p50_ms"], 1000)
            self.assertEqual(result["ready_last_ms"], 2000)
            self.assertEqual(result["ready_by_ms"][1000], 1)
            self.assertEqual(result["distinct_deliveries"], 3)
            self.assertEqual(result["bytes_over_one_copy_per_delivery"], 1)
