import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze  # noqa: E402
from run_fixture import EXPERIMENT, write_churn_run, write_fixture_run  # noqa: E402


class FrequencyTests(unittest.TestCase):
    def test_percentiles_use_nearest_rank(self) -> None:
        self.assertEqual(
            analyze.frequency_percentiles({10: 1, 20: 3}),
            {"count": 4, "p5": 10, "p25": 10, "p50": 20, "p75": 20, "p95": 20},
        )

    def test_percentiles_of_nothing_are_none(self) -> None:
        self.assertIsNone(analyze.frequency_percentiles({}))

    def test_cdf_is_cumulative_percent(self) -> None:
        self.assertEqual(analyze.frequency_cdf(Counter({300: 1, 100: 2, 200: 1})), [[100, 50.0], [200, 75.0], [300, 100.0]])

    def test_cdf_is_thinned_but_keeps_both_ends(self) -> None:
        points = analyze.frequency_cdf({value: 1 for value in range(1000)}, limit=400)
        self.assertEqual(len(points), 400)
        self.assertEqual(points[0], [0, 0.1])
        self.assertEqual(points[-1], [999, 100.0])


class NodeClassTests(unittest.TestCase):
    def test_classes_follow_the_manifest_flag(self) -> None:
        self.assertEqual(analyze.node_class({"supernode": True}), "supernode")
        self.assertEqual(analyze.node_class({"supernode": False}), "regular")
        self.assertEqual(analyze.node_class({"node_id": 4}), "unknown")
        self.assertEqual(analyze.node_class(None), "unknown")


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-analyze-")
        cls.snapshot = analyze.build_snapshot(write_fixture_run(Path(cls.temporary.name) / "run"))
        cls.metrics = cls.snapshot["metrics"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_metadata_keeps_the_main_config(self) -> None:
        skipped = {"supernode_by_validator_count", "supernode_fraction", "node_map"}
        self.assertEqual(self.snapshot["metadata"]["config"], {key: value for key, value in EXPERIMENT.items() if key not in skipped})

    def test_times_start_at_the_first_signature(self) -> None:
        self.assertEqual(self.metrics["t0_ms"], 1000)

    def test_arrival_rows_per_message_and_class(self) -> None:
        self.assertEqual(self.metrics["arrivals"], [
            {"message": "Signatures", "class": "supernode", "count": 1, "p5": 50, "p25": 50, "p50": 50, "p75": 50, "p95": 50},
            {"message": "Signatures", "class": "regular", "count": 4, "p5": 100, "p25": 100, "p50": 200, "p75": 300, "p95": 400},
            {"message": "Subnet proofs", "class": "supernode", "count": 1, "p5": 1000, "p25": 1000, "p50": 1000, "p75": 1000, "p95": 1000},
            {"message": "Subnet proofs", "class": "regular", "count": 1, "p5": 1300, "p25": 1300, "p50": 1300, "p75": 1300, "p95": 1300},
            {"message": "Final proof", "class": "supernode", "count": 1, "p5": 2200, "p25": 2200, "p50": 2200, "p75": 2200, "p95": 2200},
            {"message": "Final proof", "class": "regular", "count": 1, "p5": 2000, "p25": 2000, "p50": 2000, "p75": 2000, "p95": 2000},
        ])

    def test_signature_cdf_lines(self) -> None:
        self.assertEqual(self.metrics["signature_cdf"], {
            "first_seen": [[50, 25.0], [100, 50.0], [200, 75.0], [300, 100.0]],
            "supernode": [[50, 100.0]],
            "regular": [[100, 25.0], [200, 50.0], [300, 75.0], [400, 100.0]],
        })

    def test_population_from_the_manifest(self) -> None:
        self.assertEqual(self.metrics["population"], {
            "hosts": 3,
            "validators": 4,
            "supernode_by_validator_count": 2,
            "supernode_fraction": 0.05,
            "classes": [
                {"class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000, "hosts": 1, "validators": 3},
                {"class": "regular", "uplink_mbps": 50, "downlink_mbps": 100, "hosts": 2, "validators": 1},
            ],
            "validators_per_host": [
                {"low": 0, "high": 0, "supernode": 0, "regular": 1, "unknown": 0, "validators": 0},
                {"low": 1, "high": 1, "supernode": 0, "regular": 1, "unknown": 0, "validators": 1},
                {"low": 2, "high": 3, "supernode": 1, "regular": 0, "unknown": 0, "validators": 3},
            ],
            "countries": [
                {"country": "germany", "supernode": 0, "regular": 2, "unknown": 0, "validators": 1},
                {"country": "finland", "supernode": 1, "regular": 0, "unknown": 0, "validators": 3},
            ],
        })

    def test_traffic_hosts_carry_their_manifest_card(self) -> None:
        self.assertEqual(self.metrics["traffic"]["1"]["host"], {
            "country": "germany", "class": "regular", "uplink_mbps": 50, "downlink_mbps": 100,
            "validators": 1, "role": "validator", "duties": {"subnets": [], "layers": {}, "final": False},
        })

    def test_subnet_proofs_in_the_snapshot(self) -> None:
        self.assertEqual(self.metrics["subnet_proofs"], [
            {"subnet": 0, "count": 1, "min": 1000, "p25": 1000, "p50": 1000, "p75": 1000, "max": 1000,
             "proofs": [[1000, 0, "supernode"]]},
        ])

    def test_subnet_proof_rows_spread_every_aggregator(self) -> None:
        hosts = {1: {"supernode": True}, 2: {"supernode": False}, 3: {"supernode": False}}
        local_proofs = [(1, 5, 1300), (2, 5, 1100), (3, 5, 1200), (4, 5, 1500), (1, 2, 1000), (None, 2, 1700)]
        self.assertEqual(analyze.subnet_proof_rows(local_proofs, 1000, hosts), [
            {"subnet": 2, "count": 2, "min": 0, "p25": 0, "p50": 0, "p75": 700, "max": 700,
             "proofs": [[0, 1, "supernode"], [700, None, "unknown"]]},
            {"subnet": 5, "count": 4, "min": 100, "p25": 100, "p50": 200, "p75": 300, "max": 500,
             "proofs": [[100, 2, "regular"], [200, 3, "regular"], [300, 1, "supernode"], [500, 4, "unknown"]]},
        ])

    def test_duties_split_subnets_tree_layers_and_the_final_proof(self) -> None:
        host = {"aggregated_subnets": [40, 12], "recursive_seats": [[2, 3], [1, 11], [1, 10], [3, 0]]}
        self.assertEqual(analyze.host_duties(host, top_layer=3),
                         {"subnets": [12, 40], "layers": {"1": [10, 11], "2": [3]}, "final": True})
        self.assertEqual(analyze.host_duties({}, top_layer=None), {"subnets": [], "layers": {}, "final": False})

    def test_subnet_pages_show_this_subnet_only(self) -> None:
        self.assertEqual(self.metrics["subnet_hosts"], {
            0: {"classes": {"supernode": 1, "regular": 1, "unknown": 0},
                "countries": [{"country": "finland", "supernode": 1, "regular": 0, "unknown": 0, "validators": 3},
                              {"country": "germany", "supernode": 0, "regular": 1, "unknown": 0, "validators": 1}],
                "aggregators": [{"node": 0, "country": "finland", "class": "supernode",
                                 "uplink_mbps": 1000, "downlink_mbps": 1000, "validators": 3}],
                "aggregator_countries": [{"country": "finland", "supernode": 1, "regular": 0, "unknown": 0,
                                          "validators": 3}]}})
        self.assertEqual(self.metrics["signature_cdf_by_subnet"], {
            0: {"first_seen": [[50, 25.0], [100, 50.0], [200, 75.0], [300, 100.0]],
                "supernode": [[50, 100.0]],
                "regular": [[100, 25.0], [200, 50.0], [300, 75.0], [400, 100.0]]}})

    def test_aggregator_population_counts_hosts_and_their_subnets(self) -> None:
        self.assertEqual(self.metrics["aggregators"], {
            "hosts": 1, "subnets": 1, "validators": 3,
            "classes": [{"class": "supernode", "uplink_mbps": 1000, "downlink_mbps": 1000, "hosts": 1, "validators": 3}],
            "countries": [{"country": "finland", "supernode": 1, "regular": 0, "unknown": 0, "validators": 3}],
            "subnets_per_host": [{"low": 1, "high": 1, "supernode": 1, "regular": 0, "unknown": 0, "validators": 3}],
        })

    def test_a_run_without_churn_has_no_churn_metrics(self) -> None:
        self.assertIsNone(self.metrics["churn"])
        self.assertNotIn("churn", self.metrics["subnet_hosts"][0])
        self.assertNotIn("offline_ms", self.metrics["traffic"]["1"])

    def test_runs_without_a_node_list_have_no_population(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leansim-analyze-") as temporary:
            directory = write_fixture_run(Path(temporary) / "run")
            (directory / "run-manifest.json").write_text('{"experiment": {"local_threshold": 1.0}}', encoding="utf-8")
            metrics = analyze.build_snapshot(directory)["metrics"]
        self.assertIsNone(metrics["population"])
        self.assertEqual({row["class"] for row in metrics["arrivals"]}, {"unknown"})


class ChurnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="leansim-analyze-")
        cls.snapshot = analyze.build_snapshot(write_churn_run(Path(cls.temporary.name) / "run"))
        cls.metrics = cls.snapshot["metrics"]
        cls.churn = cls.metrics["churn"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_offline_windows_follow_the_churn_events(self) -> None:
        self.assertEqual(analyze.offline_windows([(0, False), (1200, True), (3000, False), (3400, True)], 5000),
                         [[0, 1200], [3000, 3400]])
        self.assertEqual(analyze.offline_windows([(4000, False)], 5000), [[4000, 5000]], "offline until the run ends")
        self.assertEqual(analyze.offline_windows([(700, True)], 5000), [], "a host that only came online was never seen offline")
        self.assertEqual(analyze.crashes_in([[0, 1200], [3000, 3400]]), 1, "starting offline is not a crash")

    def test_settings_say_what_each_class_was_given(self) -> None:
        self.assertEqual(self.churn["tick_ms"], 100)
        self.assertEqual(self.churn["idle_timeout_ms"], 10_000)
        self.assertEqual(self.churn["settings"]["regular"], {
            "fraction": 0.5, "leave_probability": 0.01, "rejoin_probability": 0.05,
            "mean_session_ms": 10_000.0, "mean_gap_ms": 2_000.0, "availability": 0.05 / (0.01 + 0.05),
        })
        self.assertEqual(self.churn["settings"]["supernode"]["fraction"], 0.0)

    def test_classes_count_hosts_online_at_signing_and_signatures_missed(self) -> None:
        self.assertEqual((self.churn["hosts"], self.churn["churny_hosts"]), (4, 2))
        self.assertEqual(self.churn["signing_ms"], 1000)
        self.assertEqual(self.churn["online_at_signing"], 3, "host 2 joins after the signatures were sent")
        self.assertEqual(self.churn["missed_signatures"], 1, "host 2's validator never signed")
        self.assertEqual(self.churn["classes"], [
            {"class": "supernode", "hosts": 1, "churny": 0, "online_at_signing": 1, "crashes": 0, "rejoins": 0,
             "validators": 2, "churny_validators": 0, "missed_signatures": 0},
            {"class": "regular", "hosts": 3, "churny": 2, "online_at_signing": 2, "crashes": 1, "rejoins": 2,
             "validators": 2, "churny_validators": 2, "missed_signatures": 1},
        ])

    def test_availability_steps_with_the_offline_windows(self) -> None:
        series = dict(self.churn["availability"]["all"])
        self.assertEqual(len(series), 50, "one point per tick of the 5 s run")
        # Times count from the first signature, sent at 1000 ms.
        self.assertEqual([series[at - 1000] for at in (0, 1100, 1200, 1400, 1500, 2400, 2500, 4900)],
                         [75.0, 75.0, 100.0, 100.0, 75.0, 75.0, 100.0, 100.0])
        regular = dict(self.churn["availability"]["regular"])
        self.assertEqual(regular[-1000], round(200 / 3, 3))
        self.assertNotIn("supernode", self.churn["availability"], "no supernode churns")

    def test_signatures_got_again_after_a_crash_are_not_first_copies(self) -> None:
        self.assertEqual(self.churn["counters"]["relearned"],
                         {"gossip": 0, "pull": 0, "coded": 0, "bundle": 0, "backlog": 2, "requested": 0})
        self.assertEqual(self.churn["counters"]["relearned_total"], 2)
        deliveries = self.metrics["signature_transport"]["deliveries"]
        self.assertEqual(deliveries["backlog"], {"unique": 1, "duplicate": 1, "bytes": 0})
        self.assertEqual(deliveries["bundle"]["unique"], 2)
        self.assertEqual(self.metrics["unique_signature_events"], 10)

    def test_a_host_logs_transport_stats_once_per_session(self) -> None:
        self.assertEqual(self.metrics["signature_transport"]["hosts"], 3)
        self.assertEqual(self.churn["counters"]["restart_notices_sent"], 2)
        self.assertEqual(self.churn["counters"]["restart_reconnects"], 1)
        self.assertEqual(self.churn["counters"]["sync_failures"], 1)

    def test_catch_up_counts_from_the_rejoin(self) -> None:
        self.assertEqual(self.churn["catch_up_fraction"], 0.75)
        # Host 1 held 3 signatures 300 ms after its rejoin, host 2 700 ms after joining.
        self.assertEqual(self.churn["catch_up"], {
            "regular": {"rejoins": 2, "caught_up": 2, "p50": 300, "p95": 700, "cdf": [[300, 50.0], [700, 100.0]]},
        })
        self.assertEqual(analyze.catch_up_summary([400], 4),
                         {"rejoins": 4, "caught_up": 1, "p50": None, "p95": None, "cdf": [[400, 25.0]]})

    def test_completion_keeps_stable_and_churny_hosts_apart(self) -> None:
        stable, churny = self.churn["completion"]["stable"], self.churn["completion"]["churny"]
        self.assertEqual((stable["pairs"], churny["pairs"]), (2, 2))
        self.assertEqual(stable["90pct"], {"reached": 2, "p50": 50, "p95": 60, "p99": 60, "max": 60})
        self.assertEqual(churny["90pct"], {"reached": 2, "p50": 150, "p95": 900, "p99": 900, "max": 900})

    def test_delivery_charts_keep_churny_hosts_apart(self) -> None:
        self.assertEqual(list(self.metrics["signature_cdf"]), ["first_seen", "supernode", "regular", "regular_churny"])
        self.assertEqual([(row["class"], row["count"]) for row in self.metrics["arrivals"] if row["message"] == "Signatures"],
                         [("supernode", 1), ("regular", 3), ("regular_churny", 6)])
        self.assertEqual(analyze.node_group({"supernode": True, "churny": True}), "supernode_churny")
        self.assertEqual(analyze.node_group({"churny": True}), "unknown")

    def test_pages_about_one_host_or_subnet_get_their_churn(self) -> None:
        self.assertEqual(self.metrics["traffic"]["1"]["offline_ms"], [[1500, 2500]])
        self.assertEqual(self.metrics["traffic"]["1"]["host"]["churn"], {"crashes": 1})
        subnet = self.metrics["subnet_hosts"][0]
        self.assertEqual(subnet["churn"], {"churny": 2, "online_at_signing": 3, "missed_signatures": 1})
        self.assertNotIn("crashes", subnet["aggregators"][0], "host 0 is stable")

    def test_an_aggregator_back_from_a_crash_proves_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leansim-analyze-") as temporary:
            directory = write_churn_run(Path(temporary) / "run")
            log = directory / "shadow.data" / "hosts" / "node-0" / "leansim.1000.stdout"
            again = '{"event": "LocalProofGenerated", "node_id": 0, "subnet_id": 0, "sig_count": 3, "latency_ms": 4000}\n'
            log.write_text(log.read_text(encoding="utf-8") + again, encoding="utf-8")
            metrics = analyze.build_snapshot(directory)["metrics"]
        self.assertEqual(metrics["subnet_proofs"][0]["proofs"], [[100, 0, "supernode"]])
        self.assertEqual(metrics["churn"]["counters"]["repeated_proofs"], 1)

    def test_the_manifest_schedule_stands_in_for_missing_churn_events(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leansim-analyze-") as temporary:
            directory = write_churn_run(Path(temporary) / "run")
            for log in directory.glob("shadow.data/hosts/*/*stdout*"):
                lines = [line for line in log.read_text(encoding="utf-8").splitlines() if '"Churn"' not in line]
                log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            churn = analyze.build_snapshot(directory)["metrics"]["churn"]
        self.assertEqual(churn["online_at_signing"], 3)
        self.assertEqual(churn["classes"][1]["crashes"], 1)


if __name__ == "__main__":
    unittest.main()
