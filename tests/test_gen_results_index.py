"""Regression coverage for classic and integrated runs sharing one Pages index."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from gen_results_index import load_pipeline_run, load_run, render


class ResultsIndexTests(unittest.TestCase):
    def test_pipeline_seed_gets_a_row_and_shared_comparison_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            classic = root / 'classic'
            classic.mkdir()
            (classic / 'run-manifest.json').write_text(json.dumps({'run_id': 'classic', 'seed': 42}))
            (classic / 'summary.html').touch()
            suite = root / 'waggle'
            suite.mkdir()
            (suite / 'index.html').touch()
            runs = [load_run(classic)]
            for seed in (42, 43):
                directory = suite / f'seed-{seed}'
                directory.mkdir()
                (directory / 'summary.html').touch()
                summary = directory / 'pipeline-summary.json'
                summary.write_text(json.dumps({'seed': seed, 'hosts': 13613}))
                (directory / 'experiment.toml').write_text('''run_id = "slots"
validator_count = 32768
subnet_count = 16
local_aggregators_per_subnet = 4
local_threshold = 0.9
signature_transport = "waggle"
waggle_push_selection = "fixed"
waggle_push_peers = 4
''')
                runs.append(load_pipeline_run(summary, root))
            output = render(runs, 'test')
        self.assertIn('3 published runs', output)
        self.assertIn('href="classic/run-manifest.json"', output)
        self.assertEqual(output.count('href="waggle/index.html"'), 1)
        for seed in (42, 43):
            self.assertIn(f'href="waggle/seed-{seed}/summary.html"', output)
            self.assertIn(f'href="waggle/seed-{seed}/pipeline-summary.json"', output)
        self.assertEqual(output.count('Waggle signatures (fixed, 4 peers) + Waggle proofs'), 2)
