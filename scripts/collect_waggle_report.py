"""Reduce a completed integrated Waggle run to publishable report inputs."""
import csv
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

case = Path(sys.argv[1])
read = lambda name: json.loads((case / name).read_text())
summary = read('pipeline-summary.json')
manifest = read('run-manifest.json')
settings = read('pipeline-settings.json')
assert manifest['seed'] == summary['seed']
with (case / 'shadow.log').open(errors='replace') as f:
    assert any('Shadow completed successfully' in line for line in f)
config = manifest['experiment']
# Keep only fields used in the report; do not publish peer keys or addresses.
fields = ('node_id', 'supernode', 'country', 'uplink_mbps', 'downlink_mbps', 'validator_ids',
          'subscribed_subnets', 'signing_subnets', 'aggregated_subnets')
nodes = [{k: node[k] for k in fields} for node in manifest['nodes']]
assert len(nodes) == summary['hosts'] and all(n['node_id'] == i and not manifest['nodes'][i]['churny'] for i, n in enumerate(nodes))
owner = {v: n['node_id'] for n in nodes for v in n['validator_ids']}
count = summary['signatures']
assert set(owner) == set(range(count))
expected_proofs = {(d['producer'], d['subnet']) for d in settings['producers']}
assert expected_proofs == {(n['node_id'], s) for n in nodes for s in n['aggregated_subnets']}
class_names = ('regular', 'supernode')
classes = [int(n['supernode']) for n in nodes]
first_seen = [sys.maxsize] * count
sent = {}
# A host's first-copy bitmap verifies one observation per (host, validator).
# No full per-pair times or raw logs are retained in the output.
seen = [bytearray((count + 7) // 8) for _ in nodes]
sig_counts = [Counter(), Counter()]
variant_counts = [Counter(), Counter()]
variants = Counter()
proofs = {}
sig = re.compile(rb'^\{"event":"SigReceived","node_id":(\d+),"from_id":\d+,"validator_id":(\d+),"from_peer_id":"[^"]*","subnet_id":(\d+),"duplicate":false,"ts_ms":(\d+),')
pattern = '^\\{"event":"(SigReceived".*"duplicate":false|SigSent"|WaggleCommitteeHeld"|LocalProofGenerated")'
cmd = ['rg', '--no-config', '--no-heading', '--no-filename', '--color', 'never', '-a', '--threads', '6',
       '-g', '*.stdout', pattern, str(case / 'shadow.data' / 'hosts')]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
try:
    for line in proc.stdout:
        if line.startswith(b'{"event":"SigReceived"'):
            m = sig.match(line)
            assert m, line[:180]
            n, v, s, time = map(int, m.groups())
            assert 0 <= v < count and s == v // (count // config['subnet_count'])
            octet, mask = v >> 3, 1 << (v & 7)
            assert not seen[n][octet] & mask, (n, v)
            seen[n][octet] |= mask
            sig_counts[classes[n]][time] += 1
            if time < first_seen[v]:
                first_seen[v] = time
            continue
        e = json.loads(line)
        n = e['node_id']
        if e['event'] == 'SigSent':
            v = e['validator_id']
            assert owner[v] == n and v not in sent
            sent[v] = e['ts_ms']
        elif e['event'] == 'LocalProofGenerated':
            key = (n, e['subnet_id'])
            assert key in expected_proofs and key not in proofs
            proofs[key] = e['latency_ms']
        else:
            assert e['event'] == 'WaggleCommitteeHeld'
            variants[(e['producer'], e['subnet_id'])] += 1
            variant_counts[classes[n]][e['ts_ms']] += 1
finally:
    if sys.exc_info()[0] is not None:
        proc.kill()
    proc.stdout.close()
    code = proc.wait()
assert code == 0
assert len(sent) == count and all(sent[v] <= first_seen[v] < sys.maxsize for v in sent)
t0 = min(sent.values())
assert t0 == summary['first_signature_ts_ms']
assert set(proofs) == expected_proofs and len(proofs) == summary['proofs_produced'] == 64
assert set(variants) == expected_proofs and set(variants.values()) == {len(nodes)}
assert sum(variants.values()) == summary['committee_variant_deliveries']
assert min(proofs.values()) - t0 == summary['first_proof_ms'] and max(proofs.values()) - t0 == summary['last_proof_ms']
for k in ('hosts', 'transport_reporters', 'exits', 'quic_stream_traffic_reporters', 'global_proof_hosts'):
    assert summary[k] == len(nodes)
with (case / 'pipeline-receivers.csv').open(newline='') as f:
    receivers = list(csv.DictReader(f))
assert {int(r['node_id']) for r in receivers} == set(range(len(nodes))) and len(receivers) == len(nodes)
assert {int(r['committee_variants']) for r in receivers} == {len(proofs)}
assert [r for r in receivers if int(r['node_id']) == settings['proposer']][0]['all_committees_ms'] == str(summary['proposer_ready_ms'])

def groups(counters):
    return {k: {t - t0: c for t, c in counts.items()} for k, counts in zip(class_names, counters)}

public_config = {k: v for k, v in config.items() if k not in ('node_map',)}
assert config['node_map'] == 'nodes.csv'
public_nodes = [{k: v for k, v in n.items() if k != 'validator_ids'} | {'validator_count': len(n['validator_ids'])} for n in nodes]
result = {'seed': summary['seed'], 'config': public_config | {'node_map': config['node_map']}, 'nodes': public_nodes,
          'signature': groups(sig_counts), 'committee_variants': groups(variant_counts),
          'first_seen': Counter(t - t0 for t in first_seen), 'settings': settings,
          'local_proofs': [[n, s, t] for (n, s), t in sorted(proofs.items())]}
print(json.dumps(result, separators=(',', ':')))
