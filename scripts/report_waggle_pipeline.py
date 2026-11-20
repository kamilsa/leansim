#!/usr/bin/env python3
"""Render a legacy-style summary for an integrated Waggle slot.

Usage: uv run --group analyze python scripts/report_waggle_pipeline.py INPUT_JSON RUN_DIR
INPUT_JSON is the compact output of collect_waggle_report.py. RUN_DIR holds the
existing pipeline summary, receiver CSV, experiment TOML and provenance.
"""

import csv
import html
import json
import sys
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

import analyze
import report


def section(title, name, body):
    return f'<section aria-labelledby="{name}"><h2 id="{name}">{title}</h2>{body}</section>'


def grid_table(labels, rows):
    head = ''.join(f'<th scope="col">{html.escape(label)}</th>' for label in labels)
    body = ''.join('<tr>' + f'<th scope="row">{html.escape(str(row[0]))}</th>'
                   + ''.join(f'<td>{html.escape(str(value))}</td>' for value in row[1:]) + '</tr>'
                   for row in rows)
    return f'<div class="table-scroll" tabindex="0" role="region" aria-label="{html.escape(labels[0])} table"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def configuration(c, s):
    committee = c['validator_count'] // c['subnet_count']
    need = int(committee * c['local_threshold'])
    groups = {
        'Signatures': [
            ('Signature size', f'{c["signature_payload_bytes"]:,} B', ''),
            ('Transfer', f'Bundled Waggle · fixed {c["waggle_push_peers"]}', f'{c["waggle_gossip_peers"]} inventory peers · {c["bundle_request_delay_ms"]} ms pull delay'),
            ('Bundles', f'Up to {c["bundle_max_signatures"]} signatures', f'{c["bundle_tick_ms"]} ms tick · {c["bundle_stagger_ms"]:,} ms fallback'),
            ('Signing', f'{c["burst_time_ms"]}–{c["burst_time_ms"] + c["burst_jitter_ms"]} ms after warmup', f'{c["mesh_warmup_ms"]:,} ms warmup'),
        ],
        'Aggregation': [
            ('Committees', f'{c["subnet_count"]} × {committee:,} validators', f'Exactly {c["local_aggregators_per_subnet"]} aggregator hosts per committee'),
            ('Local threshold', f'{c["local_threshold"]:.0%} · {need:,} signatures', f'Modeled at {c["signature_aggregation_rate"]:,} signatures/s'),
            ('Proposer combine', f'{c["recursive_aggregation_time_ms"]:,} ms', 'Starts with one complete proof per committee'),
            ('Proof size', f'{s["proof_bytes"]:,} B', f'{s["chunks"]} authenticated pieces per committee or global proof'),
        ],
        'Network and proofs': [
            ('Proof transport', 'Waggle chunks', 'Signed commitments on GossipSub'),
            ('Commitment mesh', ' / '.join(str(c['gossipsub_mesh_n' + suffix]) for suffix in ('_low', '', '_high')), f'Low / target / high · {c["gossipsub_heartbeat_interval_ms"]} ms heartbeat'),
            ('Signature subscriptions', f'{c["subnet_subscriptions_per_node"]} per host', f'{c["publish_subnet_peer_count"]} target peers for publish-only subnets'),
            ('Inventory', c['node_map'], 'All hosts · geography-based simulated latency'),
        ],
    }
    cards = []
    for title, rows in groups.items():
        cells = ''.join(f'<tr><th scope="row">{html.escape(label)}</th><td><b>{html.escape(value)}</b>'
                        + (f'<span class="note">{html.escape(note)}</span>' if note else '') + '</td></tr>'
                        for label, value, note in rows)
        cards.append(f'<div class="config-card"><h3>{title}</h3><table class="config"><tbody>{cells}</tbody></table></div>')
    return section('Configuration', 'config', '<p class="caption">Run settings from the experiment and Shadow manifest.</p>'
                   + f'<div class="config-grid">{"".join(cards)}</div>')


def distribution(raw):
    return {k: Counter({int(ms): count for ms, count in values.items()}) for k, values in raw.items()}


def coverage_figure(committee, global_, generated):
    traces = []
    for name, counts, color, dash in (
        ('One proof from every committee', committee, '#52514e', 'dash'),
        ('Global proof', global_, '#2a78d6', 'solid'),
    ):
        points = analyze.frequency_cdf(counts, limit=len(counts) + 1)
        traces.append({'type': 'scatter', 'mode': 'lines', 'name': name,
                       'x': [0] + [ms / 1000 for ms, _ in points], 'y': [0] + [value for _, value in points],
                       'line': {'color': color, 'width': 2.5, 'dash': dash, 'shape': 'hv'},
                       'hovertemplate': '%{y:.2f}% by %{x:.3f} s<extra>' + name + '</extra>'})
    return {'data': traces, 'layout': {
        'xaxis': {'title': {'text': 'time after the first signature was sent (s)'}, 'rangemode': 'tozero'},
        'yaxis': {'title': {'text': 'hosts'}, 'range': [0, 101], 'ticksuffix': '%'},
        'legend': {'orientation': 'h', 'x': 0, 'y': 1.13},
        'shapes': [{'type': 'line', 'xref': 'x', 'yref': 'paper', 'x0': generated / 1000, 'x1': generated / 1000,
                    'y0': 0, 'y1': 1, 'line': {'color': '#898781', 'width': 1, 'dash': 'dot'}}],
    }}


def render(raw, directory):
    from plotly.offline import get_plotlyjs

    s = json.loads((directory / 'pipeline-summary.json').read_text())
    cfg = tomllib.loads((directory / 'experiment.toml').read_text())
    assert s['seed'] == cfg['geo_seed'] == raw['seed']
    assert all(raw['config'][k] == v for k, v in cfg.items())
    assert s['global_generated_ms'] - s['proposer_ready_ms'] == cfg['recursive_aggregation_time_ms']
    # Legacy population helpers only read the lengths of validator lists.
    hosts = {n['node_id']: {**n, 'validator_ids': range(n['validator_count'])} for n in raw['nodes']}
    assert len(hosts) == s['hosts'] == len(raw['nodes'])
    population = analyze.host_population(hosts, cfg)
    aggregators = analyze.aggregator_population(hosts)
    assert population is not None and aggregators is not None
    assert population['validators'] == s['signatures'] == cfg['validator_count']
    assert aggregators['hosts'] == s['proof_duties'] == s['proofs_produced']
    assert raw['settings']['proposer'] == s['proposer_host'] and raw['settings']['proposer_validator'] == s['proposer_validator']
    sig_counts = distribution(raw['signature'])
    variant_counts = distribution(raw['committee_variants'])
    first_seen = Counter({int(ms): count for ms, count in raw['first_seen'].items()})
    assert first_seen.total() == s['signatures']
    assert sum(v.total() for v in variant_counts.values()) == s['committee_variant_deliveries'] == s['possible_variant_deliveries']
    with (directory / 'pipeline-receivers.csv').open(newline='') as f:
        receivers = {int(r['node_id']): r for r in csv.DictReader(f)}
    assert receivers.keys() == hosts.keys() and len(receivers) == s['global_proof_hosts'] == s['all_committee_proofs_hosts']
    global_counts = defaultdict(Counter)
    committee = Counter()
    for n, r in receivers.items():
        assert int(r['committee_variants']) == s['proof_duties']
        global_counts[analyze.node_class(hosts[n])][int(r['global_proof_ms'])] += 1
        committee[int(r['all_committees_ms'])] += 1
    global_ = sum(global_counts.values(), Counter())
    assert analyze.frequency_percentiles(global_, (50, 95)) == {'count': s['hosts'], 'p50': s['global_proof_p50_ms'], 'p95': s['global_proof_p95_ms']}
    assert analyze.frequency_percentiles(committee, (95,)) == {'count': s['hosts'], 'p95': s['all_committee_proofs_p95_ms']}
    assert min(global_) == s['global_generated_ms'] and max(global_) == s['global_proof_last_ms']
    assert {deadline: sum(c for t, c in global_.items() if t <= int(deadline)) for deadline in s['global_coverage_by_ms']} == s['global_coverage_by_ms']
    assert int(receivers[s['proposer_host']]['all_committees_ms']) == s['proposer_ready_ms']
    local = analyze.subnet_proof_rows(raw['local_proofs'], s['first_signature_ts_ms'], hosts)
    assert len(local) == cfg['subnet_count'] and {r['count'] for r in local} == {cfg['local_aggregators_per_subnet']}
    assert min(r['min'] for r in local) == s['first_proof_ms'] and max(r['max'] for r in local) == s['last_proof_ms']
    arrivals = []
    for label, counts in [('Signatures', sig_counts), ('Committee proof variants', variant_counts), ('Global proof', global_counts)]:
        for kind in ('supernode', 'regular'):
            stats = analyze.frequency_percentiles(counts[kind])
            if stats:
                arrivals.append({'message': label, 'class': kind, **stats})
    metrics = {'population': population, 'aggregators': aggregators, 'arrivals': arrivals, 'subnet_proofs': local,
               'signature_cdf': {k: analyze.frequency_cdf(h) for k, h in (sig_counts | {'first_seen': first_seen}).items()}}
    figures = {
        'cdf': report.cdf_figure(metrics), 'arrival': report.arrival_figure(metrics),
        'validators': report.validators_figure(population), 'countries': report.countries_figure(population),
        'subnet-counts': report.subnet_counts_figure(aggregators), 'aggregator-countries': report.countries_figure(aggregators),
        'subnet-proofs': report.subnet_proofs_figure(metrics), 'proof-coverage': coverage_figure(committee, global_, s['global_generated_ms']),
    }
    figures['subnet-proofs']['layout']['yaxis']['tickfont']['color'] = '#52514e'
    figures['arrival']['layout']['margin']['l'] = 132
    sig95 = {r['class']: r['p95'] for r in arrivals if r['message'] == 'Signatures'}
    signing = sum(n['validator_count'] > 0 for n in hosts.values())
    supernodes = sum(n['supernode'] for n in hosts.values())
    sec = lambda t: f'{t / 1000:.3f} s'
    cards = [('Hosts', f'{s["hosts"]:,}', f'{supernodes:,} supernodes'),
             ('Validators', f'{s["signatures"]:,}', f'{signing:,} signing hosts'),
             ('Signature delivery p95', sec(sig95['regular']), f'Regular nodes · supernodes {sec(sig95["supernode"])}'),
             ('Global proof produced', sec(s['global_generated_ms']), f'Proposer ready at {sec(s["proposer_ready_ms"])}'),
             ('Global proof delivery p95', sec(s['global_proof_p95_ms']), f'{s["global_proof_hosts"]:,} of {s["hosts"]:,} hosts reached')]
    kpis = '<div class="kpis five">' + ''.join(f'<div class="kpi"><span class="label">{label}</span><b>{value}</b><span class="note">{note}</span></div>' for label, value, note in cards) + '</div>'
    seed = s['seed']
    navigation = '<nav class="host-strip" aria-label="Results navigation"><a href="../../index.html">All runs</a><a href="../index.html">Compare seeds</a></nav>'
    sig = section('Signature propagation', 'propagation',
                  f'<p class="caption">The dotted line counts each validator once, at its first logged receipt. '
                  f'The other lines count first receipts by host class, one per host and validator, across the subnets a host tracked. '
                  f'{sum(h.total() for h in sig_counts.values()):,} first receipts were logged. '
                  'The curves normalize by observed receipts, not all possible deliveries; signing events are not receipt events.</p>'
                  '<div class="chart" id="cdf" aria-label="Signature propagation by host class"></div>')
    arrival = section('Arrival times across hosts', 'arrivals',
                      '<p class="caption">Whiskers span p5–p95, boxes p25–p75, and lines mark the median. '
                      'Each observed signature receipt, each complete committee proof variant, and the one global proof count once per host. '
                      'For proofs, local production counts as possession.</p><div class="chart" id="arrival" style="height:320px"></div>'
                      f'<div class="table-scroll" tabindex="0" role="region" aria-label="Arrival percentiles">{report.arrival_table(metrics)}</div>')
    proofs = section('Subnet proof times', 'subnet-proofs-heading',
                     f'<p class="caption">All {s["proofs_produced"]} subnet proofs finished. Each dot is one aggregator; '
                     'hover to see its node and completion time. The box shows p25 to p75, with the median line and first-to-last whiskers.</p>'
                     f'<div class="chart" id="subnet-proofs" style="height:{report.subnet_proofs_height(local)}px"></div>'
                     + grid_table(['Subnet', 'Aggregator host', 'Class', 'Country', 'Finished'],
                                  [(r['subnet'], n, report.CLASS_STYLE[k][1], (hosts[n]['country'] or 'unknown').title(), sec(ms))
                                   for r in local for ms, n, k in r['proofs']]))
    coverage = section('Global-proof delivery', 'coverage',
                       f'<p class="caption">Proposer host {s["proposer_host"]:,} collected a complete proof from all {cfg["subnet_count"]} committees at {sec(s["proposer_ready_ms"])}. '
                       f'After the modeled combination it published at {sec(s["global_generated_ms"])} (dotted marker), and the last host received the proof at {sec(s["global_proof_last_ms"])}. '
                       f'All {s["committee_variant_deliveries"]:,} committee proof × host pairs completed.</p><div class="chart" id="proof-coverage"></div>'
                       + grid_table(['Global-proof deadline', 'Hosts reached', 'Still waiting'],
                                    [(sec(int(t)), f'{n:,}', f'{s["hosts"]-n:,}') for t, n in s['global_coverage_by_ms'].items()]))
    downloads = section('Traffic and data', 'data',
                        f'<p class="caption">{s["quic_stream_traffic_bytes"]:,} bytes of QUIC stream writes across {s["quic_stream_traffic_reporters"]:,} reporting hosts. '
                        'This is not packet-level traffic and does not isolate a signature or proof phase.</p>'
                        '<p><a href="pipeline-summary.json">Summary JSON</a> · <a href="pipeline-receivers.csv">Receiver CSV</a> · '
                        '<a href="experiment.toml">Experiment TOML</a> · <a href="provenance.json">Input hashes</a></p>')
    body = ''.join((kpis, configuration(cfg, s), report.network_section(population, aggregators), sig, arrival, proofs, coverage, downloads))
    title = html.escape(f'{cfg["run_id"]} · seed {seed}')
    # Use the classic report's stylesheet and Plotly settings; the event semantics differ from its recursive runner.
    css = report.PAGE_CSS + '\n.kpis.five{grid-template-columns:repeat(5,minmax(0,1fr))}.two>div{min-width:0}.config td b{white-space:normal}#subnet-proofs .ytick text{cursor:default}#subnet-proofs .ytick text:hover{text-decoration:none}@media(max-width:760px){.kpis.five{grid-template-columns:repeat(2,minmax(0,1fr))}}\n'
    plotly = '\n'.join(line.rstrip() for line in get_plotlyjs().split('\n')).replace('</script', '<\\/script')
    script = '''const figures = JSON.parse(document.getElementById('report-data').textContent);
for (const [id, figure] of Object.entries(figures)) {
  Plotly.newPlot(id, figure.data, plotLayout(figure.layout), PLOT_CONFIG);
}'''
    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>leanSim summary: {title}</title><style>{css}</style></head><body><main>
{navigation}<header class="page"><p class="eyebrow">leanSim run summary</p><h1>{title}</h1>
<p class="facts">Integrated Waggle pipeline · local threshold {cfg['local_threshold']:.0%}</p></header>
{body}
<footer class="page">Times are simulated. t = 0 is first signature send ({sec(s['first_signature_ts_ms'])} into the run). All proving costs are modeled.</footer>
</main><script id="report-data" type="application/json">{report.json_data(figures)}</script>
<script>{plotly}</script><script>{report.COMMON_JS}</script><script>{script}</script></body></html>
'''
    (directory / 'summary.html').write_text(document, encoding='utf-8')
    print(f'Seed {seed}: {sig_counts["regular"].total() + sig_counts["supernode"].total():,} observed first signature receipts; p95 regular {sec(sig95["regular"])} / supernodes {sec(sig95["supernode"])}')


if __name__ == '__main__':
    data, out = map(Path, sys.argv[1:])
    render(json.loads(data.read_text()), out)
