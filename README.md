# leansim

`leansim` simulates hierarchical validator signature aggregation over real
`rust-libp2p` QUIC and gossipsub nodes running in the
[Shadow](https://shadow.github.io/) discrete-event network simulator.

Validators publish signatures and local aggregators collect each subnet's
threshold into a local proof (computed, not transmitted: global aggregation was
removed and will be redesigned). Experiments can model
uniform or country-based latency, supernode bandwidth, sparse network graphs,
gossipsub mesh settings, and churn: hosts that crash and rejoin during the run.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Docker for the default `docker` runner
- Rust and a Linux `shadow` executable on `PATH` for the `native` runner

The Docker runner targets `linux/arm64`, including Apple Silicon. Shadow runs
Linux binaries, so macOS users should use Docker.

## Run

The launcher takes an experiment TOML. `experiments/` holds the 65k
(`nodes_small.csv`) and 131k (`nodes.csv`) node-map configs; both CSVs are kept
out of git and must be present in the repo root.

```bash
# Build (if needed) and run an experiment.
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml

# Generate shadow.yaml, topology.gml, node TOMLs, and run-manifest.json only.
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --dry-run

# Rebuild the Docker image and discard the output directory's prior campaign.
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --rebuild --clean

# Run and serve an offline interactive report at http://0.0.0.0:4321/summary.html.
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --clean --serve

# Rebuild and serve the report from existing results without simulating.
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --serve-only

# Rebuild only the existing report.
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --summary-only

# Merge snapshots from other output directories into runs-history.json
# (summary.html shows the primary run only).
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --serve-only --overlay other-output
```

`--serve` appends each completed run to `runs-history.json`, writes a
self-contained `summary.html` with Plotly embedded, and serves the output
directory until Ctrl+C. The report works without a network connection after it
has been generated.

## Configure

Experiments retain leansim's original flat simulation settings and
`[network_defaults]` table. The launcher adds these tables:

```toml
[run]
# "docker" builds leansim into a Shadow image. "native" builds with cargo and
# runs the Shadow executable found on PATH. "local" is accepted as an alias.
runner = "docker"
runs = 1
parallelism = 10
# Shadow pins its workers and the processes they run to the lowest-numbered
# cores. Set false when several simulations share a machine, or they all land
# on the same cores; confine each with taskset instead.
cpu_pinning = true

[docker]
shadow_image = "kamilsa/shadow-arm:latest"
image_name = "leansim-shadow:local"
rebuild = false

[output]
dir = "output"
```

Each run uses `geo_seed + run_index` and replaces `shadow.data` in the output
directory. The launcher snapshots the resulting metrics immediately, so a
multi-run campaign is retained in `runs-history.json` even though Shadow's raw
logs are replaced on the next run.

`validator_count` is the number of signing validators. In each subnet, the first
`local_aggregators_per_subnet` validators also collect signatures and compute
local proofs; they are not additional hosts, so there are `validator_count`
hosts unless validators share hosts (see below).

The launcher validates experiment counts and thresholds before building. In
particular, `validator_count` must be divisible by `subnet_count`.

### Several validators per physical node

As on Ethereum mainnet, one physical node can run many validators. Co-location
comes from a nodes.csv node map (below); without `node_map`, every validator
runs on its own host.

A host publishes one signature per validator it runs, back to back after a
single burst delay. Validator ids are split into contiguous subnets of
`validator_count / subnet_count`, and an aggregating host counts its own
validators' signatures immediately. Countries, supernodes, and bandwidth are
assigned per host.

### Ethereum-style node map (nodes.csv)

Set `node_map` to a nodes.csv table (`node_type, peer_key, validator_count, ...`,
one row per physical node) for a topology closer to mainnet:

```toml
validator_count = 512
node_map = "nodes.csv"                 # relative to the repo root
subnet_subscriptions_per_node = 2     # default 2
subnet_count = 8
```

`validator_count` validator slots are sampled from the map's nodes, so the
validators-per-host distribution matches the real network (a node with 20
validators is 20x more likely to receive validators than one with 1).
`no_validator` nodes are sampled on top, preserving their real share of the host
population (~20%), and run as gossip-only relays: they subscribe, forward, and
occupy bandwidth, but never sign.

Every node subscribes to `subnet_subscriptions_per_node` random subnets,
independent of the subnets its validators publish to — as on Ethereum, a
validator's attestations go to the subnet duty assigns, not the subnets its
node is subscribed to. Publishing to a non-subscribed subnet works through
gossipsub's fanout cache. With `subscribe_to_duty_subnets = true`, validator
hosts additionally subscribe to the subnets their validators publish in, so a
node's subscription count scales with the validators it runs, as beacon nodes
on mainnet (duty subnets plus the random gossip ones); relays keep the random
ones only. Local aggregators are promoted from each subnet's subscribers, so
an aggregator always collects a subnet it is subscribed to. With `node_map`,
node ids are unrelated to validator ids.

Gossipsub publication uses the normal mesh by default:

```toml
# Set to a positive value to choose this many remote local aggregators in each
# signing node's subnet. They become reciprocal gossipsub explicit peers.
gossipsub_explicit_aggregator_count = 0

# false sends local publications to mesh peers and explicit peers only. Set true
# to also publish directly to every connected subscribed peer.
gossipsub_flood_publish = false

# false stops the heartbeat's gossip to non-mesh peers: no IHAVE is sent, so no
# IWANT follows and messages travel over mesh links only. With bundled
# propagation it also stops the advertisements to non-mesh peers.
gossipsub_gossip = true
```

The first gossipsub heartbeat fires after `gossipsub_heartbeat_initial_delay_ms`,
which defaults to `gossipsub_heartbeat_interval_ms`. Until then a node's mesh
holds only the first `gossipsub_mesh_n_low` peers to subscribe, which are its
lowest-latency neighbours, and no IHAVE gossip is sent. With libp2p's 5 s
default (set `gossipsub_heartbeat_initial_delay_ms = 5000` to reproduce it),
signatures stayed inside their region until about 5 s after start.

Every host waits the same mesh warmup before signing, so all of them vote at
once: 1,500 ms, or 3,000 ms when any host dials more than 200 peers. The
launcher derives it from the busiest host and records it as `mesh_warmup_ms`
(set it in the experiment to override). With per-host warmups, hosts past the
dial threshold signed late and dropped the gossip that reached them while
still warming up.

The explicit aggregator count must be smaller than
`local_aggregators_per_subnet`, because local aggregators also sign and cannot
select themselves. Explicit peers are additional direct forwarding links and do
not count toward `gossipsub_mesh_n`.

#### Committee aggregators

With `committee_aggregators = true` (requires `node_map`), aggregation follows
Ethereum's committee model:

- Each validator belongs to exactly one committee: `validator_count / subnet_count`
  validators per committee, as contiguous id blocks. Ids are dealt over randomly
  sampled node-map slots, so every committee is a random set of validators.
- Committee `i` attests on subnet `i` (one slot of `subnet_count` committees).
- Aggregators are picked by Ethereum's `is_aggregator` lottery: a validator wins when
  `hash(geo_seed, validator)[0:8] % max(1, committee_size / local_aggregators_per_subnet) == 0`,
  so `local_aggregators_per_subnet` is the expected number per committee. The host
  of a winning validator aggregates that committee's subnet. Hosts without
  validators never aggregate. A host with winners in several committees
  aggregates all of them; several winners on one host still make one aggregator.
- Each aggregated subnet gets its own ≥ `local_threshold` proof. Proofs compute in
  parallel (`sig_count / signature_aggregation_rate` each) without pausing the
  host's gossip. Without recursive aggregation they are logged, not transmitted.

Without the flag, `local_aggregators_per_subnet` hosts are promoted among each
subnet's subscribers, one subnet per host, possibly relays.

#### Recursive aggregation

With `recursive_aggregation = true` (requires `committee_aggregators = true`), subnet
proofs are aggregated recursively until one final proof remains, as leanVM's
`aggregate` proves one proof from up to 16 child proofs:

- Layer 1 has `ceil(subnet_count / arity)` groups; group `i` aggregates subnets
  `i*arity` to `(i+1)*arity - 1`. Each later layer aggregates `arity` groups of the
  layer below until one group remains. 64 subnets give 32/16/8/4/2/1 groups at
  arity 2, 16/4/1 at 4, and 8/1 at 8.
- Group members are attesters, drawn like subnet aggregators. Validator ids are
  dealt into one pool per group in a `geo_seed`-keyed hash order; a validator wins a
  seat when `hash(geo_seed, validator)[0:8] % max(1, pool_size / recursive_group_size) == 0`,
  so `recursive_group_size` is the expected number of winners per group. A validator
  that won a subnet duty is skipped, so no validator holds two duties; a host can
  hold several through different validators, and several winners on one host share
  one seat.
- Proofs travel by announce and pull over a request-response protocol
  (`/leansim/proof/1`). An aggregator that finishes a proof announces it to every
  member of the next group. A member pulls each child proof from the first
  announcer, from up to `recursive_proofs_per_child` announcers at once until one
  copy arrives, and announces the child proofs it holds to its group's other
  members, who can pull from it too.
- A member proves once it holds one proof of every child. The proof takes
  `recursive_aggregation_time_ms`, whatever the arity, so set the two together.
  The final group's first proof is the final proof.

| Key | Default | Meaning |
|---|---|---|
| `recursive_aggregation` | `false` | Enable recursive aggregation |
| `recursive_aggregation_arity` | `2` | Child proofs per recursive proof, 2 to 16 |
| `recursive_aggregation_time_ms` | `276` | Time of one recursive proof (leanVM 2-to-1 on an M4 Max) |
| `recursive_group_size` | `16` | Expected members per group (lottery target) |
| `recursive_proofs_per_child` | `1` | Announcers a member pulls one child proof from at once |
| `aggregate_proof_bytes` | `262144` | Wire size of every subnet and recursive proof |

On the 65k network (`experiments/nodemap-small-65k-recursive-sub64.toml`):

| Arity | Groups | Seats (hosts) | Members per group | Most seats on one host |
|---|---|---|---|---|
| 2 | 63 (32/16/8/4/2/1) | 826 (150) | 7-22 | 50 |
| 4 | 21 (16/4/1) | 269 (92) | 8-18 | 16 |
| 8 | 9 (8/1) | 115 (57) | 7-18 | 8 |

### Subnet-proof broadcast comparison (PQ-CL)

`scripts/subnet-proof-campaign.py` runs the same single-round workload in Shadow
with four strategies on the same connections and producer roster:

- `announce_pull`: a holder announces each complete proof to its connected
  peers. A receiver fetches one copy from the first advertiser, retries another
  on failure, and reannounces only after the full response arrives.
- `gossipsub`: the producer publishes each proof whole on a global proof topic.
- `eip8411`: the producer builds a Merkle tree over the pieces, signs only its
  root, and publishes the pieces independently on one global proof topic. Every
  piece message carries its Merkle path and that one 2,400-byte root signature,
  because a publisher cannot know which receivers already hold it. Nothing is
  sent ahead of the release. A receiver checks that the path leads to a root the
  producer signed, holds the proof to the first such root, and needs every index
  from the same producer to count a proof as available. This adapts the draft's
  chunked GossipSub path, not Lighthouse's Waggle implementation, with no block,
  BAL or erasure coding.
- `waggle`: the same pieces and root signature on one Waggle topic over mutually
  subscribed connections. Every chunk message carries its Merkle path. The
  signature goes along only while the peer may lack it: a host leaves it out once
  the peer has advertised or sent a chunk, or once it has queued the peer a signed
  one on the current stream. A receiver verifies the signature on its first
  chunk and accepts later chunks on their Merkle path alone; it refuses a chunk
  without a signature while it holds no signed root. The simulator has no
  post-quantum scheme: an Ed25519 signature authenticates and filler brings it to
  2,400 bytes.
  Every peer on the topic is a push target; an inventory only says which chunks a
  peer already holds. The proof policy follows ec-sim's Lighthouse-inspired defaults:
  push to up to two peers per chunk, favor shorter queues, coalesce inventories
  over 50 ms, and pull rare chunks with one outstanding request per peer per
  proof. Receivers eager-push for 250 ms after their first chunk; producers are
  exempt. This uses leanSim's vendored Waggle library and proof-specific encoding,
  not Lighthouse block messages or ec-sim's optional turn-taking policy.

Run all four arms for two seeds and one or two producers per subnet:

```sh
python3 scripts/subnet-proof-campaign.py output-subnet-proofs \
  --build --nodes 256 --seeds 42 43 --copies 1 2 --seconds 25
```

On a machine with a working local leanSim Shadow image, use
`--base-image leansim-shadow:waggle` with `--build` to reuse its Shadow runtime.
Default proof size is 200,000 bytes, with 16 subnets, 16 chunks, and IDONTWANT
enabled above 1,000 bytes for GossipSub. No arm sends a commitment ahead of the
release. `--commitment-lead-ms` (default 500) is kept only as the start of the
traffic count, that long before the release, so byte totals stay comparable with
earlier runs. Mesh settings do
not affect the Waggle arm, which sends nothing on GossipSub. Regular
hosts have 25/50 Mbit/s up/down; 5% have 1 Gbit/s each way. Every host is a
candidate proposer. The synthetic proof bytes are released together by default;
pass `--stagger-ms` to spread release times across producers.

To reuse an existing mixed network, pass `--network-config` with its experiment
TOML and keep the referenced node map relative to that file. This preserves the
host and validator placement, bandwidth, geographic latency, and peer overlay
for each seed. Producers are distinct validator hosts with duties in the
corresponding subnet. The one-producer roster is a subset of the two-producer
roster. Every host, including relays, is measured for proof readiness.

On a Linux host with Shadow installed, build with `cargo build --release --locked`
and use `--native-binary target/release/leansim` instead of `--build`. For example:

```sh
python3 scripts/subnet-proof-campaign.py output-subnet-proofs-mixed \
  --network-config mixed-network.toml --native-binary target/release/leansim \
  --seeds 42 43 --copies 1 2 --seconds 25 --parallelism 24
```

`comparison.json` and each arm's `receivers.csv` record coverage and time from
first release until a host has at least one full proof for every subnet (its own
proof counts). The denominator for traffic overhead is one full transfer per
non-origin host for every produced proof, not just the first proof per subnet.
Traffic counts bytes written to QUIC streams, including duplicate data, framing
and control from first commitment time to run end. It excludes UDP/IP, packet
overhead and retransmissions. Missing receivers are counted separately and not
included in latency percentiles.

This benchmark does not send signatures, perform real proof verification or
recursion, model churn, or include parallel block traffic. Arrival latency is
not time from the start of a slot and does not validate a slot schedule by itself.

### Integrated Waggle slot

`scripts/waggle-pipeline.py` prepares and summarizes a native Shadow run that
uses the regular signature event loop and the same authenticated chunk policy as
the proof-only Waggle arm. Committee proofs are released only when the local
signature threshold is met and simulated proving finishes. One proposer, chosen
from the placed validators, takes the first complete proof for each committee,
waits the configured simulated combination time, and broadcasts its global
proof. Every chunk carries its producer's signed commitment; proofs use a separate
topic on the same Waggle behaviour as signatures. Both committee variants and the final
proof continue to propagate. This models one slot, not a real prover or a block.

Use the original `nodes.csv` at the repository root. This experiment chooses
exactly four subscriber hosts per committee, not a validator lottery with an
expected count of four. On a Linux host with Shadow installed:

```sh
cargo build --release --locked
python3 scripts/waggle-pipeline.py prepare output-waggle-pipeline \
  --config experiments/nodemap-32k-allhosts-waggle-pipeline.toml \
  --binary target/release/leansim
(cd output-waggle-pipeline && shadow -d shadow.data --progress true \
  --parallelism 24 --use-cpu-pinning false shadow.yaml >shadow.log 2>&1)
python3 scripts/waggle-pipeline.py summary output-waggle-pipeline
```

`pipeline-summary.json` and `pipeline-receivers.csv` measure latencies from the
first signature. The summary records all 64 committee proof variants, proposer
readiness, global-proof creation, deadline coverage, and total QUIC stream
bytes across both transports. Latency percentiles include only hosts that
reached the relevant milestone; use the coverage counts alongside them.

#### Traffic logs

Logging every host's traffic would dominate the run's output, so logging is
opt-in per host: `traffic_log_nodes` lists the hosts that keep it, and only those
node configs get `traffic_log = true`.

- Each logged host records `TrafficBucket` events every `traffic_log_bucket_ms`
  (default 100 ms): bytes sent and received in that bucket broken down by
  `signature`, `duplicate_signature`, `proof_announce`, `proof_request`,
  `proof_payload`, `proof_control` (acks, missing answers), and with signature
  sync `sync_control` (bitmaps, pull requests, acks) and `sync_payload` (pulled
  signatures, coded packets).
- At exit it writes one `TrafficPeer` event per peer with the run's totals.
- Incoming signatures are attributed to the peer that forwarded them. Gossipsub
  does not expose which peers a forward went to, so outgoing gossip is attributed
  one copy per MESH peer, up to the lazy fan-out (`ceil(sqrt(mesh_n))`); with fewer
  mesh peers than that, the logged total is below `NodeStats.bytes_sent`.
- Proof traffic is attributed to the peer's node id, so a peer shows up under
  `node:<id>` on the proof side and `peer:<base58>` on the gossip side; the
  analyzer resolves both through the `NodePeerId` events.
- Traffic events carry no `byte_size`, so they never enter the run's signature
  traffic totals.
- `scripts/report.py` writes `traffic-<node>.html` per logged host: sent above
  and received below the axis, stacked areas by kind in MB/s (averaged over each
  bucket), with the host's country, class, link rates, validator count, role
  and aggregation duties (subnets, tree layers, final proof) in the header, a ranked peer-exchange table below, and links between tracked
  hosts and back to the summary.
  Run-wide markers show the median signature-send time, first subnet proof and
  first final proof (when available). Curved outlines are the default;
  enable **Raw buckets** for the exact step view. Curves are display interpolation
  only: totals, peak rates and hover values still use measured buckets.
  Empty intervals have zero-valued endpoints. The time axis starts at run start
  (zero); when `mesh_warmup_ms` is known, the warmup interval is shaded and marked
  "traffic not captured" rather than hidden or filled with artificial zero samples.
  These are application-level rates, not exact wire bandwidth: outgoing gossip
  is estimated, IHAVE/IWANT and transport overhead are not measured, and proof
  payloads are attributed when handled rather than throughout their transfer.

| Key | Default | Meaning |
|---|---|---|
| `traffic_log_nodes` | `[]` | Hosts that keep traffic logs |
| `traffic_log_bucket_ms` | `100` | Bucket width of the traffic chart |

#### Signature sync

Signatures always travel by gossipsub's eager push. `signature_sync` adds a
per-hop protocol between each subnet's gossipsub mesh neighbours (libp2p
request-response, `/leansim/sigsync/1`). Nobody needs to know which hosts
aggregate: every subscriber collects and relays the subnet's signatures, and
messages go to one mesh neighbour each, never forwarded as they are.

- `none`: gossipsub only.
- `bitmap_pull`: neighbours send each other a bitmap of the signatures they hold
  (one bit per validator of the subnet, 128 B for 1,024 validators) whenever it
  changes, and every `sync_refresh_ms` while incomplete. A host pulls a
  signature it lacks from the neighbours that advertised it once the first
  advertisement is `sync_grace_ms` old, at most `sync_pull_batch` per neighbour
  per tick, spreading the pulls over the advertisers.
- `coded_repair`: the same bitmaps; a host pushes each neighbour random
  GF(2^8) combinations of the signatures that neighbour lacks, counting a
  signature as lacking only if the neighbour's bitmap came `sync_grace_ms` after
  this host got it. Each neighbour sends ceil(`sync_coded_redundancy` x gaps /
  its mesh size) packets per bitmap heard, so the mesh shares a peer's repair
  without coordinating, and every combination is useful to the receiver whoever
  else sent one. Receivers run incremental Gaussian elimination; a signature
  learned by gossip or decoding is subtracted from pending equations. Each
  packet carries a 2-byte index and a coefficient per signature plus one
  signature-sized payload. `sync_coded_degree = 0` combines about log2(gaps) + 2
  signatures (at most 16): with uncoordinated senders, degrees 2-3 leave 8-20 %
  of gaps undecodable however many packets arrive. `sync_coded_degree = 1` sends
  uncoded random repairs, the no-coding control.

The simulator carries no real signature bytes: each signature stands in as a
one-byte symbol, combined alongside the coefficients, so every decode is
checked (`coded_mismatches` must stay 0). Shadow does not model CPU time, so
encoding and decoding are free in simulated time.

`gossipsub_idontwant_threshold_bytes` turns on the gossipsub v1.2 IDONTWANT
backported to the vendored gossipsub: on first receipt of a message larger than
the threshold, a host tells the topic's other mesh peers not to send it, and a
forward still in a peer's send queue is dropped when that peer's IDONTWANT
arrives.

| Key | Default | Meaning |
|---|---|---|
| `gossipsub_idontwant_threshold_bytes` | `0` | IDONTWANT for larger messages; 0 = off |
| `signature_sync` | `"none"` | `none`, `bitmap_pull` or `coded_repair` |
| `sync_interval_ms` | `100` | Tick: send changed bitmaps, plan pulls or repairs |
| `sync_grace_ms` | `300` | Gossip's head start before pulling or repairing |
| `sync_refresh_ms` | `1000` | Repeat an incomplete host's bitmap; re-arm repair budgets |
| `sync_pull_batch` | `16` | Signatures pulled from one neighbour per tick |
| `sync_pull_timeout_ms` | `1000` | Retry an unanswered pull elsewhere after this |
| `sync_coded_degree` | `0` | Signatures per coded packet; 0 = about log2(gaps) + 2 |
| `sync_coded_redundancy` | `1.1` | Coded packets the mesh sends per gap |
| `sync_coded_per_tick` | `8` | Coded packets to one neighbour per tick |

Every `SigReceived` names how the signature came (`via`: `gossip`, `pull`,
`coded`, and with bundles `bundle`, `backlog` or `requested`), and a signature already held
through any path counts as a duplicate.
Each host writes a `TransportStats` event at exit with gossipsub control ids
(IHAVE, IWANT, IDONTWANT, suppressed and dropped forwards), the messages that
answered its IWANTs (`iwant_responses`, `iwant_response_duplicates`: a message
from a peer it sent IWANT for it within `iwant_followup_time`), the signature
copies it sent into subnets it does not subscribe to (`fanout_sigs_sent`) and the sync
protocol's messages and bytes. The analyzer turns these into
`signature_transport`: deliveries by path and a wire-byte ledger (gossiped and
pulled signatures, coded packets, bitmaps, pull requests, gossipsub control
ids). Byte counts are application-level approximations; QUIC and libp2p framing
are not included. The `nodemap-*-allhosts-sync-{gossip,pull,coded}-sub64`
experiments compare the three on the same network.

Each host also logs a `MeshDegree` event per subscribed subnet, right after
signing and at exit: its gossipsub mesh peers on that subnet. An eager push sends
every signature over every mesh link at least once, and twice when both ends'
copies cross, so duplicates per first copy cannot go below about half the mesh
degree minus one. The analyzer's `mesh` metrics give the degree distribution per
sample, the mesh links (half the sum of degrees at signing), `copies_per_link`
(pushed copies received, without IWANT responses and without the copies
publishers sent in from outside the mesh, per link and signature) and
`one_copy_per_link_duplicates_per_first_copy`, what pushes would leave if no
copies crossed. The summary's transport caption shows them.

#### Bundled propagation (EIP-8334)

`signature_propagation = "bundled"` replaces one gossipsub message per signature
with [EIP-8334](https://github.com/ethereum/EIPs/pull/11905)'s bundled
attestation propagation, as the EIP stood before it moved to waggle: signatures
travel in bundles over gossipsub's partial messages extension, and peers
reconcile by validator index instead of IHAVE/IWANT. The extension is backported
to the vendored gossipsub. A subscription to a partial topic sets `SubOpts`'
`requestsPartial`/`supportsPartial`; a partial message (`RPC.partial`: topic,
group, `partialMessage`, `partsMetadata`) goes to one peer and is never
forwarded by gossipsub; on a partial topic the heartbeat sends no IHAVE to peers
that requested partial messages and hands them to the application as gossip
peers instead. The mesh, fanout and peer selection are gossipsub's own.

- Every `bundle_tick_ms` (EIP: 20 ms), a host pushes each mesh peer the signatures
  it holds and the peer is not known to hold, in bundles of at most
  `bundle_max_signatures` (EIP: 50). A peer is known to hold a signature it sent,
  one it was sent, and one it advertised. A signature a peer delivers while the
  host waits for its tick is never sent back: that is how bundling saves
  duplicates over gossipsub's forward-on-receipt (`pushes_avoided` counts them).
  Ticks fall on a per-host clock with a random phase. A host's own signatures wait
  for its next tick too; one that signs in a subnet it does not subscribe to
  pushes them to fanout peers.
- A peer that was not a push target at the subnet's previous tick (a new mesh
  peer, say) gets everything held then too, as the EIP's set reconciliation
  implies; gossipsub forwards only new messages to a new mesh peer. These go in
  bundles of their own, logged as `via: "backlog"` (`backlog_sigs_sent` counts
  them), so their duplicates show apart from fresh pushes.
- With `bundle_stagger_ms`, the two ends of a mesh link take turns instead of
  both pushing at once (the EIP has no stagger). For each signature a hash of
  the signature and the two peer ids names the end that pushes first; the other
  end pushes only once it has held the signature that long without the peer
  delivering or advertising it (`lazy_sigs_sent` counts those; `pushes_avoided`
  counts the ones the wait saved). A host's own signatures always go out at once.
  Without a stagger most mesh links carry a signature in both directions
  (`copies_per_link` in the `mesh` metrics).
- With `bundle_announce` on top of a stagger, the end that waits also tells the
  peer at once that it holds the signature, in the parts metadata `available`
  list the EIP keeps for gossip peers (`announce_ids_sent`). A peer that hears
  this before it holds the signature never pushes it back; when it gets the
  signature elsewhere it announces in turn, which cancels the waiting end's
  push, so the link carries no copy at all. A peer that still lacks the
  signature requests it like any advertised one, after
  `bundle_request_delay_ms`; the stagger remains as the fallback. A request for
  a signature already pushed to the requester is not served again
  (`requests_already_sent`).
- When gossipsub picks gossip peers, a host advertises to each the signatures it
  holds that the peer is not known to hold and has not been told about (parts
  metadata `available`). The receiver requests what it lacks (`requests`), and the
  advertiser answers with a bundle. A signature requested from one peer is not
  requested from another for `bundle_request_timeout_ms` (`requests_suppressed`);
  the EIP itself would request it again. With `bundle_request_delay_ms`, a host
  waits that long after an advertisement and requests only what has not arrived
  meanwhile (`requests_avoided`); the EIP requests at once.
- The partial-message group is the slot, so every message uses slot 0. The run
  has one slot.

`bundle_tick_ms = 0` pushes each arrival at once, which is gossipsub's
forward-on-receipt with bundle framing: the no-batching control. Bundles require
`signature_sync = "none"`.

What the model leaves out or adds:

- The EIP's shared `AttestationData` is not modelled: every signature keeps its
  full `signature_payload_bytes`, so bundles save duplicates only, not the data
  the EIP deduplicates. Validator indices are 8 bytes, as SSZ `ValidatorIndex`.
- Bundles carry simulator bookkeeping that a real one would not: each
  signature's publishing host (4 bytes) and why the bundle was sent (push,
  backlog or requested; 4 bytes).
- Experiments are homogeneous: no bridging between bundles and full messages.
- Partial messages carry no gossipsub signature and get no peer scoring.

| Key | Default | Meaning |
|---|---|---|
| `signature_propagation` | `"gossipsub"` | `gossipsub` or `bundled` |
| `bundle_tick_ms` | `20` | Push new signatures every this many ms; 0 = at once |
| `bundle_max_signatures` | `50` | Signatures per bundle |
| `bundle_request_timeout_ms` | `1000` | Request a signature from another advertiser after this |
| `bundle_request_delay_ms` | `0` | Wait this long before requesting advertised signatures; 0 = at once |
| `bundle_stagger_ms` | `0` | One end of each link waits this long for the other's copy; 0 = both push at once |
| `bundle_announce` | `false` | The waiting end announces what it holds; needs a stagger |

`TransportStats` adds bundles, the signatures they carried and their bytes,
signatures served on request or pushed as backlog, parts metadata (frames, bytes, indices advertised
and requested), `pushes_avoided`, `lazy_sigs_sent`, `announce_ids_sent`, `requests_already_sent`, `requests_suppressed`, `requests_avoided` and `invalid_partials`.
Byte counts are gossipsub frames (protobuf framing included, QUIC excluded). The
ledger in `signature_transport` gets `bundled_signatures` (every copy received,
signature plus index), `bundle_framing` (the rest of the bundle frames) and
`parts_metadata`. In bundled mode `NodeStats` counts bundle frames sent and
signatures received exactly, not estimated as for gossip. On a traffic-logging
host, bundles out and signatures in are `signature` (`duplicate_signature` for
copies already held), and parts metadata and bundle framing are `sync_control`.
`nodemap-*-allhosts-sync-bundled-sub64` runs the gossip baseline's network with
bundles.

#### Signatures over waggle

`signature_transport = "waggle"` carries subnet signatures over
[waggle](https://github.com/libp2p/specs/pull/732) instead of gossipsub, the
protocol EIP-8334 moved to. Waggle is vendored in `patch/waggle` from
sigp/waggle `3b031d0`, ported to libp2p 0.54. With the default
`signature_transport = "gossipsub"` the waggle behaviour is off and nothing of
it is on the wire.

Waggle only opens streams: a host that subscribes to a topic opens one to every
connected peer, and a peer writes to it what it chooses. There is no mesh, no
forwarding and no heartbeat, so the rest is leansim's:

- A subnet's topic is its gossipsub topic string, and the subnet is one waggle
  object (slot 0, as the partial-message group). A message's `pieces` are a
  signature bundle and its `piecesMetadata` the parts metadata, the same
  encodings as over partial messages, driven by the same state machine. The
  topic is named once per stream, not in every message.
- A host accepts subscriptions to the subnets whose signatures it holds: the ones
  it subscribes to, aggregates or signs in. So a host that only signs in a subnet
  still pushes to its subscribers, as gossipsub's fanout does.
- It pushes a subnet's signatures to `waggle_push_peers` of the subnet's
  subscribers, picked at random when it first pushes and kept until they
  unsubscribe; a free place goes to another subscriber. The pick is one-sided:
  a host may push to a peer that does not push back, and a host no peer picked
  gets nothing by push. 0 pushes to every subscriber.
- With `waggle_push_selection = "hashed"` a host picks push peers per signature
  instead. Every subscriber is a candidate. A hash of the signature and the two
  peer ids, the same at both ends (the one a stagger takes turns by), names the
  end of each link that sends the signature: a host pushes a signature only to
  the subscribers the hash names it the sender for, so no link carries a
  signature both ways, and the other end never pushes it, however long nothing
  comes. Of those subscribers a host pushes to at most `waggle_push_peers`, the
  ones the hash ranks first among those not known to hold the signature; 0
  pushes to all of them. A host sends its own signatures whatever the hash
  says, to at most `waggle_push_peers` subscribers. A subscriber that turns up
  after a signature's peers were picked gets it if the hash names this host the
  sender. About half a host's subscribers are named for a signature, so the cap
  only binds below half of them. There is no stagger
  (`bundle_stagger_ms` must be 0), and `bundle_announce` needs none: the end
  that does not send tells the sender at once that it holds the signature, and
  a sender that lacks it requests it. Hashed selection works with and without
  bundling.
- Every `waggle_gossip_interval_ms` it advertises what it holds to
  `waggle_gossip_peers` of the other subscribers, picked anew each time, which
  request what they lack: the parts metadata exchange of bundled propagation,
  and the only way to a host no peer pushes to. With hashed selection any
  subscriber can be picked, and is told what it was not pushed.
- `waggle_bundled = true` pushes bundles every `bundle_tick_ms`, with every
  `bundle_*` setting of bundled propagation (stagger and announcements
  included). `waggle_bundled = false` sends each signature in a message of its
  own, forwarded on receipt to the push peers not known to hold it: gossipsub's
  forward-on-receipt. It ignores the tick, the bundle cap, the stagger and the
  announcements, and keeps the requests.
- A message that finds the peer's send queue full (`waggle_max_send_queue`
  messages per peer and topic) is not sent. Its signatures are pushed again 20 ms
  later, or advertised again at the next gossip round (`frames_unsent` counts
  the messages turned away).

`signature_propagation` must stay `gossipsub` with waggle, which also requires
`signature_sync = "none"` and no explicit aggregators: both need gossipsub's
mesh. The launcher still connects hosts by `gossipsub_mesh_n` peers per
subscribed subnet.

| Key | Default | Meaning |
|---|---|---|
| `signature_transport` | `"gossipsub"` | `gossipsub` or `waggle` |
| `waggle_bundled` | `true` | Bundles every tick, or one signature per message |
| `waggle_push_peers` | `8` | Subscribers of a subnet a host pushes to; 0 = all. Hashed: per signature |
| `waggle_push_selection` | `"fixed"` | `fixed`: the same push peers for every signature; `hashed`: per signature, by a hash both ends agree on |
| `waggle_gossip_peers` | `6` | Other subscribers a host advertises to each round; 0 = none |
| `waggle_gossip_interval_ms` | heartbeat interval | How often a host advertises |
| `waggle_max_send_queue` | `100` | Messages queued for one peer on one topic |
| `waggle_max_receive_queue` | `100` | Received messages buffered per topic; reading pauses when full |
| `waggle_max_message_bytes` | 64 KiB, or the run's largest message | Largest message on the wire |
| `waggle_max_topic_subscription` | `subnet_count` | Topics a peer may subscribe to on a connection |

The logs and metrics are those of bundled propagation, in both modes:
`SigReceived` names `bundle`, `backlog` or `requested`, `TransportStats` counts
bundles and parts metadata, and `NodeStats` counts frames exactly. Byte counts
are waggle frames (protobuf and its length prefix; QUIC and stream negotiation
excluded). `MeshDegree` logs a host's push peers per subnet, with hashed
selection its subscribers, about half of which a signature goes to. The analyzer counts
a mesh link as two-sided, so with one-sided picks `copies_per_link` reads about
twice the copies per push edge. `pushes_avoided` also counts copies from peers
that push to a host without being its push peers, to which it would not have
pushed anyway, so it is not the tick's saving as it is over gossipsub. `nodemap-small-65k-allhosts-waggle-bundled-sub64`
and `nodemap-small-65k-allhosts-waggle-single-sub64` run the gossip baseline's
network over waggle.

#### Churn

With churn, some hosts crash and rejoin while the run goes on, as the churny
peers of [Lean Gossip](https://ankitku.github.io/stuff/leangossip-debs2026.pdf)
(Kumar and Manolios, DEBS '26). Regular hosts and supernodes have settings of
their own, and neither falls back to the other's:

| Key | Default | Meaning |
|---|---|---|
| `churn_tick_ms` | `100` | How often a churny host may crash or rejoin (both classes) |
| `regular_churn_fraction` | `0.0` | Share of the regular hosts that churn |
| `regular_churn_leave_probability` | `0.01` | Chance per tick that an online churny regular host crashes |
| `regular_churn_rejoin_probability` | `0.05` | Chance per tick that an offline churny regular host rejoins |
| `supernode_churn_fraction` | `0.0` | Share of the supernodes that churn |
| `supernode_churn_leave_probability` | `0.01` | As above, for supernodes |
| `supernode_churn_rejoin_probability` | `0.05` | As above, for supernodes |

The paper's setup is `regular_churn_fraction = 0.2` and
`supernode_churn_fraction = 0.2` with the default probabilities: 10 s sessions
and 2 s gaps on average, so a churny host is online 83% of the time. Setting
only one fraction leaves the other class always online.

- The launcher picks each class's churny hosts (its fraction of the class,
  rounded up) and draws their offline windows tick by tick for the whole run.
  A host starts in the chain's stationary state, so churny hosts are offline at
  the same rate from the first tick as later; a host can start the run offline.
  The windows are in the host's node config (`offline_windows_ms`) and in
  `run-manifest.json`. Hosts come first in a seeded order of their class and
  each host's windows are seeded by its node id, so a larger fraction adds
  churny hosts to those of a smaller one without changing their windows, and
  one class's settings do not move the other's.
- A crash is silent: the host sends nothing, not even a QUIC close. Its peers
  keep their connection, keep it in their mesh and keep sending to it until
  QUIC's idle timeout closes the connection after 10 s (libp2p-quic's default),
  unless the host is back sooner. Requests to a crashed host fail at their
  timeout (`sync_pull_timeout_ms`; 10 s for a proof pull).
- A rejoining host has lost all state but its peer table: the signatures it
  held, its own included, its mesh, what it knew of its peers, and its proofs.
  It dials every peer of its table (its seeds and the hosts that dial it,
  `inbound_peer_addrs`) and enters the network at once: the mesh warmup is a
  stretch of the run, not of each session.
- A peer that still holds its connection to the crashed session would end up
  with an old and a new connection, and gossipsub only greets the first
  connection to a peer, so the rejoined host would never learn the peer's
  subscriptions. So a rejoined host tells every peer it connects to when it came
  back (`/leansim/sigsync/1`, `Restarted`); a peer whose connections to it are
  older drops them all and dials it again. Every host forgets what it knew
  about a peer (signatures held, bitmaps heard) when its last connection to
  that peer closes.
- A host that is offline when it should sign misses the slot: its validators
  never sign. A host that crashes after signing does not sign again.
- What a rejoined host gets back depends on the transport. Gossipsub offers
  only the last few heartbeats of messages (IHAVE). With `signature_sync`, the
  host advertises its empty bitmap to its new mesh neighbours and pulls or is
  repaired. With bundles, every heartbeat a host checks for push targets that
  were not there at its previous tick and pushes them the backlog (without
  churn, bundles only tick when signatures arrive). Gossipsub never delivers a
  host its own messages, so in plain gossipsub a rejoined host does not get its
  own signatures back.
- Churn cannot be combined with `gossipsub_explicit_aggregator_count`: the
  warmup fails if a selected aggregator is offline.

A churny host logs a `Churn` event (`online`, `ts_ms`) whenever it goes offline
or comes back, a `TransportStats` event per session (with `restart_notices_sent`
and `restart_reconnects`), and one `NodeStats` for the run. The summary gets a
Churn section: hosts online at signing, crashes, rejoins and signatures missed
per class, the share of hosts online over the run, how long rejoined hosts took
to hold their subnets' signatures again, and subnet completion for stable and
churny hosts apart. Delivery charts show a class's churny hosts apart from its
stable ones, signatures a host got again after a crash are counted apart from
first copies and duplicates, subnet pages say which aggregators churn, and
traffic pages shade the offline windows. `sweep.py` adds the churn numbers to
`results.csv` as `churn_*` columns. The summary cannot show the bytes sent to
hosts that were offline: senders do not know.

`nodemap-small-65k-allhosts-sync-{gossip,pull,coded,bundled}-churn20-sub64` run
the four signature transports with 20% of the regular hosts churning.

## Output

For an output directory such as `output/`, a run produces:

```text
output/
├── shadow.yaml                 # generated Shadow configuration
├── topology.gml                # generated network graph
├── configs/node_<id>.toml      # one node config per simulated process
├── run-manifest.json           # actual node, validator, country, bandwidth, role, and churn assignments
├── aggregation-plan.json       # recursive groups and each host's proof duties (recursive aggregation only)
├── traffic-<node>.html         # sent/received dashboard per traffic-logging host
├── run-meta.json               # runner, seed, and campaign index
├── shadow.data/hosts/.../*.stdout
├── runs-history.json           # persisted analysis snapshots
└── summary.html                # offline interactive report
```

`run-manifest.json` is the topology source of truth: read it rather than
reconstructing seeded geo, supernode or churn assignments.

## Analysis

`summary.html` is a white, self-contained page (Plotly inlined) for the primary
run. It shows the main settings (signature size and aggregation rate, local
threshold, committees and aggregators, recursive arity, proof time and proof
size, gossipsub mesh), the hosts by class (supernode/regular) with uplink/downlink
rates, validators per host, hosts and validators per country, the subnet
aggregators with their class split, link rates, hosts per number of subnets
aggregated and their countries, the signature
CDF (first seen anywhere and delivered per host class), arrival-time boxes
(p5–p95 whiskers, p25–p75 box, median) for signatures, subnet proofs, every
recursive layer and the final proof per host class with the numbers in a
table, a candle per subnet showing when each of its aggregators finished its
subnet proof (one dot per aggregator), and a preview card per traffic-logging host. Summary times start at the
first signature sent. `scripts/report.py` renders both page types; it has no
web framework or npm dependency.

Clicking a subnet label in that chart opens `subnet-<n>.html`, one white page
per subnet with the same style: the CDF of that subnet's signature deliveries
(first seen anywhere, then per host class), its aggregators (per country,
stacked by supernode/regular, plus a table with each aggregator's country,
class, link rates, validators and subnet-proof time), and its subscribed hosts
broken down by country and host class with the validators they run.

Run the analyzer directly when needed:

```bash
uv run --group analyze python scripts/analyze.py output
uv run --group analyze python scripts/analyze.py output --serve --port 4321
uv run --group analyze python scripts/analyze.py --self-test
```

## Parameter sweeps

`sweep.py` creates one temporary experiment TOML per point and delegates each
run to `shadow-sim.py`. It writes each run beneath the selected output root and
collects the snapshots into `results.csv`.

```bash
uv run sweep.py experiments/nodemap-small-65k-committees-sub64.toml \
  --param signature_payload_bytes=1024,3072,8192 \
  --param network_defaults.uplink_mbps=25,50 \
  --output sweep-output
```

## Development

```bash
cargo fmt --check
cargo test
uv run shadow-sim.py experiments/nodemap-small-65k-committees-sub64.toml --dry-run
uv run --group analyze python scripts/analyze.py --self-test
```
