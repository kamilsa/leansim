#!/usr/bin/env python3
"""Draw a smaller node map from nodes.csv that keeps the all-hosts mix of hosts.

The default sampling in shadow-sim.py (all_hosts = false) keeps the hosts that
received a validator, which favours big operators: on the 32k network about half
of the 3,713 hosts are supernodes, against 18% in nodes.csv as a whole. This
script instead picks `--hosts` rows from nodes.csv at random, stratified so that
the three kinds of host keep their nodes.csv shares:

  - supernodes: validator_count >= --supernode-threshold (as supernode_by_validator_count)
  - small validator hosts: 1 <= validator_count < threshold
  - no_validator hosts (and validator rows with validator_count 0)

Run the result with all_hosts = true: every sampled host joins, validators are
drawn from the sampled hosts' slots, and hosts that get none relay.

    python3 scripts/sample_node_map.py --hosts 3713 --seed 1 -o nodes_3713_mix.csv
"""

import argparse
import csv
import random
import sys

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", default="nodes.csv")
    parser.add_argument("--hosts", type=int, default=3713)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--supernode-threshold", type=int, default=10)
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    csv.field_size_limit(sys.maxsize)
    with open(args.input, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        rows = list(reader)

    def kind(row):
        slots = 0 if (row["node_type"] or "").strip() == "no_validator" else int(row["validator_count"])
        if slots >= args.supernode_threshold:
            return "supernode"
        return "small" if slots > 0 else "none"

    strata = {"supernode": [], "small": [], "none": []}
    for index, row in enumerate(rows):
        strata[kind(row)].append(index)
    total = len(rows)
    if args.hosts > total:
        sys.exit(f"--hosts {args.hosts} exceeds the {total} rows of {args.input}")

    # Proportional allocation, largest remainder.
    exact = {name: args.hosts * len(members) / total for name, members in strata.items()}
    counts = {name: int(value) for name, value in exact.items()}
    for name in sorted(exact, key=lambda n: exact[n] - counts[n], reverse=True)[: args.hosts - sum(counts.values())]:
        counts[name] += 1

    rng = random.Random(args.seed)
    picked = set()
    for name in ("supernode", "small", "none"):
        picked.update(rng.sample(strata[name], counts[name]))

    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for index, row in enumerate(rows):
            if index in picked:
                writer.writerow(row)

    shares = ", ".join(f"{name} {counts[name]} ({counts[name] / args.hosts:.1%}, nodes.csv {len(strata[name]) / total:.1%})"
                       for name in ("supernode", "small", "none"))
    print(f"{args.output}: {args.hosts} of {total} hosts, seed {args.seed}: {shares}")

if __name__ == "__main__":
    main()
