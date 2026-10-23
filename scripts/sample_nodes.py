#!/usr/bin/env python3
"""Create a downsampled copy of a nodes.csv node map.

Keeps the validators-per-node distribution via stratified sampling: common
validator counts form their own strata, rare counts are grouped into
power-of-two buckets so the heavy tail is still represented, and every
stratum contributes a proportional share of the output rows (largest-remainder
rounding). Rows are sampled with a fixed seed and written in input order with
all original columns untouched.
"""

import argparse
import csv
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Summary-table buckets: (label, inclusive lower bound, inclusive upper bound).
SUMMARY_BUCKETS = [
    ("0", 0, 0), ("1", 1, 1), ("2-4", 2, 4), ("5-8", 5, 8), ("9-16", 9, 16),
    ("17-32", 17, 32), ("33-64", 33, 64), ("65-128", 65, 128),
    ("129-256", 129, 256), ("257-512", 257, 512), ("513-1024", 513, 1024),
    ("1025-2048", 1025, 2048), ("2049-4096", 2049, 4096),
    ("4097-8192", 4097, 8192), ("8193-16384", 8193, 16384),
    (">16384", 16385, float("inf")),
]


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=Path("nodes.csv"))
    parser.add_argument("--output", type=Path, default=Path("nodes_small.csv"))
    parser.add_argument("--factor", type=int, default=10,
                        help="downsampling factor; the output keeps ~1/factor of the nodes")
    parser.add_argument("--seed", type=int, default=42,
                        help="seed for sampling within strata")
    return parser.parse_args()


def stratum_key(count, frequency, factor):
    """Stratum for one node: exact validator count while common enough that it
    still expects >= 1 sampled node, otherwise a power-of-two count bucket."""
    if count == 0 or frequency >= factor:
        return ("count", count)
    return ("bucket", count.bit_length())  # bucket k covers [2^(k-1), 2^k)


def allocate(sizes, target):
    """Proportional stratum sizes summing exactly to target (largest remainder)."""
    total = sum(sizes.values())
    raw = {key: size * target / total for key, size in sizes.items()}
    alloc = {key: int(value) for key, value in raw.items()}
    remaining = target - sum(alloc.values())
    # Largest fractional remainder first; bigger strata win ties, key breaks them.
    order = sorted(sizes, key=lambda key: (alloc[key] - raw[key], -sizes[key], str(key)))
    for key in order:
        if remaining <= 0:
            break
        if alloc[key] < sizes[key]:
            alloc[key] += 1
            remaining -= 1
    if remaining:
        sys.exit(f"cannot allocate {remaining} more nodes; target too large?")
    return alloc


def summarize(label, counts):
    total = len(counts)
    validators = sum(counts)
    print(f"{label}: {total} nodes, {validators} validators "
          f"(mean {validators / total:.2f}/node, max {max(counts)})")
    for name, low, high in SUMMARY_BUCKETS:
        n = sum(1 for c in counts if low <= c <= high)
        if n:
            print(f"  {name:>10} {n:>7} ({100 * n / total:5.2f}%)")


def main():
    args = parse_args()
    csv.field_size_limit(sys.maxsize)  # validator_indices lists exceed the 128 KiB default
    with args.input.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    header, data = rows[0], rows[1:]
    try:
        count_col = header.index("validator_count")
    except ValueError:
        sys.exit(f"{args.input} has no validator_count column")

    try:
        counts = [int(row[count_col]) for row in data]
    except (IndexError, ValueError) as error:
        sys.exit(f"{args.input}: bad validator_count value: {error}")

    frequency = Counter(counts)
    strata = defaultdict(list)
    for index, count in enumerate(counts):
        strata[stratum_key(count, frequency[count], args.factor)].append(index)

    target = round(len(data) / args.factor)
    alloc = allocate({key: len(rows_) for key, rows_ in strata.items()}, target)

    rng = random.Random(args.seed)
    picked = []
    for key in sorted(strata):
        if alloc[key]:
            picked.extend(rng.sample(strata[key], alloc[key]))
    picked.sort()  # keep the input ordering

    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)  # QUOTE_MINIMAL, CRLF: matches the source file
        writer.writerow(header)
        writer.writerows(data[i] for i in picked)

    print(f"{args.input} -> {args.output} (1/{args.factor}, seed {args.seed})")
    summarize("original", counts)
    summarize("sampled", [counts[i] for i in picked])
    print(f"strata: {len(strata)} "
          f"({sum(1 for k in strata if k[0] == 'count')} exact counts, "
          f"{sum(1 for k in strata if k[0] == 'bucket')} tail buckets)")


if __name__ == "__main__":
    main()
