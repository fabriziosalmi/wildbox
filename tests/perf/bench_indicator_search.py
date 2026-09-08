#!/usr/bin/env python3
"""
Indicator-search latency baseline.

Nothing in this repository was ever measured: no benchmark, no load test, no
profiling, no timing assertion, so every performance property was unverified --
including the ones the documentation states (WILDBO-PERF-03).

This is the first repeatable measurement, and it targets the one cost that grows
with something the operator does not control: the free-text indicator search runs
three leading-wildcard ILIKE comparisons, which no B-tree index can serve, over a
table the collectors grow continuously (WILDBO-PERF-02). Alembic revision
0004_trgm adds pg_trgm GIN indexes; this script is how you tell whether they
help, and by how much.

Usage:
    python tests/perf/bench_indicator_search.py                  # against a running stack
    python tests/perf/bench_indicator_search.py --report out.json
    python tests/perf/bench_indicator_search.py --rows 100000    # seed first
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from typing import Dict, List

import requests

DEFAULT_BASE = os.getenv("DATA_SERVICE_URL", "http://localhost:8002")
QUERIES = ["evil", "malware", "8.8.8.8", "example.com", "d41d8cd9", "zzz-no-match-zzz"]


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - int(k))


def bench(base_url: str, iterations: int, headers: Dict[str, str]) -> Dict:
    results = {}
    for q in QUERIES:
        timings: List[float] = []
        errors = 0
        for _ in range(iterations):
            start = time.perf_counter()
            try:
                resp = requests.get(
                    f"{base_url.rstrip('/')}/api/v1/indicators/search",
                    params={"q": q, "limit": 50},
                    headers=headers,
                    timeout=30,
                )
                if resp.status_code >= 400:
                    errors += 1
            except requests.RequestException:
                errors += 1
                continue
            timings.append((time.perf_counter() - start) * 1000)
        results[q] = {
            "samples": len(timings),
            "errors": errors,
            "mean_ms": round(statistics.fmean(timings), 2) if timings else None,
            "p50_ms": round(_percentile(timings, 0.50), 2) if timings else None,
            "p95_ms": round(_percentile(timings, 0.95), 2) if timings else None,
            "max_ms": round(max(timings), 2) if timings else None,
        }
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--report", help="write JSON results here")
    parser.add_argument(
        "--fail-over-ms",
        type=float,
        default=None,
        help="exit non-zero if any query's p95 exceeds this (turns the baseline into a gate)",
    )
    args = parser.parse_args()

    headers = {}
    if os.getenv("TEST_API_KEY"):
        headers["X-API-Key"] = os.environ["TEST_API_KEY"]

    print(f"Benchmarking {args.base_url} ({args.iterations} iterations per query)\n")
    results = bench(args.base_url, args.iterations, headers)

    print(f"{'query':<22} {'p50 ms':>9} {'p95 ms':>9} {'max ms':>9} {'errors':>7}")
    print("-" * 60)
    worst = 0.0
    for q, r in results.items():
        print(
            f"{q:<22} {str(r['p50_ms']):>9} {str(r['p95_ms']):>9} "
            f"{str(r['max_ms']):>9} {r['errors']:>7}"
        )
        if r["p95_ms"]:
            worst = max(worst, r["p95_ms"])

    payload = {
        "base_url": args.base_url,
        "iterations": args.iterations,
        "timestamp": time.time(),
        "results": results,
        "worst_p95_ms": worst,
    }
    if args.report:
        with open(args.report, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nWrote {args.report}")

    if args.fail_over_ms is not None and worst > args.fail_over_ms:
        print(
            f"\nFAIL: worst p95 {worst}ms exceeds {args.fail_over_ms}ms",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
