# Evaluation

Everything needed to produce the numbers in the paper. Run it on the
experiment machine (the author's Mac or a VM), never in a cloud sandbox, and
commit the result folders.

## Files

| File | What it does |
| --- | --- |
| `run_experiment.py` | Starts the authorization server and both gateways, runs each mode through the same fault timeline, saves results |
| `loadgen.py` | Open-loop load generator: fixed request rate, every request signed, latency measured from the scheduled send time |
| `run_matrix.py` | Runs the whole plan below (resumable: finished runs are skipped); `--dry-run` lists runs and time |
| `find_max_rate.py` | Capacity ramp: `baseline` at rising rates until neither gateway keeps up on schedule (runs `capacity-<rate>`) |
| `aggregate.py` | Checks every matrix run against the gen-lag rule and writes median/min/max tables (CSV + LaTeX) to `tables/` (gitignored) |
| `plot.py` | Generates the paper's figures from the result folders into `figures/` (gitignored; re-run to rebuild) |
| `results/` | One folder per run: `offline.csv.gz`, `online.csv.gz` (one row per request, gzipped; older runs plain `.csv`), `summary.json`, `meta.json` (machine, versions, arguments), process logs (gitignored) |

## Running

```bash
source .venv/bin/activate          # from the repository root
python evaluation/run_experiment.py --scenario error --rate 200 --duration 60
```

Default timeline: 60 s of load, fault from second 20 to second 40, first 5 s
excluded as warm-up. Each mode runs separately so they never compete for CPU.

Figures: `python evaluation/plot.py` builds every figure the results allow
(outage success rate over time per fault scenario, latency CDF, revocation
lag vs. refresh interval / cache TTL) as PDF and PNG.

Before trusting a run, check `gen lag p99` in the output. If the generator
sends requests more than a few milliseconds late, it is the bottleneck at that
rate: lower `--rate`.

## Scenarios

| Scenario | What happens to the authorization server | Flags |
| --- | --- | --- |
| `baseline` | nothing; steady-state cost of each mode | |
| `slow` | adds latency to every answer | `--delay-ms`, `--jitter-ms` |
| `error` | answers 503 immediately (crashed but reachable) | |
| `hang` | holds requests without answering (black hole) | |
| `freeze` | process stopped with SIGSTOP (unresponsive host) | |
| `flapping` | alternates healthy and failing | `--flap-period`, `--flap-down` |
| `revoke` | token revoked at `--fault-at`; measures time to first refusal | `--refresh-seconds` |

Gateway options that are part of the design space:

| Flag | Mode | Meaning |
| --- | --- | --- |
| `--refresh-seconds` | offline | how often the revocation list is fetched (default 5) |
| `--max-staleness` | offline | fail closed once the list is this old (default: never) |
| `--timeout` | online | deadline for one introspection call (default 2 s) |
| `--cache-ttl` | online | reuse positive introspection answers for this long (default 0) |

## Experiment plan for the paper

Each configuration is repeated 5 times; the paper reports the median run and
the spread.

1. **Steady-state cost.** `baseline` at 50, 100, 200, 400 req/s. Metric:
   authorization time (`authz_ms`) and end-to-end latency, p50/p95/p99.
   Run twice: on the idle host (`baseline`) and with the host kept busy
   (`baseline-warm`, `--keep-warm 4`); see "Low-load latency tail" below.
2. **Slow authorization server.** `slow` with 10, 50, 200 ms added. Expected:
   online latency grows by the delay, offline does not change.
3. **Outage.** `error`, `hang` and `freeze`, 20 s each. Metric: success rate
   and time to fail during the fault, and recovery time after it.
   Also online with cache TTL 5 s and 30 s (`outage-cached`, online only,
   random fault start within one TTL).
4. **Flapping.** period 4 s, 50% down. Metric: success rate.
5. **Revocation lag (the cost of offline).** `revoke` with offline refresh
   1, 5, 30 s, and online with cache TTL 0, 5, 30 s. Metric: seconds from
   revocation to first refusal; 20 repetitions each, since lag is uniform
   over the refresh interval. Each run revokes at a random point of one
   interval (see `docs/DECISIONS.md`).
6. **Delegation depth.** `spike/bench.py`: verification cost and token size
   for 0–10 hops (done: `results/spike_depth.csv`). End to end through the
   gateway: group `delegation`, `--chain-depth` 0, 1, 2, 3, 5, both modes,
   200 req/s, host kept busy.

Together, 3 and 5 are the paper's core trade-off: offline keeps serving
through outages, at the price of revocation lag bounded by the refresh
interval. Online with a cache moves along the same curve, so the comparison
shows where each design sits on it.

## Low-load latency tail (host idle effect)

In the `baseline` matrix, end-to-end latency falls as the rate rises, for
both modes (pooled over the 5 runs, steady phase, ms):

| rate | offline p50 / p99 | online p50 / p99 |
|-----:|------------------:|-----------------:|
|   50 | 6.36 / 10.32      | 6.60 / 9.01      |
|  100 | 4.73 / 7.40       | 4.70 / 7.56      |
|  200 | 2.45 / 6.31       | 2.79 / 3.75      |
|  400 | 1.85 / 2.52       | 2.02 / 3.77      |

At 200 req/s offline has a second latency mode at 4–6.5 ms (about 7% of
requests), although its `authz_ms` stays under 1 ms. The extra time is
outside the authorization step. It is not the revocation-list refresh: the
slow requests are spread evenly over the 5 s refresh cycle and over the run.
It is not the order of the modes either (`p99-swap-200`, online first:
offline p99 4.9 ms, online 4.3 ms).

It is the host going idle between requests. With four busy-loop processes
(`python -c "while 1: pass"`) running in the background, the tail disappears
and offline is faster at every percentile (same sitting, 200 req/s):

| run            | offline p50 / p99 | online p50 / p99 |
|----------------|------------------:|-----------------:|
| `p99-ctrl-200` | 2.41 / 6.57       | (not run)        |
| `p99-warm-200` | 1.63 / 2.47       | 2.35 / 2.96      |

The offline stack does less work per request (no call to the authorization
server), so at 200 req/s the cores are idle more often and more requests pay
a wake-up penalty (CPU idle states / frequency scaling on Apple Silicon). At
50 req/s both stacks are idle enough that nearly every request pays it; at
400 req/s neither does. The end-to-end tail at low rates is therefore a
property of the host, not of the authorization design. `p99-warm-200` has
no flag in `meta.json` for the background load; this section is its record.
Later runs record it as `keep_warm` (matrix group `baseline-warm`).

`baseline-warm` matrix (5 runs each, median, ms): offline authz p50 is
0.19–0.20 and online 1.06–1.12 at every rate; at 200 req/s end-to-end p50/p99
is 1.52/1.77 offline vs 2.32/2.88 online. Table: `evaluation/tables/latency.tex`.

## Outage with the online introspection cache

Matrix group `outage-cached` (30 runs, 2026-10-17): the online gateway with
cache TTL T = 5 s and 30 s through `error`, `hang` and `freeze` at
200 req/s, online only (offline does not use the cache; its `outage` runs
stand). The 20 s fault starts at a random point of one TTL; see
`docs/DECISIONS.md` for why, and for what the cache does when an entry
expires mid-outage (dropped, then 503 until the server is back).

Success during the fault, median of 5 runs (min–max):

| fault  | offline | online T=0 | online T=5 s     | online T=30 s     |
|--------|--------:|-----------:|-----------------:|------------------:|
| error  | 100     | 0.3        | 15.8 (7.4–25.2)  | 92.8 (32.2–100)   |
| hang   | 100     | 5.0        | 18.9 (17.0–29.2) | 66.3 (29.7–100)   |
| freeze | 100     | 0.1        | 7.0 (1.5–21.7)   | 100 (11.7–100)    |

The cache serves only until its entry reaches the TTL, then the gateway
fails closed for the rest of the fault, as without a cache: refusals take
about 3 ms for `error` and `freeze` and the full 2 s deadline for `hang`. So
the share served is the remaining cache lifetime over the fault length.
With T = 5 s it is a few seconds out of 20; with T = 30 s it ranges from a
third of the fault to all of it, depending on the entry's age when the
fault starts. Recovery is immediate in every run (no refused request after
the fault ends). A cache therefore helps online only for outages shorter
than its TTL, and buys that with up to T seconds of revocation lag (`revoke`
runs). The offline gateway served 100% in every run with a 5 s refresh
interval, because it keeps its last good revocation list for the whole
outage. Figure: `outage_cached_error` (success over time from the fault
start, runs pooled; the 20-point steps of the T = 30 s curve are the five
runs losing their entry one by one). Table: `outage.tex`.

`matrix-hang-ttl30-r2` broke the gen-lag rule on its first try (19 ms
during the fault) and was re-run.

## Delegation depth through the gateway

Matrix group `delegation` (25 runs, 2026-10-17): the load is sent by the last
agent of a chain of N hops, 200 req/s, host kept busy. Median of 5 runs, ms:

| depth | offline authz p50 | offline p50 / p99 | online authz p50 | online p50 / p99 | offline token |
|------:|------------------:|------------------:|-----------------:|-----------------:|--------------:|
| 0     | 0.19              | 1.54 / 2.07       | 1.10             | 2.37 / 4.13      | 544 B         |
| 1     | 0.28              | 1.62 / 2.16       | 1.07             | 2.31 / 2.71      | 1024 B        |
| 2     | 0.37              | 2.03 / 2.26       | 1.06             | 2.58 / 2.88      | 1500 B        |
| 3     | 0.46              | 1.78 / 2.01       | 1.05             | 2.30 / 2.87      | 1980 B        |
| 5     | 0.63              | 1.95 / 2.47       | 1.07             | 2.31 / 2.68      | 2936 B        |

Offline authorization grows linearly, by about 0.09 ms per hop (one more
signature to verify and one more block to query), and is still below online
at depth 5. Online stays flat at about 1.07 ms: the server walks the chain
in memory, and the round trip dominates. The online token stays 43 bytes;
the offline token grows by about 480 bytes per hop. End-to-end latency is
within noise across depths for both modes; offline stays lower at every
depth. Online p99 at depth 0 is noisy across runs (3.1–13.0 ms). The price
of offline delegation that does not show here is the work done once per
hop: online needs one exchange with the server per hop, offline none.
Figure: `delegation_depth`. Table: `delegation.tex`.

## Agent tasks: delegating during the fault

Matrix group `tasks` (40 runs, 2026-10-24; design in
`docs/delegation-outage-design.md`).
The `delegation` group above builds every chain before the load starts; here
the agent delegates *while* the server is failing. Each task (`--workload
tasks`, 40 tasks/s = 200 req/s) gives a fresh sub-agent a token with
`max_amount` lowered by one, then the sub-agent sends 5 requests. Offline
delegation is a local Biscuit block; online it is an RFC 8693 exchange with
a 2 s deadline. Fault 20–40 s; median of 5 runs; tasks done and delegated
are the share of tasks started during the fault, latencies are from before
it:

| fault    | mode           | tasks done | delegated | delegation p50 | task p50 |
|----------|----------------|-----------:|----------:|---------------:|---------:|
| baseline | offline        | 100%       | 100%      | 0.31 ms        | 9.85 ms  |
| baseline | online, T = 0  | 100%       | 100%      | 1.09 ms        | 12.32 ms |
| baseline | online, T = 30 s | 100%     | 100%      | 1.27 ms        | 9.01 ms  |
| error    | offline        | 100%       | 100%      | 0.33 ms        | 8.71 ms  |
| error    | online, T = 0  | 0.4%       | 0.4%      | 1.21 ms        | 11.72 ms |
| error    | online, T = 30 s | 0.3%     | 0.3%      | 1.28 ms        | 8.80 ms  |
| hang     | offline        | 100%       | 100%      | 0.33 ms        | 8.90 ms  |
| hang     | online, T = 0  | 0.3%       | 0.3%      | 1.19 ms        | 11.67 ms |
| hang     | online, T = 30 s | 0.3%     | 0.3%      | 1.50 ms        | 9.24 ms  |
| freeze   | offline        | 100%       | 100%      | 0.33 ms        | 8.86 ms  |
| freeze   | online, T = 0  | 0.3%       | 0.3%      | 1.22 ms        | 11.62 ms |
| freeze   | online, T = 30 s | 0.3%     | 0.3%      | 1.41 ms        | 8.72 ms  |

Offline agents kept delegating and working through every fault. Online,
every task that failed during the fault failed at delegation, before
sending a request (`error`: `exchange_503`; `hang`: `exchange_timeout`;
`freeze`: mostly `ConnectError`, the rest `exchange_timeout`). The few
online successes are tasks scheduled at the phase edge (20.0 and 20.025 s),
before the fault took effect. The introspection cache does not help:
a sub-agent's token is new, so the server must be reached to create it. The
cache only shortens the task once the token exists (requests 2–5 hit it:
task p50 8.8 vs 11.7 ms), the same as offline. Online recovers right after the
fault (99.4–99.8% of tasks in `after`). Offline delegation costs about
0.3 ms against 1.1–1.5 ms for the exchange. Table: `tasks.tex`.

## Capacity: highest sustainable rate

`python evaluation/find_max_rate.py --rates 400,600,800,1000,1200,1500,2000,3000`
(2026-10-24, Mac on AC power, one 30 s `baseline` run per rate and mode, runs
`capacity-<rate>`). A mode counts at a rate only if the generator kept its
schedule in it (gen lag p99 ≤ 5 ms) and the gateway answered ≥ 99.9% with p50
≤ 10 ms.

| rate | offline ok / p50 / p99 | online ok / p50 / p99 |
|-----:|-----------------------:|----------------------:|
| 400  | 100% / 1.79 / 2.44 ms  | 100% / 1.93 / 2.84 ms |
| 600  | 100% / 1.32 / 1.79 ms  | 100% / 1.46 / 3.51 ms |
| 800  | 100% / 1.01 / 1.12 ms  | 100% / 1.71 / 2.09 ms |
| 1000 | 100% / 0.82 / 0.90 ms  | 100% / 1.55 / 2.71 ms |
| 1200 | 100% / 0.84 / 1.55 ms  | 100% / 2.19 / 12.7 ms |
| 1500 | 100% / 1.15 / 1.30 ms  | 52% (collapsed)       |
| 2000 | 100% / 0.97 / 2.55 ms  | 39% (collapsed)       |
| 3000 | generator falls behind (lag 165 ms) | collapsed |

The generator sustains 2000 req/s. The offline gateway keeps up to that
limit; where it would fail on its own is not measurable here. The online
gateway keeps up to 1200 req/s and collapses at 1500: its single process runs
out of CPU (the authorization server stays at about 25%), because every request
also makes an outbound HTTP call (about +0.2 ms of gateway CPU per request
at 400 req/s: 34% vs 26% of a core). Once behind, it does not recover at the
same load. All rates in the experiment plan (≤ 400 req/s) are far below
both limits. Around the online limit, 1200 and 1500 req/s were repeated
twice more (`capacity-<rate>-r2`, `-r3`, `run_experiment.py --scenario
baseline --rate <rate> --duration 30`): online held 1200 in 3 of 3 runs (p99
4.7–12.7 ms) and collapsed at 1500 in 3 of 3 (21–64% served); offline held
both in every run. Other rates ran once.
Offline p50 falling with rate is the host idle effect described above.

The first ramp found the online gateway collapsing at 600 req/s. That was
httpcore pool bookkeeping, not online authorization; it was removed by
splitting the gateway's HTTP client into small pools (DECISIONS, Gateway)
before these runs. `capacity-1500-r3` offline has one refused request: a
host stall pushed Datalog evaluation past biscuit's 1 ms limit; fixed
afterwards (DECISIONS, Token design).

## Sandbox sanity check (not for the paper)

A 10-second smoke run of each scenario in the development sandbox (100
req/s) confirmed the harness works: offline served 100% through `error` and
`freeze`; online fell to about 1–3% during the fault, and after `freeze` it
needed time to drain stuck connections. Offline revocation lag was 1.5 s with
a 2 s refresh; online was immediate.
