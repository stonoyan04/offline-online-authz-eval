# Decision log

Why the project is built the way it is. Read this before changing the design;
add an entry when a decision changes. Newest decisions go at the bottom of
each section.

## Scope and goals

- **Contribution.** The project compares *offline* authorization (Biscuit
  tokens verified locally at a gateway) with *online* authorization (the
  gateway asks the authorization server on every request, OAuth 2.0 token
  introspection, RFC 7662). Offline verification alone is not new (JWTs with
  cached keys already do it). The differentiators are: **delegation to
  sub-agents needs no server** (online needs RFC 8693 token exchange), and
  **the gateway survives authorization-server failure**. The cost is
  **revocation lag**, bounded by the revocation-list refresh interval.
- **Fair baseline.** Online mode uses introspection + token exchange, and has
  an optional introspection cache. A plain API key would be a straw man.
- **Scope.** The experiments cover what the offline-vs-online comparison
  needs; extras (Permission Manager UI, AgentDojo, detection layer) come
  later.
- **Delegation under outage (2026-10-24).** Sub-agent delegation during
  the fault is measured as a separate matrix group
  (`docs/delegation-outage-design.md`). The paper's harness (`loadgen.py`,
  the matrix groups, the tables) is not changed by this work, so earlier
  runs stay comparable.

## Language and tooling

- **Python 3.11+ for everything.** Earlier plans
  mentioned a Go proxy; `biscuit-go` lags the Rust core, so Go was dropped. A
  Rust gateway may come later, only if asked.
- **One installable package `agentauthz`** (flat layout, `pip install -e
  ".[dev]"`), so both gateway modes, the server and the experiments share
  one implementation.
- **FastAPI / Starlette, pure ASGI middleware** (not `BaseHTTPMiddleware`)
  to keep gateway overhead minimal and identical in both modes.

## Token design (agentauthz/delegation.py)

- **Biscuit v3 via `biscuit-python` 0.4.0.** Key loading needs an explicit
  `Algorithm.Ed25519` argument in this version.
- **Proof of possession + attenuation conflict, and its fix.** A root block
  saying "holder = parent key" cannot be overridden by a sub-agent block,
  because blocks only add restrictions. Fix: the holder is named by
  `holder(...)` in the authority block, and each delegation is a
  *third-party block signed by the current holder* containing
  `delegate(<next key>)`. The verifier walks the chain in code, because a
  Datalog rule can only trust keys written into the rule text.
- **Linear chain, last holder only.** A parent cannot use its sub-agent's
  token. Exactly one `delegate` per delegation block.
- **First-party blocks** may add checks but never `delegate` facts.
- **`expires(...)` facts** sit next to each expiry check, only so the
  verifier can report "expired" (401) instead of "not permitted" (403), the
  same as online mode. The checks enforce expiry; facts are read only from
  trusted blocks.
- **Revocation by ID.** Revoking a token adds its *last* block's revocation
  ID: that token and everything derived from it die, its parent does not.
- **Datalog time limit 10 ms, and a limit hit is `401`, not `403`.**
  biscuit's default wall-clock limit is 1 ms. In `capacity-1500-r3` one
  valid request took 1.6 ms (a host stall) and was refused as
  `insufficient_scope`: the limit error is the same `AuthorizationError` as a
  policy refusal, and `verify` did not tell them apart. A limit hit in the
  holder queries escaped `verify` altogether. Now both are reported as
  "authorizer limits exceeded" (the token could not be evaluated), and the
  time budget is 10 ms: still a bound on a costly attenuation block, but
  above scheduling jitter. Facts and iterations keep biscuit's deterministic
  limits. Across all runs the limit fired three times: this refusal, and two
  500s in `matrix-revoke-refresh30-ttl30` (r3 at 22.2 s, before the
  revocation; r10 at 47.9 s, after it). Revocation lag counts only 401s, so
  both lags are correct and the matrix results stand. Since a limit hit is
  now a 401, a revoke run could in principle count one as the revocation
  taking effect; at 10 ms that should be rare, and `summary.json` error
  counts would show it.

## Request signatures (agentauthz/pop.py)

- **Simplified stand-in for RFC 9421**, the same in both modes. The signature
  covers method, request target, body digest, **token digest** (a signature
  cannot be reused with another token), timestamp and nonce.
- **No server-issued nonce.** A 30-second window plus a replay cache keeps
  verification local (a server nonce would add a round trip and contradict
  "offline").
- **Sign the request target as sent on the wire** (percent-encoded). The
  gateway uses ASGI `raw_path`. Found as a real bug with non-ASCII queries
  like `?to=Երևան`.
- Replay cache **fails closed** when full of live entries.

## Gateway (agentauthz/gateway/)

- **Default deny**: unmapped routes get 403; only `/healthz` is public.
- **Online deadline uses `asyncio.wait_for`**, not httpx timeouts (those are
  per phase, and do not apply to in-process transports). Same for the
  offline revocation refresh.
- **Online fails closed** (503) when the server is unreachable, as OAuth
  deployments do.
- **Online bounds outstanding introspection calls** to the HTTP pool size
  (`max_in_flight`, 200); extra calls wait on a semaphore under the same
  deadline. Without it, the first matrix run showed the online gateway at
  100% CPU and unreachable (even `/healthz`) during `hang`, and still down
  20 s after the fault ended. Profiling: httpcore's
  `_assign_requests_to_connections` rescans every queued request against
  every connection on each pool event, so thousands of queued calls are
  quadratic. That was an implementation artefact, not a property of online
  authorization, and it would have made the baseline look worse than it is.
- **The gateway's HTTP client is 8 pools of 25 connections, used
  round-robin** (`agentauthz/gateway/http.py`, both modes), not one pool of
  200. The capacity ramp (2026-10-24) found the online gateway collapsing
  for good at 600–800 req/s while the authorization server sat at 10% CPU.
  Profile under collapse: 60% of the gateway's CPU in httpcore's
  `_assign_requests_to_connections`, which walks and `poll`s every
  connection of the pool on each event; one stall leaves ~100 idle
  connections, the cost per request rises, and the backlog never drains.
  Same total limit (200) and `max_in_flight`, so outage behaviour is
  unchanged; with small pools the online gateway holds 1000 req/s at 63%
  CPU. Another implementation artefact, removed for the same reason.
  Matrix runs made before it stay valid: a check at 200 req/s (`hang`,
  `freeze`, `error`, `baseline`) gave the same success rates during and
  after each fault and the same recovery; only online p99 in the 20 s
  after `hang` dropped (15 ms vs 69–149 ms), which the paper does not
  report.
- **`sniffio` is a dependency.** httpcore imports it on every lock it
  creates; anyio 4 no longer pulls it in, and each failed import walked
  `sys.path` (about 10% of the online gateway's CPU under load).
- **Offline `max_staleness`**: unset = keep serving with an old revocation
  list (availability first); set = fail closed once the list is too old.
- **Revocation list rollback protection**: never accept a lower
  `(seq, issued_at)`.
- **`Server-Timing: authz;dur=<ms>`** on every response, so experiments
  separate authorization cost from the service's work.

## Authorization server (agentauthz/authz_server/)

- **Two roles in one process**: online baseline (introspection, exchange,
  RFC 7009 revocation) and offline issuer (Biscuit grants, signed revocation
  list).
- **In-memory, single worker.** Enough for the experiments and the fastest an
  online check can be, which is fair to the baseline.
- **Fault injection** (`slow`, `error`, `hang`, `flapping`) hits only the
  endpoints gateways depend on, never admin or health endpoints.

## Experiments (evaluation/)

- **Open-loop load generator in Python.** k6 cannot easily produce the Ed25519
  signatures. Open loop + latency measured from the *scheduled* send time
  avoids coordinated omission (a stalled server must not slow the generator
  and hide its own slowness). Check `gen lag p99` stays at a few ms.
- **The generator uses many small connection pools** (64 connections per
  httpx client, round-robin) instead of one pool of 2000, for the same
  httpcore reason: one large pool stalled the generator by seconds after a
  `hang` and during `freeze` (gen lag p99 up to 7 s).
- **Each run records the git commit** (`meta.json`), so runs made before and
  after a fix can be told apart. Matrix runs of `hang` and `freeze` from
  before commit "Fix httpx pool stalls in online gateway and load generator"
  are invalid and were re-run.
- **Modes run one after the other**, never concurrently, so they do not
  compete for CPU.
- **`freeze` uses SIGSTOP/SIGCONT** (unresponsive host, no state loss). A real
  kill + restart would lose the in-memory grants.
- **Numbers for the paper come only from the author's machine or a VM**, never
  from a cloud sandbox. Every result folder records hardware and versions.
- **Revocation time is randomized per run** (`run_matrix.py`: `fault_at` =
  20 s + uniform(0, interval), seeded by the run id). The online cache fills
  at the first request and the offline refresh timer starts with the
  process, so with a fixed `fault_at` every repetition hits the same phase
  of the period. Found in a smoke run: cache TTL 5 s gave 0.007 s lag,
  because 20 s is a multiple of 5 s. Lag must be sampled over the interval.
- **Steady-state latency is also measured with the host kept busy**
  (`--keep-warm 4`, matrix group `baseline-warm`). On the idle Mac, requests
  often pay a CPU wake-up penalty, and the lighter offline stack pays it more
  often, which made its end-to-end p99 look worse than online's at 200 req/s
  (see "Low-load latency tail" in `evaluation/README.md`). The spinners keep
  the cores awake so the comparison measures the gateways. The plain
  `baseline` runs stay as the idle-host case. Fault experiments run without
  spinners; their metrics are dominated by the fault.
- **Outage is also measured for online with an introspection cache**
  (matrix group `outage-cached`: `error`, `hang`, `freeze` with cache TTL
  5 s and 30 s, online only, 5 repeats). Otherwise a reviewer can say the
  offline gateway (refresh 5 s) was compared with an online gateway that had
  no cache. Offline does not use the cache, so its `outage` runs stand.
- **What the online cache does during a fault** (`OnlineAuthorizer`,
  `agentauthz/gateway/authorizers.py`). Only `active: true` answers are
  stored, keyed by token, with the time they were stored. A lookup older
  than the TTL deletes the entry and introspects again. There is no
  background refresh and no stale-if-error: if that call fails (error,
  deadline, refused connection), the request gets `503
  authorization_unavailable`, and so does every later request until the
  server answers again, since a failed call stores nothing. So during an
  outage the online gateway keeps serving only until its cached entry reaches
  the TTL, then fails closed. When the server is back, the first successful
  call refills the cache. This is the usual cache-aside behaviour and is
  left as it is; serving stale entries during an outage would be a
  different design (it is what the offline gateway does with its revocation
  list).
- **The cached outage starts at a random point of one TTL** (`fault_at` =
  20 s + uniform(0, T), as for `revoke`), still lasts 20 s, and is followed
  by 20 s of recovery (`duration` = 60 + T). The cache refills at the first
  request after expiry, so its cycle is fixed relative to the start of the
  load. With a fixed `fault_at` = 20 s every repetition would see the same
  cache age at the fault: about 0 s served for T = 5 s and exactly 10 s for
  T = 30 s.
- **Delegation depth is also measured end to end** (`--chain-depth N`,
  matrix group `delegation`: depth 0, 1, 2, 3, 5, both modes, 200 req/s,
  host kept busy). `spike/bench.py` measures token verification alone; this
  measures the whole request path through the gateway. The chain is built
  once per mode before the load starts, so token creation is never inside
  the measured window: offline attenuates the Biscuit N times (third-party
  blocks signed by the current holder, `agentauthz/delegation.py`), online
  does N RFC 8693 exchanges. Each hop lowers `max_amount` by one, so every
  hop adds a real restriction, as in the spike. The last holder signs every
  request. `summary.json` records `chain_depth` and `token_bytes` per mode.

## Repository and publishing

- **License: Apache 2.0** for the code. The published paper is IEEE's.
