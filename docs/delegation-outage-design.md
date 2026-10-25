# Delegation under authorization-server failure

Date: 2026-10-24.

## Question

The paper's `delegation` group measured the cost of *using* a delegated
token; every chain was built before the load started. The claim that online
delegation needs the authorization server while offline delegation needs none
was argued, not measured. This experiment measures it: agents delegate to
sub-agents *while* the authorization server is slow, failing or down.

## Workload: agent tasks

One task, from the agent's point of view:

1. Generate a fresh key pair for a new sub-agent.
2. Delegate to it, lowering `max_amount` by one (a real restriction, as in
   the `delegation` group).
   - offline: `loadgen.offline_hop`, a third-party Biscuit block signed by the
     agent; no network.
   - online: RFC 8693 token exchange at `/token/exchange`, signed by the
     agent, under a 2 s deadline (`--timeout`, the same deadline the online
     gateway uses for introspection).
3. If delegation succeeded, the sub-agent sends `--task-requests` (default 5)
   signed `GET /flights` through the gateway, one after another.

Tasks start open-loop at `--rate` tasks/s (default for the matrix: 40, so
200 requests/s, the rate of every fault experiment in the paper), with an
in-flight cap; a task over the cap is recorded as `generator_overload`. The
agent's root token is issued before the load starts; only per-task
delegation is inside the measured window.

## Components

- `evaluation/tasks.py` (new): `run_tasks()` scheduler, one task coroutine,
  `TaskSample` rows, `summarize_tasks()`, an async online hop with deadline.
  Imports signing, `Sample`, `POOL_SIZE` and `offline_hop` from `loadgen.py`;
  `loadgen.py` is not changed, so the paper's runs stay reproducible.
- `evaluation/run_experiment.py`: `--workload {requests,tasks}` (default
  `requests`, current behaviour) and `--task-requests N`. Same processes,
  fault timeline (`on_tick`), phases and result folder. For `tasks` it
  writes `<mode>.csv.gz` (every request of every task, the usual columns) and
  `<mode>-tasks.csv.gz` (one row per task).
- `evaluation/run_matrix.py`: group `tasks`.
- `evaluation/aggregate.py`: task runs (meta `args.workload == "tasks"`) get
  their own table (`tasks.csv`, `tasks.tex`) and are kept out of the outage,
  latency and slow tables, so the paper's tables do not change.

## What is measured

Per task (`<mode>-tasks.csv.gz`): `seq, t_sched, send_lag_ms, delegate_ms,
delegate_error, requests_ok, task_ms, error`. `task_ms` runs from the
scheduled start to the last response. A task succeeds if delegation
succeeded and all its requests got 2xx.

Per phase (`summary.json`, `phases`, by task start time): `tasks`,
`task_success_rate`, `delegation_success_rate`, `delegate_p50_ms`,
`delegate_p99_ms`, `task_p50_ms`, `task_p99_ms`, `send_lag_p99_ms`, `errors`.
Request-level phase summaries (same format as today) go under `requests`.
Validity: the existing rule, gen lag p99 at task start ≤ 5 ms in every phase.

## Error handling

- Exchange: non-200, connection error or deadline → task fails with
  `delegate_error` = `exchange_<status>`, `exchange_timeout` or the httpx
  error name; no requests are sent.
- Offline delegation cannot fail on the server; any exception is recorded as
  `delegate_error` = exception name.
- Requests: the existing codes (gateway `error` field, `client_timeout`,
  httpx error names). A task stops at its first failed request
  (`requests_ok` counts the successes), as an agent would.

## Run matrix (group `tasks`, 5 repetitions)

Scenarios `baseline`, `error`, `hang`, `freeze` (60 s, fault 20–40 s,
40 tasks/s, 5 requests per task):

- both modes, online without cache: `tasks-<scenario>`;
- online with introspection cache T = 30 s: `tasks-<scenario>-ttl30`
  (`--modes online --cache-ttl 30`). A fresh sub-agent token is never in the
  cache when delegation happens, so the expectation is that the cache does
  not help; the runs check it.

40 runs, about 80 minutes.

## Tests

- `tasks.py`: a task delegates once and sends N requests; a failed exchange
  sends none and is recorded; a deadline is applied to the exchange; a task
  stops at its first failed request; over-cap tasks are recorded as
  `generator_overload`; `summarize_tasks` rates and percentiles per phase.
- `run_experiment.py`: `--workload tasks` writes both CSVs and the summary
  layout; `requests` is unchanged.
- `aggregate.py`: task runs land in `tasks.csv` and never in the outage table.
- `run_matrix.py`: the `tasks` group has the 8 configurations above.

## Out of scope

Delegation trees and revocation of branches, deeper on-the-fly chains
(`--task-depth` can come later), the Permission Manager, AgentDojo.
