# Spike: Biscuit delegation with proof of possession

Answers the first design question of the project: can a token be **attenuated
for sub-agents offline** and still be **bound to the key of whoever holds it**?

Yes. The code now lives in the shared package (`agentauthz/delegation.py` and
`agentauthz/pop.py`); see the module docstring for the design and why the
holder chain is walked in Python rather than in Datalog. This folder keeps
the benchmark and the findings.

## Files

| File | What it does |
| --- | --- |
| `../agentauthz/delegation.py` | `issue()` a root token, `delegate()` a narrower one to a sub-agent, `verify()` a request locally |
| `../agentauthz/pop.py` | Signs and checks requests with the holder's Ed25519 key; time window + replay cache (stand-in for RFC 9421) |
| `../tests/test_delegation.py` | One test per attack or misuse case |
| `bench.py` | Verification latency and token size vs. delegation depth |

## Run

From the repository root:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
python spike/bench.py --out evaluation/results/spike_depth.csv
```

## What the tests cover

- Allowed: holder within limits; sub-agent within narrowed rights; two hops;
  signed request end to end.
- Denied: over the limit, operation not granted, expired, revoked (including
  revoking a parent token, which revokes every token derived from it),
  token from another issuer, tampered bytes, stolen token without the holder's
  key, parent presenting the sub-agent's token, sub-agent re-adding removed
  rights, a thief redirecting the holder with a first-party block or with a
  block signed by its own key, replayed request, stale request, modified body.

## Design decisions

- **Linear chain, last holder only.** Each delegation block must be signed by
  the current holder and name exactly one next holder. Only the final holder
  can use the token.
- **No server-issued nonce.** Requests carry a timestamp and a random nonce;
  the verifier accepts a 30-second window and remembers nonces inside it.
  Verification stays fully local.
- **Revocation by ID.** The verifier checks the token's revocation IDs against
  a cached list. Revoking any block's ID kills every token derived from it.
  How stale that cache may be is exactly the revocation-lag cost measured in
  the experiments.

## Results (author's MacBook, arm64, Python 3.12)

From `evaluation/results/spike_depth.csv`: local verification costs about
69 µs (p50) with no delegation and grows linearly by about 73 µs per hop,
reaching about 0.8 ms (p50) and 1.0 ms (p99) at 10 hops. Each hop adds
359 bytes to the token (383 B at depth 0, 3,973 B at depth 10).

## Open points for the gateway

- Replace `agentauthz/pop.py` with real HTTP Message Signatures (RFC 9421).
- Token size grows ~360 B per hop; deep chains approach common header-size
  limits (8 KB), so the protocol should cap depth or send the token in the body.
