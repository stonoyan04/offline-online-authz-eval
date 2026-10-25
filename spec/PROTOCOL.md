# Protocol: offline-verifiable delegation for AI agents

Version 0.1 (draft). This document describes what the code in `agentauthz/`
implements. Where the two disagree, the code is the bug or the spec is out of
date; fix one of them in the same commit.

## 1. Roles

| Role | In the code | Holds |
| --- | --- | --- |
| **User** | `user` fact / `sub` claim | Decides what an agent may do |
| **Issuer** | `authz_server` (`/admin/grants`) | Root Ed25519 key; stands in for the user's Permission Manager |
| **Agent / sub-agent** | `client.AgentClient` | Its own Ed25519 key pair and a token naming that key |
| **Gateway** | `gateway.AuthzMiddleware` | Issuer public key (offline) or introspection credentials (online) |
| **Service** | `demo_service` | Business logic only; sees requests the gateway allowed |

## 2. Operations and route mapping

Tokens grant **operations** (names matching `^[a-z][a-z0-9_:.-]{0,63}$`), not
URLs. Each gateway maps routes to operations and, for spending operations,
names the JSON body field that holds the **amount** (a non-negative integer).
Unmapped routes are denied with `403 route_not_mapped`; only configured public
paths (default `/healthz`) skip authorization.

Demo service mapping:

| Route | Operation | Amount |
| --- | --- | --- |
| `GET /flights` | `search` | none (0) |
| `GET /orders/{id}` | `search` | none (0) |
| `POST /orders` | `buy` | body field `price` |
| `DELETE /orders/{id}` | `cancel` | none (0) |

## 3. Offline mode: Biscuit tokens

### 3.1 Authority block (signed by the issuer's root key)

```datalog
user("alice");
holder("<64 hex chars: agent public key>");
expires(2026-10-11T13:00:00Z);
right("search");
right("buy");
check if time($t), $t < 2026-10-11T13:00:00Z;
check if amount($a), $a <= 300;
```

### 3.2 Delegation block (third-party block signed by the current holder)

```datalog
delegate("<64 hex chars: sub-agent public key>");
// optional restrictions, each only narrows:
check if operation($op), {"search"}.contains($op);
check if amount($a), $a <= 50;
expires(2026-10-11T12:30:00Z);
check if time($t), $t < 2026-10-11T12:30:00Z;
```

Created with `delegation.delegate()`, entirely offline: the holder signs the
block with its own key; no server is contacted.

### 3.3 Verification (gateway, per request)

Inputs: the token, the issuer public key, the **presenter** key (from the
verified request signature, Section 5), the operation, the amount, the current
time, and the cached revocation set.

1. Parse and verify all block signatures against the issuer key.
   Failure → `401 invalid_token`.
2. If any of the token's revocation IDs is in the revocation set →
   `401 invalid_token` ("token revoked").
3. Walk the chain to find the **current holder**:
   - the authority block must contain exactly one `holder` fact;
   - a block containing `delegate(...)` must be a third-party block signed by
     the current holder and contain exactly one `delegate` fact; the named
     key becomes the current holder;
   - a third-party block signed by any other key is rejected;
   - a first-party block may add checks but never `delegate` facts.
   Any violation → `401 invalid_token` ("bad delegation chain").
4. The presenter must equal the current holder. Only the last holder can use
   a token, so a parent cannot present its sub-agent's token.
   Otherwise → `401 invalid_token`.
5. If the earliest `expires` fact from a trusted block (authority, or
   third-party blocks of legitimate holders) has passed → `401 invalid_token`
   ("token expired"). These facts only classify the error; enforcement is the
   Datalog checks in step 6.
6. Run the Datalog authorizer with facts `time(now)`, `operation(op)`,
   `amount(n)` and policy `allow if operation($op), right($op)`. Every check in
   every block must pass. Failure → `403 insufficient_scope`.

Steps 3 and 6 run under biscuit's run limits: at most 1000 facts and 100
iterations (biscuit defaults) and 10 ms of evaluation (biscuit's default is
1 ms). Hitting a limit in either step → `401 invalid_token` ("authorizer
limits exceeded"), never `403`: the token could not be evaluated, which is
not a policy decision.

Why step 3 runs in code rather than Datalog: a Datalog rule can only trust a
block signed by a key written into the rule. The legitimate holders are known
only while reading the chain, so the verifier discovers them block by block
and queries each block with `trusting {current holder}`.

### 3.4 Revocation list

`GET /revocations` returns:

```json
{
  "payload": {"seq": 2, "issued_at": 1760000000, "revoked": ["<hex id>", "..."]},
  "signature": "<base64 Ed25519 signature by the issuer over the payload>"
}
```

The signature covers the payload serialized as JSON with sorted keys and no
whitespace. Revoking a token adds the revocation ID of its **last** block:
this kills that token and every token derived from it, but not its parent.

Gateways refresh the list every `refresh_seconds` (default 5) and:

- accept only lists signed by the issuer;
- never replace a list with one that has a lower `(seq, issued_at)`;
- keep the last good list when the issuer is unreachable;
- with `max_staleness` set, answer `503 revocation_list_stale` once the list
  they hold was issued more than `max_staleness` seconds ago. Unset (default)
  means they keep serving: availability over revocation freshness.

## 4. Online mode: opaque tokens and introspection (baseline)

### 4.1 Introspection (RFC 7662)

`POST /introspect`, HTTP Basic client authentication, form body `token=...`.

Active response:

```json
{
  "active": true,
  "token_type": "Bearer",
  "sub": "alice",
  "scope": "buy search",
  "iat": 1760000000,
  "exp": 1760003600,
  "cnf": {"agent_key": "<64 hex chars>"},
  "max_amount": 300,
  "delegation_depth": 0
}
```

Inactive, unknown, expired or revoked: `{"active": false}`.

The gateway allows a request when `active` is true, `cnf.agent_key` equals the
presenter, `exp` is in the future, the operation is in `scope`, and the amount
is at most `max_amount`. If the server cannot be reached within the gateway's
deadline (default 2 s total), or answers anything but 200, the gateway answers
`503 authorization_unavailable` (fail closed).

At most `max_in_flight` introspection calls (default 200, the gateway's HTTP
connection limit: 8 pools of 25 connections, used round-robin) are
outstanding at once; further calls wait
for a slot inside the same deadline. When the server hangs, the gateway so
keeps answering 503 on time instead of piling up calls.

Optional introspection cache: with `cache_ttl > 0`, active responses are
reused for that many seconds. This is the usual optimization, and it creates
the same trade-off as the offline refresh interval: up to `cache_ttl` seconds
of revocation lag in exchange for surviving short outages.

### 4.2 Delegation (RFC 8693-style token exchange)

`POST /token/exchange`, form body:

| Parameter | Meaning |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | the parent's token |
| `actor_key` | sub-agent public key (64 hex) |
| `scope` | optional, space-separated operations; subset of the parent's |
| `max_amount` | optional, at most the parent's |
| `ttl_seconds` | optional; never beyond the parent's expiry |

The request must carry a valid request signature (Section 5) by the parent's
holder key. Unlike offline delegation, **this needs the server to be up**.

### 4.3 Revocation (RFC 7009)

`POST /revoke` (admin bearer), form `token=...`, always `200`. Works for both
token formats: opaque tokens are marked revoked (and their descendants become
inactive); Biscuit tokens have their last revocation ID added to the list.

## 5. Request signatures (proof of possession)

Both modes use the same scheme (`agentauthz/pop.py`), a simplified stand-in
for HTTP Message Signatures (RFC 9421).

Headers:

```
Authorization:   Bearer <token>
Agent-Key:       <64 hex: signer public key>
Agent-Created:   <unix seconds>
Agent-Nonce:     <random hex; the client uses 128 random bits>
Agent-Signature: <base64 Ed25519 signature>
```

Signed string (lines joined with `\n`):

```
<METHOD uppercased>
<request target exactly as sent: percent-encoded path and query>
<sha256 hex of the body>
<sha256 hex of the token>
<created>
<nonce>
```

The verifier rejects a request when `|now - created| > 30 s`, when the
signature does not verify, or when `(key, nonce)` was already seen inside the
window. The replay cache fails closed when full of live entries. No
server-issued nonce is needed, so verification stays local.

## 6. Gateway responses

Denials are JSON: `{"error": "<code>", "reason": "<text>", "mode": "offline|online"}`.

| Status | `error` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | amount missing or not a non-negative integer |
| 401 | `invalid_request` | token or signature headers missing |
| 401 | `invalid_signature` | bad, stale or replayed request signature |
| 401 | `invalid_token` | bad token, revoked, expired, wrong holder, bad chain, Datalog limits exceeded |
| 403 | `insufficient_scope` | operation not granted or amount over limit |
| 403 | `route_not_mapped` | no operation configured for this route |
| 413 | `invalid_request` | body over 1 MB |
| 503 | `authorization_unavailable` | online: authorization server unreachable |
| 503 | `revocation_list_stale` | offline: list older than `max_staleness` |

Every response the gateway touches carries:

```
Server-Timing:    authz;dur=<milliseconds spent authorizing>
Agent-Authz-Mode: offline | online
```

## 7. Fault injection (experiments only)

`PUT /admin/fault` (admin bearer) on the authorization server, JSON body:

| Field | Default | Meaning |
| --- | --- | --- |
| `mode` | `none` | `none`, `slow`, `error`, `hang`, `flapping` |
| `delay_ms`, `jitter_ms` | 0 | `slow`: added latency |
| `error_status` | 503 | `error` and `flapping`: status returned |
| `hang_seconds` | 30 | `hang`: hold the request, then 503 |
| `period_seconds`, `down_fraction` | 10, 0.5 | `flapping`: failing for the first fraction of each period |

Faults apply to `/introspect`, `/token/exchange` and `/revocations` only.
A fully stopped server (connection refused) is produced by stopping the
process.

## 8. Known limitations (v0.1)

- Request signatures are a simplified scheme, not full RFC 9421.
- Token size grows by about 360 bytes per delegation hop (measured); deep
  chains approach common 8 KB header limits. Cap depth in deployments.
- The authorization server keeps grants in memory in a single process.
- Issuer key rotation is not specified yet (use `root_key_id` later).
