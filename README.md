# offline-online-authz-eval

Offline-verifiable authorization for AI agents, and an experimental comparison
against online authorization approaches.

This repository holds the code, experiments and raw data.

## Idea in one paragraph

A user delegates a narrow set of permissions to an AI agent as a
[Biscuit](https://www.biscuitsec.org) token. The service's gateway verifies
the token **locally**, with only the issuer's public key, so it keeps working
when the authorization server is slow or down. Agents can hand a narrower
token to sub-agents without contacting any server. The baseline is the online
approach: the gateway asks the authorization server about every request
(OAuth 2.0 token introspection, RFC 7662). The experiments measure latency,
throughput, availability during authorization-server failure, and the cost of
going offline: revocation lag.

## Layout

| Path | Contents |
| --- | --- |
| `agentauthz/delegation.py` | Biscuit tokens: issue, offline delegation to sub-agents, local verification |
| `agentauthz/pop.py` | Request signatures (proof of possession), replay protection |
| `agentauthz/revocation.py` | Signed revocation list for offline gateways |
| `agentauthz/authz_server/` | Issuer + online baseline: introspection (RFC 7662), token exchange (RFC 8693), revocation (RFC 7009), fault injection |
| `agentauthz/gateway/` | One ASGI middleware, two authorizers: `offline` and `online` |
| `agentauthz/demo_service/` | Protected demo airline API |
| `agentauthz/client.py` | Agent HTTP client that signs every request |
| `tests/` | 100+ tests, most run in both modes |
| `spike/` | First design spike: findings and depth benchmark |
| `spec/PROTOCOL.md` | Token format, verification, HTTP headers, error codes |
| `evaluation/` | Load generator, failure scenarios, results, analysis |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest

# Terminal 1: authorization server
export AUTHZ_ADMIN_TOKEN=adm AUTHZ_CLIENTS=gw:sec
python -m agentauthz.authz_server --port 8001

# Terminal 2: demo service behind an offline gateway
python -m agentauthz.demo_service --mode offline --port 8000

# Terminal 3: the same service behind an online gateway
export AUTHZ_CLIENT_ID=gw AUTHZ_CLIENT_SECRET=sec
python -m agentauthz.demo_service --mode online --port 8002
```

See `spec/PROTOCOL.md` for the API and every option.

## Requirements

- Python 3.11+

## Author

Smbat Tonoyan

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
