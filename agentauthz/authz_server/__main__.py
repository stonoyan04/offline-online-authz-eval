"""python -m agentauthz.authz_server [--host 127.0.0.1] [--port 8001]"""

import argparse
import logging

import uvicorn

from agentauthz.authz_server.app import Settings, create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="agentauthz authorization server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(name)s: %(message)s")
    app = create_app(Settings.from_env())
    # One worker: the grant store is in memory (see store.py).
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level, workers=1)


if __name__ == "__main__":
    main()
