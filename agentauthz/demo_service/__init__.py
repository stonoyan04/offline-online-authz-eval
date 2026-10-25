"""Demo airline API used as the protected service in the experiments."""

from agentauthz.demo_service.app import ROUTES, create_demo_app

__all__ = ["ROUTES", "create_demo_app"]
