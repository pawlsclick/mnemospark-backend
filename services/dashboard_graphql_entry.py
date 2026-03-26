"""Lambda entry for dashboard GraphQL (loads dashboard_graphql.app)."""

from __future__ import annotations

from dashboard_graphql.app import lambda_handler

__all__ = ["lambda_handler"]
