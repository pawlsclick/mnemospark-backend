"""Per-request cache for expensive DynamoDB scans (one GraphQL HTTP request)."""

from __future__ import annotations

from typing import Any

try:
    from dashboard_graphql.domain.event_fact_builder import build_event_facts_uncached
    from dashboard_graphql.domain.quote_fact_builder import build_quote_facts
except ModuleNotFoundError as error:  # pragma: no cover - runtime path when CodeUri is services/dashboard_graphql
    if error.name != "dashboard_graphql":
        raise
    from domain.event_fact_builder import build_event_facts_uncached  # type: ignore[no-redef]
    from domain.quote_fact_builder import build_quote_facts  # type: ignore[no-redef]


class DashboardRequestContext:
    """Caches event facts and quote facts per (time_from, time_to) for a single request."""

    def __init__(self) -> None:
        self._event_facts: dict[tuple[str | None, str | None], list[dict[str, Any]]] = {}
        self._quote_facts: dict[tuple[str | None, str | None], list[dict[str, Any]]] = {}

    def _key(self, time_from: str | None, time_to: str | None) -> tuple[str | None, str | None]:
        return (time_from, time_to)

    def event_facts(self, *, time_from: str | None, time_to: str | None) -> list[dict[str, Any]]:
        k = self._key(time_from, time_to)
        if k not in self._event_facts:
            self._event_facts[k] = build_event_facts_uncached(time_from=time_from, time_to=time_to)
        return self._event_facts[k]

    def quote_facts(self, *, time_from: str | None, time_to: str | None) -> list[dict[str, Any]]:
        k = self._key(time_from, time_to)
        if k not in self._quote_facts:
            ef = self.event_facts(time_from=time_from, time_to=time_to)
            self._quote_facts[k] = build_quote_facts(
                time_from=time_from, time_to=time_to, event_facts=ef
            )
        return self._quote_facts[k]
