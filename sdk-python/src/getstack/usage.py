"""Usage service — `/v1/usage` (usage + spend + earnings rollup).

The one-call rollup of what your operator consumed against its plan,
spent, and earned this billing period. Superset of the per-domain meters
(`stack.scan.usage()`, `stack.llm.usage`, `stack.proxy` counts) — one
authoritative shape the CLI and dashboard read too. Money fields are in
cents.

Example::

    u = stack.usage.get()
    a = u["consumption"]["actions"]
    print(f"Metered actions {a['used']}/{a['limit']}")
    print(f"Allowance coverage {a['allowance_coverage']}")
    print(f"Total actions {u['consumption']['activity']['total']}")
    print(f"Spent this period: ${u['spend_cents']['total'] / 100:.2f}")
"""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


class UsageService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        """Usage, spend, and earnings for the current billing period.

        Args:
            since: Optional window start (ISO-8601 or unix-ms). When set, the
                flow metrics (spend, metered actions, proxy calls,
                proxy) are scoped to the window; inventory meters gain a
                ``created_in_window`` count. Omit for the billing period.
            until: Optional exclusive window end.

        Returns:
            Dict with keys: plan (platform, internal, contract or none: the plan the
            account is on), period_start, period_end, period_label,
            account_since (ISO-8601 account creation - the floor for any
            look-back window), consumption (all activity, metered actions,
            action allowance_coverage and allowance_plan (the account's plan for the
            current month, None for any other), and per-meter
            {used, limit, created_in_window?}), passthrough (None under a since/until
            window - those counters only exist for the current month),
            spend_cents (skills / llm_compute / identity / overage / total),
            For pooled accounts (a partner on a negotiated hard cap and its accounts),
            consumption.actions also carries pooled=True, own_used (this
            account's share) and tenants (accounts sharing the pool), and
            its ``used`` is the whole pool total.
            wallet_cents ({balance}), and earnings_cents ({unpaid, lifetime}).
            All money in cents.
        """
        params: dict[str, str] = {}
        if since is not None:
            params["since"] = since
        if until is not None:
            params["until"] = until
        return cast("dict[str, Any]", self._client.get("/v1/usage", params=params or None))
