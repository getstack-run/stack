"""Billing service: the platform and controls subscriptions of agent accounts.

Both are card subscriptions through Stripe Checkout, a card always required, with a free trial the
first time. Starting one returns a Checkout URL; the subscription itself is written from Stripe's own
events, never by these calls, and is managed and cancelled in the Stripe billing portal.

Starting a subscription is an owner or admin call and needs no approval: the person pays on Stripe's
own page. An account on a contract plan, or already on the subscription, is refused with a 409
(``SUBSCRIPTION_CONFLICT``).

Example::

    checkout = stack.billing.subscribe_platform()
    print(checkout["checkout_url"], checkout["trial"])
    status = stack.billing.subscriptions()
    print(status["platform"]["status"], status["controls"]["status"])
"""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient


def _approval(governance_approval_id: str | None) -> dict[str, str] | None:
    return {"X-Governance-Approval": governance_approval_id} if governance_approval_id is not None else None


class BillingService:
    def __init__(self, client: HttpClient):
        self._client = client

    def _post(self, path: str, governance_approval_id: str | None) -> dict[str, Any]:
        # An empty JSON object, not no body: the API refuses a JSON request with an empty body.
        return cast(
            "dict[str, Any]",
            self._client.request("POST", path, json={}, extra_headers=_approval(governance_approval_id)),
        )

    def subscriptions(self) -> dict[str, Any]:
        """The platform and controls state and this month's usage.

        ``platform`` is ``{status, active, contract, trial_ends_at}`` (status: none, incomplete, trialing, active,
        past_due, lapsed, canceled), ``controls`` is ``{status, trial_ends_at}`` (off, trialing, active, lapsed) and
        ``this_month`` is ``{account_actions, control_checks}``. ``trial_ends_at`` is the day the free trial ends as
        Stripe states it (an ISO 8601 string), or ``None`` when no trial is running.
        """
        return cast("dict[str, Any]", self._client.request("GET", "/v1/billing/subscriptions"))

    def subscribe_platform(self, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Start the platform subscription: ``{checkout_url, session_id, trial}``.

        The free trial applies when it has not been used. Owner or admin, not a white-label tenant. A 409
        ``SUBSCRIPTION_CONFLICT`` means it is already on or the account is on a contract plan; a 503
        ``BILLING_NOT_CONFIGURED`` means it is not offered yet. No approval is needed;
        ``governance_approval_id`` is accepted for compatibility and ignored.
        """
        return self._post("/v1/billing/platform/subscribe", governance_approval_id)

    def subscribe_controls(self, *, governance_approval_id: str | None = None) -> dict[str, Any]:
        """Switch on hosted controls: ``{checkout_url, session_id, trial}``.

        Needs the platform subscription (``PLATFORM_SUBSCRIPTION_REQUIRED`` otherwise). Same 409/503 rules as
        ``subscribe_platform``.
        """
        return self._post("/v1/billing/controls/subscribe", governance_approval_id)
