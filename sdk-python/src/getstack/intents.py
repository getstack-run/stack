"""Intent simulation + pre-execution approval gate.


simulate()    Dry-run a candidate IntentClaim against a passport.
              Returns a signed simulation result.
submit()      Register the Intent + run simulation + persist a
              pending intent_approvals row. Returns an approval id;
              operators decide via approve() / reject().
submit_and_wait()
              Submit then poll until the approval reaches a terminal
              state or the timeout elapses.
list_pending()
              Operator-scope queue of pending approvals.
approve() / reject()
              Operator transitions a pending row to approved or
              rejected. Rejection auto-revokes the passport;
              block_future=True additionally suspends the agent.
"""

from __future__ import annotations

import time
from typing import Any, cast

from .client import HttpClient


class IntentsService:
    def __init__(self, client: HttpClient):
        self._client = client

    # ─── 2.1 — simulate ─────────────────────────────────────────────

    def simulate(
        self,
        intent: dict[str, Any],
        passport_token: str,
        *,
        intent_claim_ref: str | None = None,
        persist: bool | None = None,
    ) -> dict[str, Any]:
        """Dry-run an Intent. No approval row created.

        Args:
            intent: IntentClaim payload (type, intent_type, agent_id,
                named_intent, target, action, parameters, estimated_cost,
                accountability, reason, requires, user_subject,
                mission_ref, submitted_at).
            passport_token: Passport JWT to simulate against.
            intent_claim_ref: Optional pc_* claim id to link this
                simulation to a pre-registered Intent.
            persist: When False, skips writing the simulation claim.
                Default True.

        Returns:
            Dict with allowed, denial_reasons, simulated_cost,
            predicted_detector_fires, simulated_at, claim_id?,
            diagnostics.
        """
        body: dict[str, Any] = {"intent": intent}
        if intent_claim_ref is not None:
            body["intent_claim_ref"] = intent_claim_ref
        if persist is not None:
            body["persist"] = persist
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                "/v1/intents/simulate",
                json=body,
                extra_headers={"X-Passport-Token": passport_token},
            ),
        )

    # ─── 2.2 — submit / approval flow ───────────────────────────────

    def submit(
        self,
        intent: dict[str, Any],
        passport_token: str,
        *,
        expires_in_seconds: int | None = None,
        skip_simulation: bool = False,
    ) -> dict[str, Any]:
        """Submit an Intent for pre-execution operator approval.

        Returns:
            Dict with approval_id, intent_claim_id, simulated_claim_id?,
            status='pending', expires_at, simulation? (when not skipped).
        """
        body: dict[str, Any] = {"intent": intent}
        if expires_in_seconds is not None:
            body["expires_in_seconds"] = expires_in_seconds
        if skip_simulation:
            body["skip_simulation"] = True
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                "/v1/intents/submit",
                json=body,
                extra_headers={"X-Passport-Token": passport_token},
            ),
        )

    def submit_and_wait(
        self,
        intent: dict[str, Any],
        passport_token: str,
        *,
        expires_in_seconds: int | None = None,
        skip_simulation: bool = False,
        timeout_seconds: float = 60.0,
        poll_interval_seconds: float = 1.0,
    ) -> dict[str, Any]:
        """Submit then poll the per-id endpoint until the row reaches a
        terminal status (approved | rejected | expired) or the timeout
        elapses.

        Returns:
            Dict with keys 'initial' (the submit response),
            'final' (the last known row state), and 'timed_out' (bool).
            When the row reaches a terminal status before timeout,
            'timed_out' is False and 'final["status"]' is one of
            approved | rejected | expired.
        """
        initial = self.submit(
            intent,
            passport_token,
            expires_in_seconds=expires_in_seconds,
            skip_simulation=skip_simulation,
        )
        approval_id = initial["approval_id"]
        deadline = time.monotonic() + timeout_seconds
        last_row: dict[str, Any] | None = None
        # Use GET /v1/intents/:id rather than list_pending so we can
        # read the actual terminal status — list_pending alone can't
        # distinguish 'no longer pending' from 'approved'.
        while time.monotonic() < deadline:
            row = self.get(approval_id)
            last_row = row
            if row.get("status") != "pending":
                return {"initial": initial, "final": row, "timed_out": False}
            time.sleep(poll_interval_seconds)
        return {
            "initial": initial,
            "final": last_row or {"id": approval_id, "status": "pending"},
            "timed_out": True,
        }

    def get(self, approval_id: str) -> dict[str, Any]:
        """Fetch a single approval row by id, regardless of status.

        Returns the full row when the calling operator owns it. Raises
        the SDK's standard 404 error when the row doesn't exist or
        belongs to a different operator (cross-tenant existence hidden).
        """
        return cast("dict[str, Any]", self._client.request("GET", f"/v1/intents/{approval_id}"))

    def list_pending(
        self,
        *,
        page: int | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List pending approvals scoped to the calling operator."""
        params: dict[str, Any] = {}
        if page is not None:
            params["page"] = page
        if limit is not None:
            params["limit"] = limit
        return cast("dict[str, Any]", self._client.request("GET", "/v1/intents/pending", params=params or None))

    def approve(
        self,
        approval_id: str,
        *,
        notes: str | None = None,
        governance_approval_id: str | None = None,
    ) -> dict[str, Any]:
        """Transition a pending approval → approved.

        From an API key or an OAuth token this raises GovernanceApprovalRequiredError: a person confirms this
        intent in the chat or on the approval page, and the retry carries ``governance_approval_id``.
        """
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = notes
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/intents/{approval_id}/approve",
                json=body,
                extra_headers={"X-Governance-Approval": governance_approval_id} if governance_approval_id else None,
            ),
        )

    def reject(
        self,
        approval_id: str,
        *,
        notes: str | None = None,
        block_future: bool = False,
    ) -> dict[str, Any]:
        """Transition a pending approval → rejected.

        Auto-revokes the passport. block_future=True additionally
        suspends the agent so subsequent passports cannot be issued.
        """
        body: dict[str, Any] = {}
        if notes is not None:
            body["notes"] = notes
        if block_future:
            body["block_future"] = True
        return cast(
            "dict[str, Any]",
            self._client.request(
                "POST",
                f"/v1/intents/{approval_id}/reject",
                json=body,
            ),
        )
