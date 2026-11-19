"""Error-response compatibility checks for the Python SDK."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack.errors import (
    AccountCallFailedError,
    AccountPieceNotReadyError,
    AgentBudgetExceededError,
    BrowserSessionLengthRefusedError,
    BrowserTimeUsedUpError,
    ControlsRequiredError,
    DestinationNotAvailableError,
    ForbiddenError,
    GovernanceApprovalRequiredError,
    GovernanceApprovalStateError,
    ProviderCapacityUnavailableError,
    RecipientOptedOutError,
    StackError,
    ToolPriceRefusedError,
    ToolRunRejectedError,
    ToolsUnavailableError,
    raise_for_status,
)


def test_parses_nested_stack_error() -> None:
    with pytest.raises(StackError) as raised:
        raise_for_status(
            409,
            {"error": {"code": "CONFLICT", "message": "Already changed", "details": {"id": "x"}}},
        )

    assert str(raised.value) == "Already changed"
    assert raised.value.code == "CONFLICT"
    assert raised.value.status_code == 409
    assert raised.value.details == {"id": "x"}


def test_parses_rfc6749_oauth_error() -> None:
    with pytest.raises(ForbiddenError) as raised:
        raise_for_status(
            403,
            {
                "error": "insufficient_scope",
                "error_description": "This route requires services:write",
                "required_scope": "services:write",
            },
        )

    assert str(raised.value) == "This route requires services:write"
    assert raised.value.code == "INSUFFICIENT_SCOPE"
    assert raised.value.status_code == 403
    assert raised.value.details == {"required_scope": "services:write"}


def test_handles_non_object_error_body() -> None:
    with pytest.raises(StackError) as raised:
        raise_for_status(500, "upstream failed")

    assert str(raised.value) == "API error: 500"
    assert raised.value.status_code == 500


def test_account_error_codes_get_their_own_classes() -> None:
    with pytest.raises(GovernanceApprovalRequiredError) as approval:
        raise_for_status(
            403,
            {
                "error": {
                    "code": "GOVERNANCE_APPROVAL_REQUIRED",
                    "message": "Ask the operator to approve request gvr_1",
                    "details": {"approval_id": "gvr_1", "approval_url": "https://getstack.run/approvals/gvr_1"},
                }
            },
        )
    assert isinstance(approval.value, ForbiddenError)
    assert (approval.value.approval_id, approval.value.approval_url) == (
        "gvr_1",
        "https://getstack.run/approvals/gvr_1",
    )

    with pytest.raises(AgentBudgetExceededError) as budget:
        raise_for_status(
            402,
            {"error": {"code": "AGENT_BUDGET_EXCEEDED", "message": "m", "details": {"account_id": "acct_1"}}},
        )
    assert budget.value.account_id == "acct_1"
    assert budget.value.remaining_cents is None

    with pytest.raises(AccountPieceNotReadyError) as piece:
        raise_for_status(409, {"error": {"code": "ACCOUNT_PIECE_NOT_READY", "message": "m", "details": "bad"}})
    assert piece.value.details == {}
    assert (piece.value.account_id, piece.value.piece, piece.value.state) == (None, None, None)


def _raised(status: int, code: str, details: object) -> StackError:
    with pytest.raises(StackError) as raised:
        raise_for_status(status, {"error": {"code": code, "message": f"{code} message", "details": details}})
    assert (raised.value.code, raised.value.status_code, str(raised.value)) == (code, status, f"{code} message")
    return raised.value


def test_call_and_tool_error_codes_get_their_own_classes() -> None:
    capacity = _raised(503, "PROVIDER_CAPACITY_UNAVAILABLE", {"provider": "telnyx"})
    assert isinstance(capacity, ProviderCapacityUnavailableError)
    assert capacity.provider == "telnyx"

    used_up = _raised(503, "BROWSER_TIME_USED_UP", {"provider": "bb"})
    assert isinstance(used_up, BrowserTimeUsedUpError)
    assert used_up.provider == "bb"
    too_long = _raised(503, "BROWSER_SESSION_LENGTH_REFUSED", {"provider": "bb"})
    assert isinstance(too_long, BrowserSessionLengthRefusedError)
    assert too_long.provider == "bb"

    maybe_placed = _raised(502, "ACCOUNT_CALL_FAILED", {"reason": "provider_unavailable"})
    assert isinstance(maybe_placed, AccountCallFailedError)
    assert (maybe_placed.reason, maybe_placed.retryable) == ("provider_unavailable", True)
    refused = _raised(422, "ACCOUNT_CALL_FAILED", {"reason": "invalid_number"})
    assert isinstance(refused, AccountCallFailedError)
    assert (refused.reason, refused.retryable) == ("invalid_number", False)

    destination = _raised(422, "DESTINATION_NOT_AVAILABLE", {"reason": "refused_by_twilio"})
    assert isinstance(destination, DestinationNotAvailableError)
    assert destination.reason == "refused_by_twilio"
    assert destination.details == {"reason": "refused_by_twilio"}

    opted_out = _raised(403, "RECIPIENT_OPTED_OUT", {"account_id": "acct_1"})
    assert isinstance(opted_out, RecipientOptedOutError) and isinstance(opted_out, ForbiddenError)
    assert opted_out.account_id == "acct_1"

    price = _raised(422, "TOOL_PRICE_REFUSED", {"reason": "unbounded_price", "endpoint": "/v1/search"})
    assert isinstance(price, ToolPriceRefusedError)
    assert price.reason == "unbounded_price"
    assert price.details == {"reason": "unbounded_price", "endpoint": "/v1/search"}

    unavailable = _raised(503, "TOOLS_UNAVAILABLE", {"reason": "wallet_low"})
    assert isinstance(unavailable, ToolsUnavailableError)
    assert unavailable.reason == "wallet_low"

    rejected = _raised(400, "TOOL_RUN_REJECTED", {"provider_status": 422})
    assert isinstance(rejected, ToolRunRejectedError)
    assert rejected.provider_status == 422


def test_call_and_tool_errors_tolerate_malformed_details() -> None:
    destination = _raised(422, "DESTINATION_NOT_AVAILABLE", "bad")
    assert isinstance(destination, DestinationNotAvailableError)
    assert (destination.details, destination.reason) == ({}, None)

    rejected = _raised(400, "TOOL_RUN_REJECTED", "bad")
    assert isinstance(rejected, ToolRunRejectedError)
    assert (rejected.details, rejected.provider_status) == ({}, None)


@pytest.mark.parametrize("state", ["pending", "rejected", "expired"])
def test_a_governance_approval_that_cannot_be_used_has_a_typed_code(state: str) -> None:
    code = f"GOVERNANCE_APPROVAL_{state.upper()}"
    with pytest.raises(GovernanceApprovalStateError) as raised:
        raise_for_status(
            403, {"error": {"code": code, "message": "m", "details": {"approval_id": "gvr_1", "status": state}}}
        )
    assert isinstance(raised.value, ForbiddenError)
    assert (raised.value.code, raised.value.approval_id, raised.value.approval_status) == (code, "gvr_1", state)


def test_other_codes_keep_the_status_class() -> None:
    with pytest.raises(ForbiddenError) as raised:
        raise_for_status(403, {"error": {"code": "FORBIDDEN", "message": "no"}})
    assert type(raised.value) is ForbiddenError


@pytest.mark.parametrize("feature", ["record", "detector_settings"])
def test_controls_required_is_typed_with_its_feature(feature: str) -> None:
    # Reading the record and changing the detector settings are controls features: 402 without controls.
    with pytest.raises(ControlsRequiredError) as raised:
        raise_for_status(
            402,
            {
                "error": {
                    "code": "CONTROLS_REQUIRED",
                    "message": "Reading the record needs controls.",
                    "details": {"feature": feature},
                }
            },
        )
    assert raised.value.code == "CONTROLS_REQUIRED"
    assert raised.value.status_code == 402
    assert raised.value.feature == feature
    assert str(raised.value) == "Reading the record needs controls."
