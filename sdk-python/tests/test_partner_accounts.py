"""Partner-managed accounts: open by reference, invite, release, revoke cascade, signing setup."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from getstack._async.partner_accounts import AsyncPartnerAccountsService
from getstack.partner_accounts import PartnerAccountsService


def test_sync_account_signing():
    client = Mock()
    client.put.return_value = {"configured": True}
    result = PartnerAccountsService(client).set_inbound_webhook_signing_secret(
        "account fixture",
        "wh/fixture",
        "synthetic-provider",
        "synthetic-downstream",
    )
    assert result == {"configured": True}
    client.put.assert_called_once_with(
        "/v1/partner/accounts/account%20fixture/inbound-webhooks/wh%2Ffixture/provider-signing-secret",
        json={"signing_secret": "synthetic-provider", "downstream_signing_secret": "synthetic-downstream"},
    )


def test_async_account_signing():
    client = Mock()
    client.put = AsyncMock(return_value={"configured": True})
    result = asyncio.run(
        AsyncPartnerAccountsService(client).set_inbound_webhook_signing_secret(
            "account fixture",
            "wh/fixture",
            "synthetic-provider",
        )
    )
    assert result == {"configured": True}
    client.put.assert_awaited_once_with(
        "/v1/partner/accounts/account%20fixture/inbound-webhooks/wh%2Ffixture/provider-signing-secret",
        json={"signing_secret": "synthetic-provider"},
    )


def test_sync_account_create_sends_the_reference_and_no_tier():
    client = Mock()
    client.post.return_value = {"account_id": "op_a", "billing": "partner", "created": True}
    service = PartnerAccountsService(client)
    result = service.create("cust_1")
    assert result["billing"] == "partner"
    client.post.assert_called_once_with("/v1/partner/accounts", json={"external_ref": "cust_1"})
    try:
        service.create("cust_2", tier="pro")  # type: ignore[call-arg]
    except TypeError:
        pass
    else:
        raise AssertionError("create must not accept tier; accounts draw from the partner's plan")
    try:
        service.create()  # type: ignore[call-arg]
    except TypeError:
        pass
    else:
        raise AssertionError("create needs the partner's reference: it is the idempotency key")


def test_account_create_switches_controls_on_only_when_asked():
    client = Mock()
    client.post.return_value = {"account_id": "op_a", "billing": "partner", "created": True}
    PartnerAccountsService(client).create("cust_1", controls=True)
    client.post.assert_called_once_with("/v1/partner/accounts", json={"external_ref": "cust_1", "controls": True})
    client.post.reset_mock()
    PartnerAccountsService(client).create("cust_2", controls=False)
    client.post.assert_called_once_with("/v1/partner/accounts", json={"external_ref": "cust_2"})
    async_client = Mock()
    async_client.post = AsyncMock(return_value={"account_id": "op_a", "billing": "partner", "created": True})
    asyncio.run(AsyncPartnerAccountsService(async_client).create("cust_3", controls=True))
    async_client.post.assert_awaited_once_with(
        "/v1/partner/accounts", json={"external_ref": "cust_3", "controls": True}
    )


def test_async_account_create_sends_the_reference():
    client = Mock()
    client.post = AsyncMock(return_value={"account_id": "op_a", "billing": "partner", "created": True})
    asyncio.run(AsyncPartnerAccountsService(client).create("cust_1"))
    client.post.assert_awaited_once_with("/v1/partner/accounts", json={"external_ref": "cust_1"})


def test_list_finds_one_by_reference():
    client = Mock()
    client.get.return_value = {"accounts": [{"account_id": "op_a"}]}
    assert PartnerAccountsService(client).list("cust 1") == [{"account_id": "op_a"}]
    client.get.assert_called_once_with("/v1/partner/accounts?external_ref=cust%201")


def test_account_revoke_returns_cascade_counts():
    cascade = {"transitioned": True, "webhooks_revoked": 2, "passports_revoked": 3}
    client = Mock()
    client.delete.return_value = cascade
    assert PartnerAccountsService(client).revoke("op_a") == cascade
    client.delete.assert_called_once_with("/v1/partner/accounts/op_a")
    aclient = Mock()
    aclient.delete = AsyncMock(return_value=cascade)
    assert asyncio.run(AsyncPartnerAccountsService(aclient).revoke("op_a")) == cascade


def test_invite_and_release_use_the_given_address_only():
    record = {"account_id": "op_a", "status": "pending"}
    client = Mock()
    client.post.side_effect = [{"status": "invited"}, {"release": record}, {"release": record}]
    service = PartnerAccountsService(client)
    assert service.invite("op_a", "customer@example.com") == {"status": "invited"}
    client.post.assert_called_with("/v1/partner/accounts/op_a/invite", json={"email": "customer@example.com"})
    assert service.release("op_a") == record
    client.post.assert_called_with("/v1/partner/accounts/op_a/release", json={})
    assert service.release("op_a", email="customer@example.com") == record
    client.post.assert_called_with("/v1/partner/accounts/op_a/release", json={"email": "customer@example.com"})


def test_release_record_cancel_and_list():
    record = {"account_id": "op_a", "status": "completed"}
    client = Mock()
    client.get.side_effect = [{"release": record}, {"releases": [record]}]
    client.delete.return_value = {"cancelled": True}
    service = PartnerAccountsService(client)
    assert service.get_release("op_a") == record
    client.get.assert_called_with("/v1/partner/accounts/op_a/release")
    assert service.list_releases() == [record]
    client.get.assert_called_with("/v1/partner/releases")
    assert service.cancel_release("op_a") == {"cancelled": True}
    client.delete.assert_called_once_with("/v1/partner/accounts/op_a/release")


def test_set_controls_sync_and_async():
    plan = {"account_id": "op_a", "plan": {"controls": {"status": "active"}}}
    client = Mock()
    client.put.return_value = plan
    assert PartnerAccountsService(client).set_controls("op_a", True) == plan
    client.put.assert_called_once_with("/v1/partner/accounts/op_a/controls", json={"enabled": True})
    async_client = Mock()
    async_client.put = AsyncMock(return_value=plan)
    assert asyncio.run(AsyncPartnerAccountsService(async_client).set_controls("op_a", False)) == plan
    async_client.put.assert_awaited_once_with("/v1/partner/accounts/op_a/controls", json={"enabled": False})


def test_async_release_and_rotate_key():
    record = {"account_id": "op_a", "status": "pending"}
    client = Mock()
    client.post = AsyncMock(side_effect=[{"release": record}, {"account_id": "op_a", "api_key": "k"}])
    service = AsyncPartnerAccountsService(client)
    assert asyncio.run(service.release("op_a")) == record
    assert asyncio.run(service.rotate_key("op_a")) == {"account_id": "op_a", "api_key": "k"}
    client.post.assert_awaited_with("/v1/partner/accounts/op_a/rotate-key", json={})
