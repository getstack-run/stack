"""Chat channels: approving a held payment from Telegram, a text or Slack.

A policy can hold a card purchase or a wallet payment for a person. If you set both chat limits in the
policy (``review.chat``: ``max_per_payment_cents`` and ``max_per_day_cents``; there is no default, so it is
off until you do), the owner can answer from a chat they have bound, and only for a payment within those
limits. Above them, or with no limits, the approval page in a signed-in browser is the only way. Every chat
answer comes from the owner's own verified chat identity, is single-use, is bound to the exact payment and
amount, expires in ten minutes, and is recorded in the signed record with its channel (``decided_via``:
``chat_telegram``, ``chat_sms`` or ``chat_slack``).

Binding an identity is the owner's own act in their own browser. Telegram and Slack: ``create_identity``
returns a link or a slash command to carry into the chat, then ``confirm_identity`` in the console. Text:
``create_identity`` with a phone number texts a code, typed with ``verify_identity`` in the console.
``verify_identity``, ``confirm_identity`` and ``install_slack`` need a signed-in dashboard session: an API
key, a CLI or an OAuth token gets a 403, and so does starting a text binding. Nothing here is metered.

Anyone who controls the bound number or chat account can answer, so keep the limits small.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


def _seg(value: str) -> str:
    return quote(value, safe="")


class ChatChannelsService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self) -> dict[str, Any]:
        """``{channels, identities, code_attempts}``: which channels this deployment has, and the identities bound."""
        return cast("dict[str, Any]", self._client.get("/v1/chat-channels"))

    def create_identity(self, channel: str, *, phone: str | None = None) -> dict[str, Any]:
        """Start binding an identity. ``channel``: telegram, sms or slack. ``phone`` (E.164) goes with sms and only sms.

        The response's ``link`` (on creation only) carries a Telegram ``url`` to open and press Start in, or a
        Slack ``command`` to send in the workspace STACK is installed in.
        """
        body: dict[str, Any] = {"channel": channel}
        if phone is not None:
            body["phone"] = phone
        return cast("dict[str, Any]", self._client.post("/v1/chat-channels/identities", json=body))

    def verify_identity(self, identity_id: str, code: str) -> dict[str, Any]:
        """The six-digit code texted to a number. Dashboard session only."""
        path = f"/v1/chat-channels/identities/{_seg(identity_id)}/verify"
        return cast("dict[str, Any]", self._client.post(path, json={"code": code}))

    def confirm_identity(self, identity_id: str) -> dict[str, Any]:
        """Confirm an identity the chat proved. Dashboard session only."""
        path = f"/v1/chat-channels/identities/{_seg(identity_id)}/confirm"
        return cast("dict[str, Any]", self._client.post(path, json={}))

    def remove_identity(self, identity_id: str) -> None:
        """End an identity at once. It only narrows who can approve, so any admin credential may."""
        self._client.delete(f"/v1/chat-channels/identities/{_seg(identity_id)}")

    def slack_install_url(self, redirect_uri: str, state: str) -> dict[str, Any]:
        """``{"url": ...}``: where the workspace's admin installs STACK's Slack app. ``state`` is yours."""
        params = {"redirect_uri": redirect_uri, "state": state}
        return cast("dict[str, Any]", self._client.get("/v1/chat-channels/slack/install-url", params=params))

    def install_slack(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Exchange the code Slack sent back for the workspace's token. Dashboard session only."""
        body = {"code": code, "redirect_uri": redirect_uri}
        return cast("dict[str, Any]", self._client.post("/v1/chat-channels/slack/install", json=body))

    def remove_slack(self) -> None:
        """Uninstall the workspace; the Slack identities bound through it end."""
        self._client.delete("/v1/chat-channels/slack")
