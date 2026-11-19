"""Async ChatChannelsService mirror: bind the chat identities an owner approves held payments from."""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from ..client import AsyncHttpClient


def _seg(value: str) -> str:
    return quote(value, safe="")


class AsyncChatChannelsService:
    def __init__(self, client: AsyncHttpClient):
        self._client = client

    async def get(self) -> dict[str, Any]:
        """``{channels, identities, code_attempts}``; see ``ChatChannelsService.get``."""
        return cast("dict[str, Any]", await self._client.get("/v1/chat-channels"))

    async def create_identity(self, channel: str, *, phone: str | None = None) -> dict[str, Any]:
        """Start binding an identity. ``channel``: telegram, sms or slack. ``phone`` (E.164) goes with sms only."""
        body: dict[str, Any] = {"channel": channel}
        if phone is not None:
            body["phone"] = phone
        return cast("dict[str, Any]", await self._client.post("/v1/chat-channels/identities", json=body))

    async def verify_identity(self, identity_id: str, code: str) -> dict[str, Any]:
        """The six-digit code texted to a number. Dashboard session only."""
        path = f"/v1/chat-channels/identities/{_seg(identity_id)}/verify"
        return cast("dict[str, Any]", await self._client.post(path, json={"code": code}))

    async def confirm_identity(self, identity_id: str) -> dict[str, Any]:
        """Confirm an identity the chat proved. Dashboard session only."""
        path = f"/v1/chat-channels/identities/{_seg(identity_id)}/confirm"
        return cast("dict[str, Any]", await self._client.post(path, json={}))

    async def remove_identity(self, identity_id: str) -> None:
        """End an identity at once."""
        await self._client.delete(f"/v1/chat-channels/identities/{_seg(identity_id)}")

    async def slack_install_url(self, redirect_uri: str, state: str) -> dict[str, Any]:
        """``{"url": ...}``: where the workspace's admin installs STACK's Slack app."""
        params = {"redirect_uri": redirect_uri, "state": state}
        return cast("dict[str, Any]", await self._client.get("/v1/chat-channels/slack/install-url", params=params))

    async def install_slack(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Exchange the code Slack sent back for the workspace's token. Dashboard session only."""
        body = {"code": code, "redirect_uri": redirect_uri}
        return cast("dict[str, Any]", await self._client.post("/v1/chat-channels/slack/install", json=body))

    async def remove_slack(self) -> None:
        """Uninstall the workspace; the Slack identities bound through it end."""
        await self._client.delete("/v1/chat-channels/slack")
