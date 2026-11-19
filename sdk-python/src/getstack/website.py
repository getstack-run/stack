"""An agent account's website: one site per agent, built and updated by the account's agent.

The agent publishes a bundle (every file, and optionally one server module) and the publish scan checks it
first: a refusal raises ``WebsitePublishRejectedError`` with each finding and nothing goes live. Publishing the
same bundle again returns the live deploy and changes nothing. The owner suspends a site in one call; an agent
can neither suspend nor resume its own site.

Calls the agent makes (``publish``, ``add_hostname``, ``remove_hostname``, ``set_prices``) require its Passport
as ``passport_token``, sent as ``X-Passport-Token``, and refuse an empty one before any request. Reads and
``check_hostname`` take it optionally; the owner's calls take none.

Example::

    files = site_files([{"path": "/index.html", "content": "<h1>Hello</h1>"}])
    deploy = stack.website.publish(account_id, files=files, passport_token=token)
    print(stack.website.get(account_id)["url"])
"""

from __future__ import annotations

import base64
import builtins
from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


def _seg(value: str) -> str:
    return quote(value, safe="")


def _site(account_id: str) -> str:
    return f"/v1/accounts/{_seg(account_id)}/website"


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _agent_passport(passport_token: str) -> dict[str, str]:
    if not isinstance(passport_token, str) or not passport_token:
        raise ValueError("passport_token is required: the account's agent does this, under its Passport")
    return {"X-Passport-Token": passport_token}


def _text_of(content: bytes) -> str | None:
    """The text of ``content`` when it is valid UTF-8 with no NUL byte, else ``None``."""
    if b"\x00" in content:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def site_files(entries: builtins.list[dict[str, Any]]) -> builtins.list[dict[str, str]]:
    """Build the ``files`` of a publish from ``{"path": ..., "content": str | bytes}`` entries.

    Text is sent as ``content``; bytes are sent as ``content`` too when they are UTF-8 text, and as
    ``content_base64`` otherwise. Raises ``ValueError`` for an empty list or a repeated path; the API
    checks the rest (a site has no limit on its number of files).
    """
    if not entries:
        raise ValueError("a site needs at least one file")
    seen: set[str] = set()
    files: builtins.list[dict[str, str]] = []
    for entry in entries:
        path = entry["path"]
        if path in seen:
            raise ValueError(f"the path {path} is in the bundle twice")
        seen.add(path)
        content = entry["content"]
        if isinstance(content, str):
            files.append({"path": path, "content": content})
            continue
        text = _text_of(bytes(content))
        if text is not None:
            files.append({"path": path, "content": text})
        else:
            files.append({"path": path, "content_base64": base64.b64encode(bytes(content)).decode("ascii")})
    return files


class WebsiteService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The account's site: addresses, live deploy, prices and limits.

        The empty site is created on the first read.
        """
        return cast("dict[str, Any]", self._client.get(_site(account_id), extra_headers=_passport(passport_token)))

    def publish(
        self,
        account_id: str,
        *,
        files: builtins.list[dict[str, str]],
        server: dict[str, str] | None = None,
        passport_token: str,
    ) -> dict[str, Any]:
        """Publish a bundle; it becomes the live site once the scan passes.

        ``files`` is one or more entries of ``{"path", "content"}`` or ``{"path", "content_base64"}`` (see
        ``site_files``); ``server`` is ``{"source": "<one JavaScript module with a default export>"}``. One
        metered action and a decision for the customer's controls. Raises ``WebsitePublishRejectedError``,
        ``WebsiteLimitExceededError`` or ``WebsiteSuspendedError``.
        """
        headers = _agent_passport(passport_token)
        body: dict[str, Any] = {"files": files}
        if server is not None:
            body["server"] = server
        return cast(
            "dict[str, Any]", self._client.post(f"{_site(account_id)}/deploys", json=body, extra_headers=headers)
        )

    def list_deploys(
        self, account_id: str, *, limit: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """The recent deploys, newest first: ``{"deploys": [...]}``. ``limit`` is 1 to 50."""
        params = {"limit": str(limit)} if limit is not None else None
        return cast(
            "dict[str, Any]",
            self._client.get(f"{_site(account_id)}/deploys", params=params, extra_headers=_passport(passport_token)),
        )

    def get_deploy(self, account_id: str, deploy_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.get(f"{_site(account_id)}/deploys/{_seg(deploy_id)}", extra_headers=_passport(passport_token)),
        )

    def add_hostname(self, account_id: str, *, hostname: str, passport_token: str) -> dict[str, Any]:
        """Add the customer's own domain. It starts ``pending``; ``dns`` lists what the customer sets at their DNS
        provider and ``check_hostname`` moves it to ``active`` once it resolves."""
        headers = _agent_passport(passport_token)
        return cast(
            "dict[str, Any]",
            self._client.post(f"{_site(account_id)}/hostnames", json={"hostname": hostname}, extra_headers=headers),
        )

    def list_hostnames(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._client.get(f"{_site(account_id)}/hostnames", extra_headers=_passport(passport_token)),
        )

    def check_hostname(self, account_id: str, hostname_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Check the domain's DNS and certificate now. The owner or the agent."""
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"{_site(account_id)}/hostnames/{_seg(hostname_id)}/check", extra_headers=_passport(passport_token)
            ),
        )

    def remove_hostname(self, account_id: str, hostname_id: str, *, passport_token: str) -> None:
        """Stop serving the site on a domain and release the name."""
        headers = _agent_passport(passport_token)
        self._client.delete(f"{_site(account_id)}/hostnames/{_seg(hostname_id)}", extra_headers=headers)

    def set_prices(
        self, account_id: str, *, prices: builtins.list[dict[str, str]], passport_token: str
    ) -> dict[str, Any]:
        """Set the paths that cost USDC to read; the list replaces the set (empty removes every price).

        Each entry is ``{"path", "price_usdc", "description"?}``; ``path`` is exact or a prefix ending in
        ``/*`` and ``price_usdc`` a decimal string such as ``"0.25"``.
        """
        headers = _agent_passport(passport_token)
        return cast(
            "dict[str, Any]",
            self._client.put(f"{_site(account_id)}/prices", json={"prices": prices}, extra_headers=headers),
        )

    def get_prices(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]", self._client.get(f"{_site(account_id)}/prices", extra_headers=_passport(passport_token))
        )

    def suspend(self, account_id: str, *, reason: str) -> dict[str, Any]:
        """Take the site offline now. Owner or admin only; an agent is refused. ``reason`` is 3 to 500 characters."""
        return cast("dict[str, Any]", self._client.post(f"{_site(account_id)}/suspension", json={"reason": reason}))

    def resume(self, account_id: str) -> dict[str, Any]:
        """Bring the site back after your own suspension. A suspension by STACK is not lifted this way."""
        return cast("dict[str, Any]", self._client.delete(f"{_site(account_id)}/suspension"))

    def suspend_all(self, *, reason: str) -> dict[str, Any]:
        """Suspend every site of your account at once: ``{"suspended": <count>}``."""
        return cast("dict[str, Any]", self._client.post("/v1/websites/suspend-all", json={"reason": reason}))

    def report(self, url: str, category: str, description: str, *, reporter_email: str | None = None) -> dict[str, Any]:
        """Report a page on a STACK-hosted site. Anyone may: it needs no account and sends no credential.

        ``category`` is phishing, impersonation, malware, illegal_content, copyright, spam or other; ``description`` is
        10 to 2000 characters. The answer is the same whether or not the address is one STACK hosts.
        """
        body: dict[str, Any] = {"url": url, "category": category, "description": description}
        if reporter_email is not None:
            body["reporter_email"] = reporter_email
        return cast("dict[str, Any]", self._client.post_public("/v1/public/site-reports", json=body))
