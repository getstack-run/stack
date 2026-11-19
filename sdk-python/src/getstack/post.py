"""Post for agent accounts: one US street address per customer that receives and
scans post (mailbox.bot), and letters and postcards out (Lob or PostGrid).

The address is the customer's own. The customer signs up at the supplier,
completes USPS Form 1583 there (two IDs and a short notary video call; STACK
never sees the documents), creates an agent key there and gives it to
``connect_address``. Each agent has its own ATTN line on the shared address,
and post goes to the agent whose line is on the envelope. Received post and
scans arrive as account messages of channel ``post``.

A scan, forward or shred is proposed at the supplier and approved by the owner
there, who is billed by the supplier. A letter or postcard is held and charged
on the account's credit at the provider's cost. The owner calls without a
Passport; the account's agent passes ``passport_token`` (sent as
``X-Passport-Token``).

Example::

    stack.post.start_address()          # the owner's steps at the supplier come next
    letter = stack.post.send(
        account_id,
        {"to": {"name": "Pat Doe", "line1": "1 Main St", "city": "Reno", "state": "NV", "postal_code": "89501"},
         "sender_name": "Acme Dental",
         "content": {"text": "Your order has shipped."},
         "use_type": "operational"},
        passport_token=agent_passport,
    )
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient


def _seg(value: str) -> str:
    return quote(value, safe="")


def _account_post(account_id: str) -> str:
    return f"/v1/accounts/{_seg(account_id)}/post"


def _headers(passport_token: str | None, idempotency_key: str | None = None) -> dict[str, str] | None:
    headers: dict[str, str] = {}
    if passport_token:
        headers["X-Passport-Token"] = passport_token
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    return headers or None


def _page_params(limit: int | None, cursor: str | None, routing: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if cursor is not None:
        params["cursor"] = cursor
    if routing is not None:
        params["routing"] = routing
    return params


def _send_input(letter: dict[str, Any]) -> dict[str, Any]:
    """Refuse a send that does not say what the mail is, before any request."""
    if letter.get("use_type") not in ("operational", "marketing"):
        raise ValueError("use_type is required: operational or marketing")
    return letter


class PostService:
    def __init__(self, client: HttpClient):
        self._client = client

    def _call(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        kwargs: dict[str, Any] = {}
        if json is not None:
            kwargs["json"] = json
        if params:
            kwargs["params"] = params
        if headers:
            kwargs["extra_headers"] = headers
        return self._client.request(method, path, **kwargs)

    # The customer's street address (owner or admin).

    def get_address(self) -> dict[str, Any]:
        """What the address is and what it waits for. A 404 before the owner starts one."""
        return cast("dict[str, Any]", self._call("GET", "/v1/post/address"))

    def start_address(self) -> dict[str, Any]:
        """Start the address; the customer's own steps at the supplier come next (``identity.url``)."""
        return cast("dict[str, Any]", self._call("POST", "/v1/post/address", json={}))

    def connect_address(self, api_key: str, *, webhook_secret: str | None = None) -> dict[str, Any]:
        """Hand over the agent key the customer created at the supplier.

        The key is a secret: read it from a vault or stdin, never a literal. It is never returned.
        ``webhook_secret`` is the ``whsec_`` secret of the webhook endpoint created at the supplier.
        """
        body: dict[str, Any] = {"api_key": api_key}
        if webhook_secret is not None:
            body["webhook_secret"] = webhook_secret
        return cast("dict[str, Any]", self._call("POST", "/v1/post/address/connect", json=body))

    def refresh_address(self) -> dict[str, Any]:
        """Look at the supplier again now."""
        return cast("dict[str, Any]", self._call("POST", "/v1/post/address/refresh", json={}))

    def pause_address(self) -> dict[str, Any]:
        return cast("dict[str, Any]", self._call("POST", "/v1/post/address/pause", json={}))

    def resume_address(self) -> dict[str, Any]:
        """Lifts the owner's own pause; an unpaid or supplier suspension is not the owner's to lift."""
        return cast("dict[str, Any]", self._call("POST", "/v1/post/address/resume", json={}))

    def close_address(self) -> dict[str, Any]:
        """Disconnect: STACK forgets the supplier key and the mailbox's own details (address, private mailbox number,
        ids).

        The mailbox at the supplier is untouched and every item and scan already received stays.
        """
        return cast("dict[str, Any]", self._call("DELETE", "/v1/post/address"))

    def list_items(
        self, *, limit: int | None = None, cursor: str | None = None, routing: str | None = None
    ) -> dict[str, Any]:
        """Every item at the address: ``{"items": [...], "next_cursor": ...}``.

        ``routing``: routed, pending or unassigned (an item that names no agent is offered to every agent of the account
        until one takes it).
        """
        return cast("dict[str, Any]", self._call("GET", "/v1/post/items", params=_page_params(limit, cursor, routing)))

    def assign_item(self, item_id: str, account_id: str) -> dict[str, Any]:
        """Give an item that no agent has taken to an account."""
        return cast(
            "dict[str, Any]",
            self._call("POST", f"/v1/post/items/{_seg(item_id)}/assign", json={"account_id": account_id}),
        )

    # An account's post.

    def account_address(self, account_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """The agent's own line on the address, to print on a form."""
        return cast(
            "dict[str, Any]",
            self._call("GET", f"{_account_post(account_id)}/address", headers=_headers(passport_token)),
        )

    def list_account_items(
        self,
        account_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._call(
                "GET",
                f"{_account_post(account_id)}/items",
                params=_page_params(limit, cursor),
                headers=_headers(passport_token),
            ),
        )

    def get_account_item(self, account_id: str, item_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._call("GET", f"{_account_post(account_id)}/items/{_seg(item_id)}", headers=_headers(passport_token)),
        )

    def scan_item(
        self,
        account_id: str,
        item_id: str,
        *,
        capture: str | None = None,
        idempotency_key: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Ask the supplier to open and scan an item. ``capture``: document_pdf (default), contents_photos or both.

        The owner approves at the supplier; the text then arrives as a message of the account.
        """
        body: dict[str, Any] = {} if capture is None else {"capture": capture}
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"{_account_post(account_id)}/items/{_seg(item_id)}/scan",
                json=body,
                headers=_headers(passport_token, idempotency_key),
            ),
        )

    def forward_item(
        self,
        account_id: str,
        item_id: str,
        destination: dict[str, Any],
        *,
        mail_class: str | None = None,
        idempotency_key: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Ask the supplier to forward an item inside the US."""
        body: dict[str, Any] = {"destination": destination}
        if mail_class is not None:
            body["mail_class"] = mail_class
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"{_account_post(account_id)}/items/{_seg(item_id)}/forward",
                json=body,
                headers=_headers(passport_token, idempotency_key),
            ),
        )

    def shred_item(
        self,
        account_id: str,
        item_id: str,
        *,
        idempotency_key: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Ask the supplier to shred an item. It cannot be undone, so the request says it knows."""
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"{_account_post(account_id)}/items/{_seg(item_id)}/shred",
                json={"confirm": True},
                headers=_headers(passport_token, idempotency_key),
            ),
        )

    def check_address(
        self, account_id: str, address: dict[str, Any], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Whether an address is deliverable, and the address as the provider standardises it."""
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"{_account_post(account_id)}/address-check",
                json={"address": address},
                headers=_headers(passport_token),
            ),
        )

    def send(self, account_id: str, letter: dict[str, Any], *, passport_token: str | None = None) -> dict[str, Any]:
        """Send a letter (text or PDF) or a postcard (``kind: "postcard"``, text on front and back).

        ``letter`` takes ``to``, ``sender_name`` (required: the name printed as the sender, up to 40 characters),
        ``use_type`` (required: ``operational`` or ``marketing``) and the content: ``content`` as
        ``{"text": ...}`` or ``{"pdf_base64": ...}`` for a letter, ``front`` and ``back`` as ``{"text": ...}`` for a
        postcard. ``return_address`` is optional, a US address in the same form as ``to``: the sender address
        printed on the letter. Without it, the account's street address is used. Returned post goes to this address.
        Refused, with nothing held: an undeliverable address (the recipient's or the return address), a return
        address outside the US, or no return address and no live street address (``POSTAL_ADDRESS_NOT_ACTIVE``).
        """
        return cast(
            "dict[str, Any]",
            self._call(
                "POST",
                f"{_account_post(account_id)}/letters",
                json=_send_input(letter),
                headers=_headers(passport_token),
            ),
        )

    def list_letters(
        self,
        account_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._call(
                "GET",
                f"{_account_post(account_id)}/letters",
                params=_page_params(limit, cursor),
                headers=_headers(passport_token),
            ),
        )

    def get_letter(self, account_id: str, letter_id: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One letter with its tracking events."""
        return cast(
            "dict[str, Any]",
            self._call(
                "GET", f"{_account_post(account_id)}/letters/{_seg(letter_id)}", headers=_headers(passport_token)
            ),
        )
