"""What the customer's controls do with flagged content.

Content the detectors flag in what reaches the customer's agents (mail, texts, voicemail, page text, tool output,
drive files, memory writes) is withheld from the agent or delivered with its flag, separately for a ``warning`` and a
``critical`` verdict: ``withhold`` (the default for both) or ``deliver``. With controls off flagged content is always
delivered with its flag. Owner or admin only; an agent is refused. A change applies at once, with no approval, and
is recorded.
"""

from __future__ import annotations

from typing import Any, cast

from .client import HttpClient

FLAGGED_CONTENT_HANDLINGS = ("withhold", "deliver")


def flagged_content_body(warning: str | None, critical: str | None) -> dict[str, str]:
    """The change to send; refuses one that names no severity, or an unknown value, before any request."""
    body: dict[str, str] = {}
    for name, value in (("warning", warning), ("critical", critical)):
        if value is None:
            continue
        if value not in FLAGGED_CONTENT_HANDLINGS:
            raise ValueError(f"{name} must be withhold or deliver")
        body[name] = value
    if not body:
        raise ValueError("name warning, critical or both")
    return body


class FlaggedContentService:
    def __init__(self, client: HttpClient):
        self._client = client

    def get(self) -> dict[str, Any]:
        """The setting in force: ``{warning, critical, controls}``; ``controls`` says whether it applies now."""
        return cast("dict[str, Any]", self._client.get("/v1/flagged-content/settings"))

    def set(self, *, warning: str | None = None, critical: str | None = None) -> dict[str, Any]:
        """Change one severity or both (``withhold`` or ``deliver``); one left out keeps its value."""
        return cast(
            "dict[str, Any]",
            self._client.put("/v1/flagged-content/settings", json=flagged_content_body(warning, critical)),
        )
