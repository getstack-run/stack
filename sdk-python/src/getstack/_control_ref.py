"""A client scoped to one approved retry: the same services, each sending ``X-Control-Ref``."""

from __future__ import annotations

import copy
from typing import Any, TypeVar

_S = TypeVar("_S")


def _rebind(value: Any, old: Any, new: Any, memo: dict[int, Any]) -> Any:
    """``value`` with every reference to the client ``old`` replaced by ``new``, copying only what holds one."""
    if value is old:
        return new
    # Only this package's own service objects are walked; a dict, a list or a foreign object is left as it is.
    if not type(value).__module__.startswith("getstack") or not hasattr(value, "__dict__"):
        return value
    key = id(value)
    if key in memo:
        return memo[key]
    clone = copy.copy(value)
    memo[key] = clone
    for name, attribute in list(vars(clone).items()):
        replaced = _rebind(attribute, old, new, memo)
        if replaced is not attribute:
            setattr(clone, name, replaced)
    return clone


def scoped_stack(stack: _S, ref: str) -> _S:
    """A copy of ``stack`` (``Stack`` or ``AsyncStack``) whose every service sends ``X-Control-Ref: <ref>``.

    The copy shares the connection and the credential with ``stack`` (closing either closes both), and ``stack`` itself
    is unchanged.
    """
    old = stack._client  # type: ignore[attr-defined]
    new = old.with_control_ref(ref)
    scoped = copy.copy(stack)
    memo: dict[int, Any] = {}
    for name, attribute in list(vars(scoped).items()):
        setattr(scoped, name, new if attribute is old else _rebind(attribute, old, new, memo))
    return scoped
