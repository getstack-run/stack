from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable

from .agent_auth import _b64url_no_pad, _generate_keypair, _key_path, _load_stored, _persist_stored, _privkey_from_jwk


def prepare_fleet_key(policy_id: str, idempotency_key: str) -> tuple[str, Callable[[str], str], Callable[[str], None]]:
    key_id = (
        "fleet_" + hashlib.sha256(json.dumps([policy_id, idempotency_key], separators=(",", ":")).encode()).hexdigest()
    )
    stored = _load_stored(key_id)
    if stored is None:
        _, public_key, private_key = _generate_keypair()
        candidate = {"agent_id": key_id, "publicKey": public_key, "privateKey": private_key, "enrolled_at": time.time()}
        path = _key_path(key_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w", encoding="utf8") as stream:
                json.dump(candidate, stream)
        except FileExistsError:
            pass
        stored = _load_stored(key_id)
        for _ in range(20):
            if stored is not None:
                break
            time.sleep(0.025)
            stored = _load_stored(key_id)
    if stored is None:
        raise ValueError("Invalid input")
    key = _privkey_from_jwk(stored["privateKey"])

    def sign(challenge: str) -> str:
        return _b64url_no_pad(key.sign(challenge.encode()))

    def persist(agent_id: str) -> None:
        if not re.fullmatch(r"agt_[\w-]+", agent_id):
            raise ValueError("Invalid input")
        _persist_stored(agent_id, {**stored, "agent_id": agent_id})

    return stored["publicKey"], sign, persist
