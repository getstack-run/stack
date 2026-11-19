"""Evidence-pack download SDK coverage."""

from __future__ import annotations

import asyncio

from getstack._async.evidence_packs import AsyncEvidencePacksService
from getstack.evidence_packs import EvidencePacksService


class StubHttpClient:
    def __init__(self, body: bytes):
        self.body = body
        self.calls: list[tuple[str, str]] = []

    def request_bytes(self, method: str, path: str) -> bytes:
        self.calls.append((method, path))
        return self.body

    def request(self, method: str, path: str) -> dict[str, str]:
        self.calls.append((method, path))
        return {"pack_id": "pck_exact"}


class StubAsyncHttpClient:
    def __init__(self, body: bytes):
        self.body = body
        self.calls: list[tuple[str, str]] = []

    async def request_bytes(self, method: str, path: str) -> bytes:
        self.calls.append((method, path))
        return self.body

    async def request(self, method: str, path: str) -> dict[str, str]:
        self.calls.append((method, path))
        return {"pack_id": "pck_exact"}


def test_sync_download_returns_exact_bytes() -> None:
    expected = b'{"pack_id":"evp_exact"}\n'
    client = StubHttpClient(expected)
    service = EvidencePacksService(client)  # type: ignore[arg-type]

    assert service.download("pck_exact/value") == expected
    assert client.calls == [("GET", "/v1/evidence-packs/pck_exact%2Fvalue/download")]


def test_async_download_returns_exact_bytes() -> None:
    expected = b'{"pack_id":"evp_exact"}\n'
    client = StubAsyncHttpClient(expected)
    service = AsyncEvidencePacksService(client)  # type: ignore[arg-type]

    assert asyncio.run(service.download("pck_exact/value")) == expected
    assert client.calls == [("GET", "/v1/evidence-packs/pck_exact%2Fvalue/download")]


def test_receipt_paths_encode_pack_ids() -> None:
    sync_client = StubHttpClient(b"")
    async_client = StubAsyncHttpClient(b"")

    assert EvidencePacksService(sync_client).get("pck_exact/value") == {"pack_id": "pck_exact"}  # type: ignore[arg-type]
    assert asyncio.run(AsyncEvidencePacksService(async_client).get("pck_exact/value")) == {"pack_id": "pck_exact"}  # type: ignore[arg-type]
    assert sync_client.calls == [("GET", "/v1/evidence-packs/pck_exact%2Fvalue")]
    assert async_client.calls == [("GET", "/v1/evidence-packs/pck_exact%2Fvalue")]
