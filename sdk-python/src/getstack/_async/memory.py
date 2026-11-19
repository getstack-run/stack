"""Async account memory: the awaitable mirror of ``getstack.memory``."""

from __future__ import annotations

from typing import Any, cast

from ..client import AsyncHttpClient
from ..memory import (
    _passport,
    _put,
    _seg,
    add_memory_body,
    add_triplet_body,
    create_entity_type_body,
    episode_entities_body,
    saga_body,
    search_memory_facts_body,
    search_nodes_body,
    settings_body,
    update_entity_type_body,
)


class AsyncMemoryService:
    """What the account's agents know, as a graph of facts with the time each held. See ``MemoryService``."""

    def __init__(self, client: AsyncHttpClient):
        self._client = client

    # ─── writing ────────────────────────────────────────────────────

    async def add_memory(
        self,
        name: str,
        episode_body: str,
        *,
        source: str | None = None,
        source_description: str | None = None,
        uuid: str | None = None,
        reference_time: str | None = None,
        excluded_entity_types: list[str] | None = None,
        custom_extraction_instructions: str | None = None,
        previous_episode_uuids: list[str] | None = None,
        saga: str | None = None,
        saga_previous_episode_uuid: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Add an episode. One metered action. ``{"message", "uuid", "status": "queued"}`` at once."""
        body = add_memory_body(
            name,
            episode_body,
            source=source,
            source_description=source_description,
            uuid=uuid,
            reference_time=reference_time,
            excluded_entity_types=excluded_entity_types,
            custom_extraction_instructions=custom_extraction_instructions,
            previous_episode_uuids=previous_episode_uuids,
            saga=saga,
            saga_previous_episode_uuid=saga_previous_episode_uuid,
        )
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/memory/episodes", json=body, extra_headers=_passport(passport_token)),
        )

    async def add_triplet(
        self,
        source_node_name: str,
        edge_name: str,
        fact: str,
        target_node_name: str,
        *,
        source_node_uuid: str | None = None,
        target_node_uuid: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Write one fact directly, without extraction. One metered action."""
        body = add_triplet_body(
            source_node_name,
            edge_name,
            fact,
            target_node_name,
            source_node_uuid=source_node_uuid,
            target_node_uuid=target_node_uuid,
        )
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/memory/triplets", json=body, extra_headers=_passport(passport_token)),
        )

    async def summarize_saga(self, saga_name: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Make or refresh the running summary of a saga. Metered."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                "/v1/memory/sagas/summary", json=saga_body(saga_name), extra_headers=_passport(passport_token)
            ),
        )

    # ─── reading ────────────────────────────────────────────────────

    async def search_nodes(
        self,
        query: str,
        *,
        max_nodes: int | None = None,
        entity_types: list[str] | None = None,
        center_node_uuid: str | None = None,
        field_filters: list[dict[str, Any]] | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The graph's entities. Free. ``field_filters``: see the sync client's ``search_nodes``."""
        body = search_nodes_body(
            query,
            max_nodes=max_nodes,
            entity_types=entity_types,
            center_node_uuid=center_node_uuid,
            field_filters=field_filters,
        )
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/memory/nodes/search", json=body, extra_headers=_passport(passport_token)),
        )

    async def search_memory_facts(
        self,
        query: str,
        *,
        max_facts: int | None = None,
        center_node_uuid: str | None = None,
        edge_types: list[str] | None = None,
        valid_at_after: str | None = None,
        valid_at_before: str | None = None,
        invalid_at_after: str | None = None,
        invalid_at_before: str | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """The graph's facts, each with when it held. Free."""
        body = search_memory_facts_body(
            query,
            max_facts=max_facts,
            center_node_uuid=center_node_uuid,
            edge_types=edge_types,
            valid_at_after=valid_at_after,
            valid_at_before=valid_at_before,
            invalid_at_after=invalid_at_after,
            invalid_at_before=invalid_at_before,
        )
        return cast(
            "dict[str, Any]",
            await self._client.post("/v1/memory/facts/search", json=body, extra_headers=_passport(passport_token)),
        )

    async def get_episodes(
        self, *, max_episodes: int | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Episodes, newest first, each with its ``status``. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.get(
                "/v1/memory/episodes",
                params=_put({}, max_episodes=max_episodes) or None,
                extra_headers=_passport(passport_token),
            ),
        )

    async def get_entity_edge(self, uuid: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One fact (entity edge) by its uuid. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.get(f"/v1/memory/facts/{_seg(uuid)}", extra_headers=_passport(passport_token)),
        )

    async def get_episode_entities(
        self, episode_uuids: list[str], *, passport_token: str | None = None
    ) -> dict[str, Any]:
        """What the given episodes produced. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                "/v1/memory/episode-entities",
                json=episode_entities_body(episode_uuids),
                extra_headers=_passport(passport_token),
            ),
        )

    # ─── deleting ───────────────────────────────────────────────────

    async def delete_episode(self, uuid: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Delete an episode. Entities and facts only this episode supports go with it. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.delete(f"/v1/memory/episodes/{_seg(uuid)}", extra_headers=_passport(passport_token)),
        )

    async def delete_entity_edge(self, uuid: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Delete a fact (entity edge). Free."""
        return cast(
            "dict[str, Any]",
            await self._client.delete(f"/v1/memory/facts/{_seg(uuid)}", extra_headers=_passport(passport_token)),
        )

    # ─── the account's own entity types ─────────────────────────────

    async def list_entity_types(self, *, passport_token: str | None = None) -> dict[str, Any]:
        """Graphiti's ten and the account's own entity types. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.get("/v1/memory/entity-types", extra_headers=_passport(passport_token)),
        )

    async def create_entity_type(
        self,
        name: str,
        description: str,
        *,
        fields: list[dict[str, Any]] | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Add a type of the account's own; later writes extract it beside the ten. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                "/v1/memory/entity-types",
                json=create_entity_type_body(name, description, fields),
                extra_headers=_passport(passport_token),
            ),
        )

    async def update_entity_type(
        self,
        name: str,
        *,
        description: str | None = None,
        fields: list[dict[str, Any]] | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Change a type: what is given replaces what was there. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.patch(
                f"/v1/memory/entity-types/{_seg(name)}",
                json=update_entity_type_body(description, fields),
                extra_headers=_passport(passport_token),
            ),
        )

    async def retire_entity_type(self, name: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Retire a type: no longer extracted; its entities keep their label. Free."""
        return cast(
            "dict[str, Any]",
            await self._client.delete(f"/v1/memory/entity-types/{_seg(name)}", extra_headers=_passport(passport_token)),
        )

    # ─── what each write changed, and undo ──────────────────────────

    async def get_history(
        self, *, max_writes: int | None = None, cursor: str | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """One page of the account's writes, newest first, with what each changed. Free.

        ``cursor`` is the ``next_cursor`` of the page before, to read the older writes.
        """
        return cast(
            "dict[str, Any]",
            await self._client.get(
                "/v1/memory/history",
                params=_put({}, max_writes=max_writes, cursor=cursor) or None,
                extra_headers=_passport(passport_token),
            ),
        )

    async def undo_write(
        self, write_id: str, *, dry_run: bool = False, passport_token: str | None = None
    ) -> dict[str, Any]:
        """Undo a write with every later write that changed the same things; ``dry_run`` only says what."""
        return cast(
            "dict[str, Any]",
            await self._client.post(
                f"/v1/memory/writes/{_seg(write_id)}/undo",
                json={"dry_run": dry_run},
                extra_headers=_passport(passport_token),
            ),
        )

    # ─── the owner: on or off ───────────────────────────────────────

    async def get_settings(self) -> dict[str, Any]:
        """Owner only: ``{"enabled", "call_memory_access", "updated_at"}``."""
        return cast("dict[str, Any]", await self._client.get("/v1/memory/settings"))

    async def update_settings(
        self, *, enabled: bool | None = None, call_memory_access: bool | None = None
    ) -> dict[str, Any]:
        """Owner or admin only; see ``MemoryService.update_settings``."""
        return cast(
            "dict[str, Any]",
            await self._client.put("/v1/memory/settings", json=settings_body(enabled, call_memory_access)),
        )
