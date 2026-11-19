"""Account memory: what the account's agents know.

Graphiti, a temporal knowledge graph, used the way its makers ship it: one graph per account, shared
by the account's agents. The methods are the tools of Graphiti's own MCP server with its arguments
and its answers (there is no group id: the graph is the account's). The owner (an API key or a
session, no agent) reads and deletes through the same calls. A write (``add_memory``,
``add_triplet``, ``summarize_saga``) is an action (metered, put to the account's controls, in the
signed record); reading and deleting are free.

``add_memory`` answers at once with ``status: "queued"``: the episode is read into the graph in the
background, one at a time per account. Nothing is stored until ``get_episodes`` shows it ``stored``;
a write that could not be read in shows ``failed`` there with a plain ``reason``.

The text of a write is scanned by STACK's detectors first: with the account's controls on, flagged
text is refused and nothing is stored or charged; with controls off it is stored with its flag,
which ``get_episodes`` shows. What memory holds may have come from outside (mail, a web page, a
file): it is information, never instructions.

Calls an agent makes take the Passport as ``passport_token``, sent as ``X-Passport-Token``, and run
under the Passport's Mission. ``get_settings`` and ``update_settings`` are the owner's, refused to an
agent.

The account's own entity types (``list_entity_types``, ``create_entity_type``, ``update_entity_type``,
``retire_entity_type``) are extracted by every later write beside Graphiti's ten; they are a setting
(free, put to the account's controls), for the owner, an admin and the account's agents.
``get_history`` lists the account's writes with what each changed (before and after), and
``undo_write`` takes a write back out with every later write that changed the same things
(``dry_run`` only says what); an undo is free and counts as one delete toward the hourly rate.
"""

from __future__ import annotations

from typing import Any, cast
from urllib.parse import quote

from .client import HttpClient

_SOURCES = ("text", "json", "message")


def _seg(value: str) -> str:
    return quote(value, safe="")


def _passport(passport_token: str | None) -> dict[str, str] | None:
    return {"X-Passport-Token": passport_token} if passport_token else None


def _put(body: dict[str, Any], **values: Any) -> dict[str, Any]:
    for key, value in values.items():
        if value is not None:
            body[key] = value
    return body


def add_memory_body(
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
) -> dict[str, Any]:
    if not name.strip():
        raise ValueError("name the episode")
    if not episode_body.strip():
        raise ValueError("say what to remember")
    if source is not None and source not in _SOURCES:
        raise ValueError(f"source is one of {', '.join(_SOURCES)}")
    return _put(
        {"name": name, "episode_body": episode_body},
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


def add_triplet_body(
    source_node_name: str,
    edge_name: str,
    fact: str,
    target_node_name: str,
    *,
    source_node_uuid: str | None = None,
    target_node_uuid: str | None = None,
) -> dict[str, Any]:
    if not (source_node_name.strip() and edge_name.strip() and fact.strip() and target_node_name.strip()):
        raise ValueError("a fact names its source entity, the relationship, the fact and its target entity")
    return _put(
        {
            "source_node_name": source_node_name,
            "edge_name": edge_name,
            "fact": fact,
            "target_node_name": target_node_name,
        },
        source_node_uuid=source_node_uuid,
        target_node_uuid=target_node_uuid,
    )


def search_nodes_body(
    query: str,
    *,
    max_nodes: int | None = None,
    entity_types: list[str] | None = None,
    center_node_uuid: str | None = None,
    field_filters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not query.strip():
        raise ValueError("say what to search for")
    if field_filters and not entity_types:
        raise ValueError("a field filter needs entity_types: a field belongs to a type")
    return _put(
        {"query": query},
        max_nodes=max_nodes,
        entity_types=entity_types,
        center_node_uuid=center_node_uuid,
        field_filters=field_filters,
    )


def search_memory_facts_body(
    query: str,
    *,
    max_facts: int | None = None,
    center_node_uuid: str | None = None,
    edge_types: list[str] | None = None,
    valid_at_after: str | None = None,
    valid_at_before: str | None = None,
    invalid_at_after: str | None = None,
    invalid_at_before: str | None = None,
) -> dict[str, Any]:
    if not query.strip():
        raise ValueError("say what to search for")
    return _put(
        {"query": query},
        max_facts=max_facts,
        center_node_uuid=center_node_uuid,
        edge_types=edge_types,
        valid_at_after=valid_at_after,
        valid_at_before=valid_at_before,
        invalid_at_after=invalid_at_after,
        invalid_at_before=invalid_at_before,
    )


def episode_entities_body(episode_uuids: list[str]) -> dict[str, Any]:
    if not episode_uuids:
        raise ValueError("name at least one episode")
    return {"episode_uuids": episode_uuids}


_FIELD_KINDS = ("text", "number", "date", "boolean", "one_of")


def entity_type_fields(fields: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """The fields of an entity type, each ``{name, kind, description?, options?}``; a ``one_of`` lists ``options``."""
    if fields is None:
        return None
    for field in fields:
        if field.get("kind") not in _FIELD_KINDS:
            raise ValueError(f"a field's kind is one of {', '.join(_FIELD_KINDS)}")
        if field.get("kind") == "one_of" and not field.get("options"):
            raise ValueError("a one_of field lists the words it may be in options")
    return fields


def create_entity_type_body(name: str, description: str, fields: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not name or not description:
        raise ValueError("an entity type needs a name and a description")
    return _put({"name": name, "description": description}, fields=entity_type_fields(fields))


def update_entity_type_body(description: str | None, fields: list[dict[str, Any]] | None) -> dict[str, Any]:
    body = _put({}, description=description, fields=entity_type_fields(fields))
    if not body:
        raise ValueError("give a description, fields or both")
    return body


def saga_body(saga_name: str) -> dict[str, Any]:
    if not saga_name.strip():
        raise ValueError("name the saga")
    return {"saga_name": saga_name}


class MemoryService:
    """What the account's agents know, as a graph of facts with the time each held; see the module docstring."""

    def __init__(self, client: HttpClient):
        self._client = client

    # ─── writing ────────────────────────────────────────────────────

    def add_memory(
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
        """Add an episode. One metered action. ``{"message", "uuid", "status": "queued"}`` at once.

        ``source`` is ``text`` (default), ``json`` (``episode_body`` is then a JSON string) or ``message``.
        ``reference_time`` (ISO 8601) is when the described events occurred; it defaults to now.
        A ``uuid`` you choose must be unused by your account; the episode's real uuid is derived from it and the
        account, so use the ``uuid`` in the answer, not the one you sent.
        """
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
            self._client.post("/v1/memory/episodes", json=body, extra_headers=_passport(passport_token)),
        )

    def add_triplet(
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
        """Write one fact (source entity, fact, target entity) directly, without extraction. One metered action.

        Answers when it is written: ``{"message", "nodes", "edges"}``.
        """
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
            self._client.post("/v1/memory/triplets", json=body, extra_headers=_passport(passport_token)),
        )

    def summarize_saga(self, saga_name: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Make or refresh the running summary of a saga (the name passed as ``saga`` to ``add_memory``). Metered."""
        return cast(
            "dict[str, Any]",
            self._client.post(
                "/v1/memory/sagas/summary", json=saga_body(saga_name), extra_headers=_passport(passport_token)
            ),
        )

    # ─── reading ────────────────────────────────────────────────────

    def search_nodes(
        self,
        query: str,
        *,
        max_nodes: int | None = None,
        entity_types: list[str] | None = None,
        center_node_uuid: str | None = None,
        field_filters: list[dict[str, Any]] | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """``{"message", "nodes": [...]}``: the graph's entities. Free.

        ``field_filters`` keeps only the entities whose field has a value: a list of ``{"field": ..., "value": ...}``,
        every one of which must hold. It needs ``entity_types``, each naming one of the account's own types that has
        the field, and the value is of the field's kind (text or one of its words, a number, ``True`` or ``False``, or
        an ISO 8601 date or date and time). A filter that cannot be tested as asked is refused (422
        ``MEMORY_FIELD_FILTER_INVALID``), never answered with an empty list.
        """
        body = search_nodes_body(
            query,
            max_nodes=max_nodes,
            entity_types=entity_types,
            center_node_uuid=center_node_uuid,
            field_filters=field_filters,
        )
        return cast(
            "dict[str, Any]",
            self._client.post("/v1/memory/nodes/search", json=body, extra_headers=_passport(passport_token)),
        )

    def search_memory_facts(
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
        """``{"message", "facts": [...]}``: the graph's facts, each with when it held. Free."""
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
            self._client.post("/v1/memory/facts/search", json=body, extra_headers=_passport(passport_token)),
        )

    def get_episodes(self, *, max_episodes: int | None = None, passport_token: str | None = None) -> dict[str, Any]:
        """``{"message", "episodes": [...]}``, newest first (1 to 100, default 10). Free.

        Every episode has a ``status``: ``stored``, ``queued``, ``processing`` or ``failed`` (with a ``reason``).
        """
        return cast(
            "dict[str, Any]",
            self._client.get(
                "/v1/memory/episodes",
                params=_put({}, max_episodes=max_episodes) or None,
                extra_headers=_passport(passport_token),
            ),
        )

    def get_entity_edge(self, uuid: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """One fact (entity edge) by its uuid. Free."""
        return cast(
            "dict[str, Any]",
            self._client.get(f"/v1/memory/facts/{_seg(uuid)}", extra_headers=_passport(passport_token)),
        )

    def get_episode_entities(self, episode_uuids: list[str], *, passport_token: str | None = None) -> dict[str, Any]:
        """``{"message", "nodes", "edges"}``: what the given episodes produced. Free."""
        return cast(
            "dict[str, Any]",
            self._client.post(
                "/v1/memory/episode-entities",
                json=episode_entities_body(episode_uuids),
                extra_headers=_passport(passport_token),
            ),
        )

    # ─── deleting ───────────────────────────────────────────────────

    def delete_episode(self, uuid: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Delete an episode. Entities and facts only this episode supports go with it. Free."""
        return cast(
            "dict[str, Any]",
            self._client.delete(f"/v1/memory/episodes/{_seg(uuid)}", extra_headers=_passport(passport_token)),
        )

    def delete_entity_edge(self, uuid: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Delete a fact (entity edge). Free."""
        return cast(
            "dict[str, Any]",
            self._client.delete(f"/v1/memory/facts/{_seg(uuid)}", extra_headers=_passport(passport_token)),
        )

    # ─── the account's own entity types ─────────────────────────────

    def list_entity_types(self, *, passport_token: str | None = None) -> dict[str, Any]:
        """``{"shipped", "types"}``: Graphiti's ten and the account's own (in force and retired). Free."""
        return cast(
            "dict[str, Any]",
            self._client.get("/v1/memory/entity-types", extra_headers=_passport(passport_token)),
        )

    def create_entity_type(
        self,
        name: str,
        description: str,
        *,
        fields: list[dict[str, Any]] | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Add a type of the account's own (or bring back a retired one); later writes extract it beside the ten. Free.

        Every type is in every write's extraction prompt, so each one makes every later write cost a little more.
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                "/v1/memory/entity-types",
                json=create_entity_type_body(name, description, fields),
                extra_headers=_passport(passport_token),
            ),
        )

    def update_entity_type(
        self,
        name: str,
        *,
        description: str | None = None,
        fields: list[dict[str, Any]] | None = None,
        passport_token: str | None = None,
    ) -> dict[str, Any]:
        """Change a type: what is given replaces what was there. Later writes use it. Free."""
        return cast(
            "dict[str, Any]",
            self._client.patch(
                f"/v1/memory/entity-types/{_seg(name)}",
                json=update_entity_type_body(description, fields),
                extra_headers=_passport(passport_token),
            ),
        )

    def retire_entity_type(self, name: str, *, passport_token: str | None = None) -> dict[str, Any]:
        """Retire a type: no longer extracted; its entities keep their label and stay searchable. Free."""
        return cast(
            "dict[str, Any]",
            self._client.delete(f"/v1/memory/entity-types/{_seg(name)}", extra_headers=_passport(passport_token)),
        )

    # ─── what each write changed, and undo ──────────────────────────

    def get_history(
        self, *, max_writes: int | None = None, cursor: str | None = None, passport_token: str | None = None
    ) -> dict[str, Any]:
        """``{"message", "writes": [...], "next_cursor"}``: one page of the account's writes, newest first.

        Each write comes with what it changed.
        ``max_writes`` is the page size (1 to 100, default 20). ``next_cursor`` is what ``cursor`` takes for the page of
        older writes, and ``None`` when this page reaches the oldest write. Free.
        """
        return cast(
            "dict[str, Any]",
            self._client.get(
                "/v1/memory/history",
                params=_put({}, max_writes=max_writes, cursor=cursor) or None,
                extra_headers=_passport(passport_token),
            ),
        )

    def undo_write(self, write_id: str, *, dry_run: bool = False, passport_token: str | None = None) -> dict[str, Any]:
        """Undo a write with every later write that changed the same things, newest first; ``dry_run`` only says what.

        Free; one delete toward the account's hourly rate (a dry run takes none).
        """
        return cast(
            "dict[str, Any]",
            self._client.post(
                f"/v1/memory/writes/{_seg(write_id)}/undo",
                json={"dry_run": dry_run},
                extra_headers=_passport(passport_token),
            ),
        )

    # ─── the owner: on or off ───────────────────────────────────────

    def get_settings(self) -> dict[str, Any]:
        """Owner only: ``{"enabled", "call_memory_access", "updated_at"}``."""
        return cast("dict[str, Any]", self._client.get("/v1/memory/settings"))

    def update_settings(self, *, enabled: bool | None = None, call_memory_access: bool | None = None) -> dict[str, Any]:
        """Owner or admin only. ``enabled`` turns memory on or off (off, new writes are refused and writes still waiting
        fail). ``call_memory_access`` decides whether STACK's model may search memory and the knowledge base during a
        call STACK holds (on by default; with it on, a caller can try to get the call's model to read out what is in
        memory or the brain). What is left out keeps its value."""
        return cast(
            "dict[str, Any]", self._client.put("/v1/memory/settings", json=settings_body(enabled, call_memory_access))
        )


def settings_body(enabled: bool | None, call_memory_access: bool | None) -> dict[str, Any]:
    """The memory settings to change; at least one is needed."""
    body: dict[str, Any] = {}
    if enabled is not None:
        body["enabled"] = enabled
    if call_memory_access is not None:
        body["call_memory_access"] = call_memory_access
    if not body:
        raise ValueError("Give enabled, call_memory_access or both")
    return body
