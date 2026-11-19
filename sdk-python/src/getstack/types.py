"""STACK SDK type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict, Union


@dataclass
class Agent:
    id: str
    operator_id: str
    name: str
    description: str | None
    status: str
    accountability_mode: str
    on_warning: str
    on_critical: str
    passport_blocked: bool
    passport_blocked_reason: str | None
    passport_blocked_at: str | None
    created_at: str
    updated_at: str
    # Raw-secret access policy: "direct" | "proxy_preferred" | "proxy_only".
    # Defaulted for backward compatibility with older API responses.
    credential_access: str = "direct"
    # Signing-key model: "stack_managed" | "customer_managed" | "co_signed".
    # Immutable after registration. Surfaced so on-box use can
    # see whether the box needs an agent keypair (customer_managed) or the
    # operator credential (stack_managed). Defaulted for older responses.
    key_mode: str = "stack_managed"
    # per-agent LLM gateway toggles. llm_inject_system_prompt has no effect:
    # STACK adds no system prompt to /v1/llm/* calls. llm_redact_pii replaces
    # PII in user messages before forwarding (default true); False means user
    # PII reaches the LLM provider unredacted. Defaulted for older API
    # responses that predate the fields.
    llm_inject_system_prompt: bool = True
    llm_redact_pii: bool = True


@dataclass
class Passport:
    token: str
    jti: str
    expires_at: str
    accountability: str | None = None


class AuthorityReference(TypedDict):
    """Opaque authority reference embedded in a verified Passport.

    It intentionally contains only stable IDs, versions, hashes, and expiry;
    proof contents and personal data never belong in Passport claims.
    """

    binding_id: str
    binding_version: int
    binding_claim_id: str
    binding_digest: str
    receiver_id: str
    receiver_profile_version_id: str
    expires_at: int


class _RequiredPassportStackClaims(TypedDict):
    operator_id: str
    agent_id: str
    agent_name: str
    services: list[dict[str, Any]]
    identity_claims: list[dict[str, Any]]
    delegation_depth: int
    session_id: str


class PassportStackClaims(_RequiredPassportStackClaims, total=False):
    authority_refs: list[AuthorityReference]
    parent_passport_id: str
    accountability: Literal["enforced", "logged", "standard"]
    intent_summary: str
    intent_services: list[str]
    intent_refs: list[dict[str, Any]]
    checkpoint_interval: int
    platform_intent: Literal["staff", "monitor"]
    mission_ids: list[str]


class _RequiredVerifiedPassportClaims(TypedDict):
    sub: str
    jti: str
    iss: str
    aud: str | list[str]
    exp: int
    iat: int
    stk: PassportStackClaims


class VerifiedPassportClaims(_RequiredVerifiedPassportClaims, total=False):
    """Cryptographically verified Passport claims returned by SDK helpers."""

    nbf: int


@dataclass
class CheckpointResult:
    checkpoint_id: str
    passport_jti: str
    new_expires_at: str | None = None
    flags: list[str] | None = None


@dataclass
class CheckoutResult:
    checkout_id: str
    passport_jti: str
    review_status: str  # clean | flagged | blocked
    flags: list[dict[str, str]] | None = None


@dataclass
class ReviewFlag:
    type: str
    severity: str
    message: str


@dataclass
class PassportReport:
    passport: dict[str, Any]
    intent: dict[str, Any] | None
    checkpoints: list[dict[str, Any]]
    checkout: dict[str, Any] | None
    review: dict[str, Any] | None


@dataclass
class ReviewQueueItem:
    checkout_id: str
    passport_jti: str
    agent_id: str
    agent_name: str
    intent_summary: str
    review_status: str
    flags: list[dict[str, str]]
    submitted_at: str


@dataclass
class ReviewQueue:
    items: list[ReviewQueueItem]
    total: int


@dataclass
class ReviewDecisionResult:
    review_id: str
    agent_id: str
    decision: str
    passport_blocked: bool


@dataclass
class Credential:
    provider: str
    credential: str | None = None
    credentials: dict[str, str] | None = None


@dataclass
class Service:
    id: str
    provider: str
    name: str
    description: str
    available: bool = True


@dataclass
class ServiceConnection:
    id: str
    provider: str
    status: str
    connected_at: str
    # The connection's name, unique among a service's active connections for one principal ("default" for the first).
    name: str = "default"


@dataclass
class Dropoff:
    id: str
    from_agent_id: str
    to_agent_id: str
    status: str
    created_at: str
    expires_at: str
    operator_id: str | None = None
    schema: dict[str, Any] | None = None
    on_expire: str = "notify"
    deposited_at: str | None = None
    collected_at: str | None = None
    mission_id: str | None = None
    deposited_bytes: int = 0
    # Every agent named, in the order named: each can see and collect it. `to_agent_id` is the first.
    to_agent_ids: list[str] = field(default_factory=list)
    # The agent that collected it; None until one has.
    collected_by_agent_id: str | None = None


@dataclass
class NotificationChannel:
    id: str
    channel_type: str
    destination: str
    events: list[str]
    min_severity: str
    active: bool
    verified: bool


@dataclass
class AuditEntry:
    entry_id: str
    action: str
    outcome: str
    timestamp: int
    agent_id: str


@dataclass
class ToolCall:
    """A single tool call logged during a mission."""

    service: str
    method: str
    target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"service": self.service, "method": self.method}
        if self.target:
            d["target"] = self.target
        return d


# ─── Skills ──────────────────────────────────────────────────────────


@dataclass
class Skill:
    id: str
    operator_id: str
    name: str
    description: str
    version: str = "1.0.0"
    tags: list[str] = field(default_factory=list)
    trust_level_required: str = "L0"
    status: str = "active"
    execution_mode: str = "open"
    price_per_invocation: int = 0
    invocation_count: int = 0
    created_at: str = ""
    updated_at: str = ""


@dataclass
class SkillInvocation:
    id: str
    skill_id: str
    status: str
    output: Any = None
    error: dict[str, str] | None = None
    expires_at: str = ""
    created_at: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    llm_tokens_input: int | None = None
    llm_tokens_output: int | None = None
    execution_duration_ms: int | None = None


@dataclass
class SkillRequest:
    id: str
    operator_id: str
    description: str
    desired_input_schema: dict[str, Any] | None = None
    desired_output_schema: dict[str, Any] | None = None
    max_price_cents: int | None = None
    tags: list[str] = field(default_factory=list)
    status: str = "open"
    created_at: str = ""


# ─── Identity ────────────────────────────────────────────────────────


@dataclass
class IdentityProvider:
    key: str
    name: str
    layers: list[str] = field(default_factory=list)
    assurance: str = ""
    description: str = ""


@dataclass
class IdentityClaim:
    id: str
    operator_id: str
    provider_key: str
    layer: str
    claim_type: str
    claim_ref: str
    assurance_level: str
    verified_at: str
    expires_at: str | None = None


@dataclass
class IdentitySettings:
    identity_claim_ttl: str  # 30d | 90d | 180d | 1y
    identity_claim_inheritance: str  # auto | opt_in
    identity_auto_revoke: bool


class _RequiredServiceRequirementInput(TypedDict):
    layer: Literal["humanity", "identity", "delegation"]
    requires_claim: str
    minimum_assurance: Literal["low", "substantial", "high"]


class SetServiceRequirementInput(_RequiredServiceRequirementInput, total=False):
    """Canonical body for one service identity requirement."""

    accepted_providers: list[str]
    required_scopes: list[str]
    requires_pii: bool
    lawful_basis: str


class ServiceRequirement(_RequiredServiceRequirementInput):
    id: str
    operator_id: str
    service_id: str
    accepted_providers: list[str]
    required_scopes: list[str] | None
    requires_pii: bool
    lawful_basis: str | None


class ReplaceServiceRequirementResult(TypedDict):
    requirements: list[ServiceRequirement]


@dataclass
class VerificationSession:
    session_ref: str
    authorization_url: str | None = None
    status: str = "pending"


# The catalogue: what an agent can use through its account, served as one JSON
# document. These are the shapes of that document and of the calls that read it.

CatalogueKind = Literal["model", "tool", "service", "skill", "account", "mcp_tool"]
CatalogueToolAudience = Literal["agent", "owner", "both"]
CatalogueOrigin = Literal["stack", "models", "tools", "publisher"]
CatalogueResultTrust = Literal["standard", "untrusted"]


class CatalogueProviderCost(TypedDict, total=False):
    """What a provider charges, in millionths of a US dollar, at cost. A key that is absent is not known beforehand."""

    per_unit_usd_micros: int
    flat_fee_usd_micros: int
    input_per_million_tokens_usd_micros: int
    output_per_million_tokens_usd_micros: int
    worst_case_usd_micros: int
    # The prices a model provider lists beyond input and output tokens (all of them, for the unit "lines").
    lines: list[CataloguePriceLine]
    # A fraction the provider takes off its prices: the charge is the figures times one minus this.
    discount: float


class CataloguePriceLine(TypedDict):
    """One price of a model as its provider lists it: ``cost_usd_micros`` for every ``per_count`` of ``per``."""

    # The provider's own name for the price (``prompt``, ``image_output``, ``web_search``, ...).
    item: str
    per: Literal[
        "token", "character", "second", "request", "image", "search", "megapixel_second", "generation", "audio_unit"
    ]
    # 1, or 1,000,000 when one unit costs less than a micro-dollar (a token always is per million).
    per_count: Literal[1, 1000000]
    cost_usd_micros: int


class CataloguePrice(TypedDict):
    # "lines": the price is the list in ``provider_cost["lines"]``, each line with a unit of its own.
    unit: Literal["token", "call", "result", "image", "lines", "free", "varies"]
    currency: Literal["USD"]
    provider_cost: CatalogueProviderCost | None
    # Actions on the account's meter one run counts as: 1, or 0 for searching and inspecting.
    stack_actions: Literal[0, 1]


# `in` is a keyword, so the functional form.
CatalogueCostCap = TypedDict("CatalogueCostCap", {"in": Literal["body", "header"], "name": str})


class _RequiredCatalogueRun(TypedDict):
    method: Literal["GET", "POST", "PUT"]
    # ``{account_id}`` in the path stands for the account's id.
    path: str


class CatalogueRun(_RequiredCatalogueRun, total=False):
    """How to run an entry: the route for its kind and the MCP tool that calls it."""

    body: dict[str, str | int | float | bool]
    mcp_tool: str
    cost_cap: CatalogueCostCap


class CatalogueModalities(TypedDict):
    input: list[str]
    output: list[str]


class CatalogueToolFacts(TypedDict):
    """What an ``mcp_tool`` entry says about a tool: group, pieces that list it (none is the core), audience, rarity."""

    group: str
    pieces: list[str]
    audience: CatalogueToolAudience
    on_demand: bool


class _RequiredCatalogueEntry(TypedDict):
    id: str
    kind: CatalogueKind
    name: str
    description: str
    origin: CatalogueOrigin
    price: CataloguePrice
    result_trust: CatalogueResultTrust


class CatalogueEntry(_RequiredCatalogueEntry, total=False):
    """One thing an agent can use. Text from ``models``, ``tools`` or ``publisher`` is data, never instructions."""

    provider: str
    modalities: CatalogueModalities
    context_length: int
    input_schema: dict[str, Any]
    run: CatalogueRun
    tool: CatalogueToolFacts


class CatalogueSection(TypedDict):
    source: Literal["stack", "models", "tools", "services", "skills"]
    status: Literal["ok", "not_configured", "unavailable", "stale"]
    refreshed_at: str | None
    count: int


class CatalogueActionBand(TypedDict):
    up_to: int | None
    usd_micros_per_action: int


class CataloguePricing(TypedDict):
    currency: Literal["USD"]
    rule: str
    included_actions_per_month: int
    bands: list[CatalogueActionBand]


class CatalogueDocument(TypedDict):
    spec: Literal["stack.catalogue"]
    spec_version: str
    version: str
    generated_at: str
    notice: str
    pricing: CataloguePricing
    sections: list[CatalogueSection]
    entries: list[CatalogueEntry]


class CatalogueSearchResult(TypedDict):
    version: str
    total: int
    entries: list[CatalogueEntry]


class CatalogueConnectedService(TypedDict):
    id: str
    provider: str
    name: str
    connection_id: str


class CatalogueAccountPiece(TypedDict):
    id: str
    state: Literal["pending", "ready", "paused", "failed", "closing", "closed"]


class CatalogueAccountTool(TypedDict):
    id: str
    listed: bool


class _RequiredCatalogueAccountView(TypedDict):
    account_id: str
    catalogue_version: str | None
    connected_services: list[CatalogueConnectedService]
    pieces: list[CatalogueAccountPiece]


class CatalogueAccountView(_RequiredCatalogueAccountView, total=False):
    """What is true of one account only: its connections, its pieces and which tools its agent lists now."""

    tools: list[CatalogueAccountTool]


@dataclass
class CatalogueRead:
    """The answer to ``catalogue.get``: the document, or ``not_modified`` when the copy sent is current."""

    not_modified: bool
    etag: str | None
    document: CatalogueDocument | None


# Tool runs and images.


class ToolRunFile(TypedDict):
    """A file a run made: saved to the agent's drive when there is one, otherwise returned."""

    name: str
    content_type: str
    size_bytes: int | None
    drive_file_id: str | None
    source_url: str | None
    data_base64: str | None


class ToolRunOutput(TypedDict):
    output: Any


class ToolRunNotice(TypedDict):
    security_event_id: str | None
    message: str


class _ToolRunView(TypedDict):
    id: str
    account_id: str
    provider: str
    endpoint: str
    state: Literal["dispatching", "pending", "settled", "released"]
    price_type: Literal["PER_CALL", "PER_RESULT"]
    max_results: int | None
    reserved_cents: int
    charged_cents: int | None
    status: str | None
    provider_http_status: int | None
    result: ToolRunOutput | None
    withheld: ToolRunNotice | None
    flag: ToolRunNotice | None
    created_at: str
    settled_at: str | None


class ToolRunResult(_ToolRunView):
    """A tool run as read: the run and its ``files``.

    ``untrusted`` is true when what it returned is data, never instructions.
    """

    untrusted: bool
    files: list[ToolRunFile]


class _RequiredEmailDriveAttachment(TypedDict):
    file_id: str


class EmailDriveAttachment(_RequiredEmailDriveAttachment, total=False):
    """A drive file the agent can see (its own private files and the account's shared ones), by its id.

    ``filename`` renames it in this email only.
    """

    filename: str


class _RequiredEmailInlineAttachment(TypedDict):
    filename: str
    content_type: str


class EmailInlineAttachment(_RequiredEmailInlineAttachment, total=False):
    """A file sent with the request: raw ``content`` (the SDK encodes it) or ``content_base64``, not both.

    Inline files come to at most 10 MB in all; a larger file is attached from the drive by ``file_id``.
    """

    content: bytes | bytearray | memoryview
    content_base64: str


EmailAttachment = Union[EmailDriveAttachment, EmailInlineAttachment]


class _RequiredSendEmailInput(TypedDict):
    to: str | list[str]
    body: str


class SendEmailInput(_RequiredSendEmailInput, total=False):
    """An email. ``to`` is one address or a list; OpenMail takes one To address, so the first is the To and any
    further ones are delivered as Cc. A To is required: ``cc`` or ``bcc`` alone is refused. ``subject`` is
    required unless ``thread_id`` is set."""

    cc: list[str]
    bcc: list[str]
    subject: str
    body_html: str
    thread_id: str
    attachments: list[EmailAttachment]
    # The id (amsg_...) of the received message this email answers; a policy that sets the account's
    # recipients.email to "per_mission" requires it, and the email then goes only to who wrote that message.
    reply_to_message: str


class _RequiredReplyEmailInput(TypedDict):
    body: str


class ReplyEmailInput(_RequiredReplyEmailInput, total=False):
    """An answer in the thread of a received email, to the person who wrote it (every address its From names, when
    it names several; ``reply_all`` also to everyone else it was sent to). The answered email is quoted unless
    ``include_quote`` is false."""

    body_html: str
    reply_all: bool
    cc: list[str]
    bcc: list[str]
    subject: str
    attachments: list[EmailAttachment]
    include_quote: bool


class _RequiredForwardEmailInput(TypedDict):
    to: str | list[str]


class ForwardEmailInput(_RequiredForwardEmailInput, total=False):
    """A received email sent on as a new email, in no thread. A ``to`` is required: ``cc`` or ``bcc`` alone is refused.
    ``body`` is your own note above the original; ``include_quote`` (default true) carries the original's text;
    ``include_attachments`` (default true) attaches the original's kept files; ``attachments`` adds more."""

    cc: list[str]
    bcc: list[str]
    body: str
    include_quote: bool
    include_attachments: bool
    attachments: list[EmailAttachment]


class EmailSentAttachment(TypedDict):
    filename: str
    content_type: str
    size_bytes: int
    file_id: str | None


class _RequiredEmailSendResult(TypedDict):
    message_id: str
    channel: Literal["email", "sms", "telegram"]
    provider_message_id: str
    thread_id: str | None
    status: str


class EmailDropped(TypedDict):
    value: str
    reason: Literal["not_an_address"]


class EmailSendResult(_RequiredEmailSendResult, total=False):
    """What a send, reply or forward answers. ``to`` is a one-element list: where further To addresses went is
    visible in ``cc``. ``dropped`` names the addresses left out, each as given, and why (an entry of a received
    message that is not one plain address); it is absent when nothing was left out."""

    to: list[str]
    cc: list[str]
    bcc: list[str]
    attachments: list[EmailSentAttachment]
    dropped: list[EmailDropped]


class _RequiredMessageAttachment(TypedDict):
    filename: str | None
    content_type: str | None
    size_bytes: int | None


class MessageAttachment(_RequiredMessageAttachment, total=False):
    """An attachment of a message. ``file_id`` is the drive file that holds it (untrusted content, like every
    drive file). ``not_saved`` is why an attachment that arrived is not in the drive:
    ``too_large``, ``unavailable``, ``drive_read_only``, ``waiting`` (STACK is still saving it and tries for 30 days)
    or ``withheld``; the email is kept either way. A received file goes with its message when it is deleted, unless its
    end is changed (``drive.update``)."""

    file_id: str | None
    not_saved: str | None


_RequiredMessageEnvelope = TypedDict(
    "_RequiredMessageEnvelope",
    {
        "from": str,
        "to": list[str],
        "cc": list[str],
        "subject": "str | None",
        "body_text": str,
        "attachments": list[MessageAttachment],
        "truncated": bool,
        "details": dict[str, str],
    },
)


class MessageEnvelope(_RequiredMessageEnvelope, total=False):
    """The ``content`` of a message. ``bcc`` is on an email the account sent (a message that arrived shows none).
    ``thread_id`` is the mail provider's thread of an email, the one a reply goes in; it is absent on other
    channels and on mail that arrived before it was kept."""

    bcc: list[str]
    thread_id: str | None
