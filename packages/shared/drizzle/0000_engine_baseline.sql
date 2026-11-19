CREATE FUNCTION public.authority_bindings_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF current_setting('stack.operator_erasure_id', true) = OLD."operator_id" THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'authority binding versions are immutable' USING ERRCODE = '55000';
  END IF;
  IF (NEW."id", NEW."version", NEW."operator_id", NEW."principal_id", NEW."agent_id",
      NEW."agent_key_thumbprint", NEW."receiver_id", NEW."receiver_profile_version_id",
      NEW."domain_profile_version_id", NEW."mission_ids", NEW."lineage_root_id",
      NEW."lineage_root_version", NEW."parent_binding_id", NEW."parent_binding_version",
      NEW."delegation_depth", NEW."purpose_code", NEW."purpose_hash", NEW."scope_hash",
      NEW."approval_policy_hash", NEW."disclosure_policy_hash",
      NEW."delegation_policy", NEW."delegation_policy_hash", NEW."proof_set_hash",
      NEW."valid_from", NEW."expires_at", NEW."created_at", NEW."supersedes_version")
     IS DISTINCT FROM
     (OLD."id", OLD."version", OLD."operator_id", OLD."principal_id", OLD."agent_id",
      OLD."agent_key_thumbprint", OLD."receiver_id", OLD."receiver_profile_version_id",
      OLD."domain_profile_version_id", OLD."mission_ids", OLD."lineage_root_id",
      OLD."lineage_root_version", OLD."parent_binding_id", OLD."parent_binding_version",
      OLD."delegation_depth", OLD."purpose_code", OLD."purpose_hash", OLD."scope_hash",
      OLD."approval_policy_hash", OLD."disclosure_policy_hash",
      OLD."delegation_policy", OLD."delegation_policy_hash", OLD."proof_set_hash",
      OLD."valid_from", OLD."expires_at", OLD."created_at", OLD."supersedes_version") THEN
    RAISE EXCEPTION 'authority binding version content is immutable' USING ERRCODE = '55000';
  END IF;
  IF (NEW."purpose_statement_encrypted", NEW."scope_encrypted", NEW."approval_policy_encrypted",
      NEW."disclosure_policy_encrypted", NEW."erased_at", NEW."tombstone_hash",
      NEW."tombstone_claim_id") IS DISTINCT FROM
     (OLD."purpose_statement_encrypted", OLD."scope_encrypted", OLD."approval_policy_encrypted",
      OLD."disclosure_policy_encrypted", OLD."erased_at", OLD."tombstone_hash",
      OLD."tombstone_claim_id")
     AND NOT (OLD."status" <> 'erased' AND NEW."status" = 'erased'
       AND NEW."purpose_statement_encrypted" IS NULL AND NEW."scope_encrypted" IS NULL
       AND NEW."approval_policy_encrypted" IS NULL AND NEW."disclosure_policy_encrypted" IS NULL
       AND OLD."erased_at" IS NULL AND OLD."tombstone_hash" IS NULL
       AND OLD."tombstone_claim_id" IS NULL AND NEW."erased_at" IS NOT NULL
       AND NEW."tombstone_hash" IS NOT NULL AND NEW."tombstone_claim_id" IS NOT NULL) THEN
    RAISE EXCEPTION 'authority binding encrypted content and erasure tombstone are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW."status" <> OLD."status" AND NOT (
    (OLD."status" = 'draft' AND NEW."status" IN ('pending_approval', 'active', 'revoked', 'replaced')) OR
    (OLD."status" = 'pending_approval' AND NEW."status" IN ('active', 'revoked', 'replaced')) OR
    (OLD."status" = 'active' AND NEW."status" IN ('suspended', 'revoked', 'replaced')) OR
    (OLD."status" = 'suspended' AND NEW."status" IN ('active', 'revoked', 'replaced')) OR
    (OLD."status" <> 'erased' AND NEW."status" = 'erased')
  ) THEN
    RAISE EXCEPTION 'invalid authority binding status transition % -> %', OLD."status", NEW."status"
      USING ERRCODE = '23514';
  END IF;
  IF OLD."claim_id" IS NOT NULL AND NEW."claim_id" IS DISTINCT FROM OLD."claim_id" THEN
    RAISE EXCEPTION 'authority binding claim cannot be replaced' USING ERRCODE = '55000';
  END IF;
  IF NEW."claim_id" IS NOT NULL AND OLD."claim_id" IS NULL AND NEW."status" <> 'active' THEN
    RAISE EXCEPTION 'authority binding claim may only be attached during activation' USING ERRCODE = '23514';
  END IF;
  IF OLD."activated_at" IS NOT NULL AND NEW."activated_at" IS DISTINCT FROM OLD."activated_at" THEN
    RAISE EXCEPTION 'authority binding activation time is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD."revoked_at" IS NOT NULL AND NEW."revoked_at" IS DISTINCT FROM OLD."revoked_at" THEN
    RAISE EXCEPTION 'authority binding revocation time is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.authority_profile_reference_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  profile_id text;
  child_operator_id text;
  profile_owner_id text;
  actual_kind text;
BEGIN
  profile_id := to_jsonb(NEW) ->> TG_ARGV[0];
  child_operator_id := to_jsonb(NEW) ->> TG_ARGV[1];
  IF profile_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT owner_operator_id, profile_kind INTO profile_owner_id, actual_kind
    FROM authority_profile_versions WHERE id = profile_id;
  IF NOT FOUND OR actual_kind <> TG_ARGV[2]
    OR (profile_owner_id IS NOT NULL AND profile_owner_id <> child_operator_id) THEN
    RAISE EXCEPTION 'authority profile reference is missing, wrong-kind, or cross-tenant'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.authority_profile_versions_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD."owner_operator_id" IS NOT NULL
      AND current_setting('stack.operator_erasure_id', true) = OLD."owner_operator_id" THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'authority profile versions are immutable' USING ERRCODE = '55000';
  END IF;
  IF (NEW."id", NEW."owner_operator_id", NEW."profile_kind", NEW."profile_key", NEW."version",
      NEW."receiver_id", NEW."schema_uri", NEW."schema_version", NEW."adapter_key",
      NEW."adapter_version", NEW."config_json", NEW."content_hash", NEW."created_at")
     IS DISTINCT FROM
     (OLD."id", OLD."owner_operator_id", OLD."profile_kind", OLD."profile_key", OLD."version",
      OLD."receiver_id", OLD."schema_uri", OLD."schema_version", OLD."adapter_key",
      OLD."adapter_version", OLD."config_json", OLD."content_hash", OLD."created_at") THEN
    RAISE EXCEPTION 'authority profile version content is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD."claim_id" IS NOT NULL AND NEW."claim_id" IS DISTINCT FROM OLD."claim_id" THEN
    RAISE EXCEPTION 'authority profile claim cannot be replaced' USING ERRCODE = '55000';
  END IF;
  IF NEW."status" <> OLD."status" AND NOT (
    (OLD."status" = 'draft' AND NEW."status" IN ('active', 'revoked')) OR
    (OLD."status" = 'active' AND NEW."status" IN ('retired', 'revoked')) OR
    (OLD."status" = 'retired' AND NEW."status" = 'revoked')
  ) THEN
    RAISE EXCEPTION 'invalid authority profile status transition % -> %', OLD."status", NEW."status"
      USING ERRCODE = '23514';
  END IF;
  IF OLD."activated_at" IS NOT NULL AND NEW."activated_at" IS DISTINCT FROM OLD."activated_at" THEN
    RAISE EXCEPTION 'authority profile activation time is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD."retired_at" IS NOT NULL AND NEW."retired_at" IS DISTINCT FROM OLD."retired_at" THEN
    RAISE EXCEPTION 'authority profile retirement time is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD."revoked_at" IS NOT NULL AND NEW."revoked_at" IS DISTINCT FROM OLD."revoked_at" THEN
    RAISE EXCEPTION 'authority profile revocation time is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.authority_reject_all_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE'
    AND current_setting('stack.operator_erasure_id', true) = to_jsonb(OLD) ->> 'operator_id' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION '% is immutable', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.dropoffs_lifecycle_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW."status" = 'deposited'
     AND COALESCE(NEW."deposited_bytes", 0) = 0
     AND NEW."payload_encrypted" IS NOT NULL THEN
    NEW."deposited_bytes" := OCTET_LENGTH(NEW."payload_encrypted");
  END IF;

  IF TG_OP = 'UPDATE' AND NEW."status" IS DISTINCT FROM OLD."status" AND NOT (
    (OLD."status" = 'created' AND NEW."status" IN ('deposited', 'expired')) OR
    (OLD."status" = 'deposited' AND NEW."status" IN ('collected', 'expired'))
  ) THEN
    RAISE EXCEPTION 'invalid drop-off status transition % -> %', OLD."status", NEW."status"
      USING ERRCODE = '23514';
  END IF;

  IF TG_OP = 'UPDATE' AND OLD."status" <> 'created' AND (
    NEW."mission_id" IS DISTINCT FROM OLD."mission_id" OR
    NEW."deposited_bytes" IS DISTINCT FROM OLD."deposited_bytes"
  ) THEN
    RAISE EXCEPTION 'drop-off mission attribution and deposited bytes are immutable'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.enforce_proxy_operation_attempt_budget() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  operation_adapter text;
  operation_deadline timestamp with time zone;
BEGIN
  SELECT adapter_kind, retry_deadline
    INTO operation_adapter, operation_deadline
    FROM proxy_operations
   WHERE id = NEW.operation_id AND operator_id = NEW.operator_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'proxy operation is unavailable';
  END IF;
  IF NEW.attempt_number > 1 AND operation_adapter <> 'stripe' THEN
    RAISE EXCEPTION 'generic proxy operations permit one transport attempt';
  END IF;
  IF NEW.attempt_number > 1 AND (operation_deadline IS NULL OR now() >= operation_deadline) THEN
    RAISE EXCEPTION 'proxy retry deadline has expired';
  END IF;
  IF NEW.attempt_number > 3 THEN
    RAISE EXCEPTION 'proxy transport attempt budget exhausted';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.erased_operators_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'erased_operators is append-only' USING ERRCODE = '42501';
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.protect_proxy_operation_evidence() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF current_setting('stack.operator_erasure_id', true) IS DISTINCT FROM OLD.operator_id THEN
    RAISE EXCEPTION 'proxy operation evidence is append-only';
  END IF;
  RETURN OLD;
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.reject_evidence_pack_artifact_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  -- A foreign-key cascade runs below the parent DELETE trigger depth. This
  -- keeps account erasure possible while every direct artifact DELETE fails.
  IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
    RETURN OLD;
  END IF;

  RAISE EXCEPTION 'evidence-pack artifact metadata is immutable'
    USING ERRCODE = '55000';
END;
$$;
--> statement-breakpoint
CREATE FUNCTION public.reject_operator_decision_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
    RETURN OLD;
  END IF;

  RAISE EXCEPTION 'signed operator decision projections are immutable'
    USING ERRCODE = '55000';
END;
$$;
--> statement-breakpoint
CREATE TABLE public.admin_actions (
    id text NOT NULL,
    admin_operator_id text NOT NULL,
    target_operator_id text,
    action text NOT NULL,
    reason text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.agent_service_grants (
    id text NOT NULL,
    agent_id text NOT NULL,
    service_connection_id text NOT NULL,
    scopes jsonb NOT NULL,
    constraints jsonb,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    allow_data_from jsonb,
    intent_refs jsonb
);
--> statement-breakpoint
CREATE TABLE public.agents (
    id text NOT NULL,
    operator_id text NOT NULL,
    name text NOT NULL,
    description text,
    status text DEFAULT 'active'::text NOT NULL,
    accountability_mode text DEFAULT 'enforced'::text NOT NULL,
    on_warning text DEFAULT 'notify'::text NOT NULL,
    on_critical text DEFAULT 'notify'::text NOT NULL,
    credential_access text DEFAULT 'proxy_only'::text NOT NULL,
    passport_blocked boolean DEFAULT false NOT NULL,
    passport_blocked_reason text,
    passport_blocked_at timestamp with time zone,
    icon_url text,
    skill_access_mode text DEFAULT 'none'::text NOT NULL,
    allowed_skills jsonb DEFAULT '[]'::jsonb NOT NULL,
    identity_claim_ids jsonb,
    pubkey jsonb,
    enrolled_at timestamp with time zone,
    key_mode text DEFAULT 'stack_managed'::text NOT NULL,
    signing_key_encrypted text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    llm_inject_system_prompt boolean DEFAULT true NOT NULL,
    twin_policy text DEFAULT 'per_mission'::text NOT NULL,
    twin_llm_model text,
    is_synthetic boolean DEFAULT false NOT NULL,
    llm_redact_pii boolean DEFAULT true NOT NULL,
    created_via_grant_id text,
    eval_traffic boolean DEFAULT false NOT NULL,
    CONSTRAINT agents_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'revoked'::text, 'blocked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.audit_archive_segments (
    id text NOT NULL,
    operator_id text NOT NULL,
    from_timestamp bigint NOT NULL,
    to_timestamp bigint NOT NULL,
    row_count integer NOT NULL,
    object_key text NOT NULL,
    byte_size integer NOT NULL,
    content_hash text NOT NULL,
    first_entry_hash text NOT NULL,
    first_prev_entry_hash text,
    last_entry_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    retention_attempt_count integer DEFAULT 0 NOT NULL,
    retention_next_attempt_at timestamp with time zone,
    retention_last_error_code text
);
--> statement-breakpoint
CREATE TABLE public.audit_log (
    entry_id text NOT NULL,
    trace_id text NOT NULL,
    span_id text NOT NULL,
    parent_span_id text,
    "timestamp" bigint NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    passport_jti text NOT NULL,
    layer text NOT NULL,
    action text NOT NULL,
    outcome text NOT NULL,
    duration_ms integer,
    payload_hash text,
    error_code text,
    error_message text,
    prev_entry_hash text NOT NULL,
    entry_hash text NOT NULL,
    passport_claims_at_event jsonb,
    request_bytes integer,
    response_bytes integer,
    request_entropy double precision,
    response_entropy double precision,
    actor_grant_id text,
    actor_partner_operator_id text,
    hash_version integer DEFAULT 2 NOT NULL,
    claim_binding_status text DEFAULT 'legacy_unbound'::text NOT NULL,
    CONSTRAINT audit_hash_version_binding_check CHECK ((((hash_version = 1) AND (claim_binding_status = 'legacy_unbound'::text)) OR ((hash_version = 2) AND (claim_binding_status = ANY (ARRAY['not_applicable'::text, 'no_active_claims'::text, 'bound'::text])))))
);
--> statement-breakpoint
CREATE TABLE public.authority_approval_decisions (
    id text NOT NULL,
    operator_id text NOT NULL,
    request_id text NOT NULL,
    authoriser_principal_id text NOT NULL,
    identity_proof_id text NOT NULL,
    identity_proof_version integer NOT NULL,
    capacity_proof_id text,
    capacity_proof_version integer,
    decision_proof_id text NOT NULL,
    decision_proof_version integer NOT NULL,
    decision text NOT NULL,
    weight integer NOT NULL,
    request_hash text NOT NULL,
    decided_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT authority_approval_decisions_capacity_ref_check CHECK ((((capacity_proof_id IS NULL) AND (capacity_proof_version IS NULL)) OR ((capacity_proof_id IS NOT NULL) AND (capacity_proof_version IS NOT NULL)))),
    CONSTRAINT authority_approval_decisions_decision_check CHECK ((decision = ANY (ARRAY['approve'::text, 'reject'::text]))),
    CONSTRAINT authority_approval_decisions_id_check CHECK ((id ~ '^apd_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_approval_decisions_weight_check CHECK ((weight > 0))
);
--> statement-breakpoint
CREATE TABLE public.authority_approval_requests (
    id text NOT NULL,
    operator_id text NOT NULL,
    binding_id text NOT NULL,
    binding_version integer NOT NULL,
    authority_use_id text,
    phase text NOT NULL,
    group_key text NOT NULL,
    request_hash text NOT NULL,
    challenge_hash text NOT NULL,
    required_weight integer NOT NULL,
    collected_weight integer DEFAULT 0 NOT NULL,
    reject_mode text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    satisfied_at timestamp with time zone,
    consumed_at timestamp with time zone,
    CONSTRAINT authority_approval_requests_id_check CHECK ((id ~ '^apr_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_approval_requests_phase_check CHECK ((phase = ANY (ARRAY['activation'::text, 'action'::text, 'presentation'::text]))),
    CONSTRAINT authority_approval_requests_reject_mode_check CHECK ((reject_mode = ANY (ARRAY['any_reject'::text, 'threshold_reject'::text]))),
    CONSTRAINT authority_approval_requests_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'satisfied'::text, 'rejected'::text, 'expired'::text, 'consumed'::text, 'cancelled'::text]))),
    CONSTRAINT authority_approval_requests_weights_check CHECK (((required_weight > 0) AND (collected_weight >= 0)))
);
--> statement-breakpoint
CREATE TABLE public.authority_binding_proofs (
    binding_id text NOT NULL,
    binding_version integer NOT NULL,
    proof_id text NOT NULL,
    proof_version integer NOT NULL,
    operator_id text NOT NULL,
    role text NOT NULL,
    authoriser_principal_id text,
    group_key text NOT NULL,
    weight integer DEFAULT 1 NOT NULL,
    required boolean DEFAULT true NOT NULL,
    ordinal integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT authority_binding_proofs_role_check CHECK ((role = ANY (ARRAY['principal_identity'::text, 'authoriser_identity'::text, 'authoriser_capacity'::text, 'mandate'::text, 'consent'::text, 'domain'::text]))),
    CONSTRAINT authority_binding_proofs_weight_check CHECK (((weight > 0) AND (ordinal >= 0)))
);
--> statement-breakpoint
CREATE TABLE public.authority_bindings (
    id text NOT NULL,
    version integer NOT NULL,
    operator_id text NOT NULL,
    principal_id text NOT NULL,
    agent_id text NOT NULL,
    agent_key_thumbprint text NOT NULL,
    receiver_id text NOT NULL,
    receiver_profile_version_id text NOT NULL,
    domain_profile_version_id text,
    mission_ids text[] DEFAULT '{}'::text[] NOT NULL,
    lineage_root_id text NOT NULL,
    lineage_root_version integer NOT NULL,
    parent_binding_id text,
    parent_binding_version integer,
    delegation_depth integer DEFAULT 0 NOT NULL,
    purpose_code text NOT NULL,
    purpose_statement_encrypted text,
    purpose_hash text NOT NULL,
    scope_encrypted text,
    scope_hash text NOT NULL,
    approval_policy_encrypted text,
    approval_policy_hash text NOT NULL,
    disclosure_policy_encrypted text,
    disclosure_policy_hash text NOT NULL,
    delegation_policy jsonb NOT NULL,
    delegation_policy_hash text NOT NULL,
    proof_set_hash text NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    status text DEFAULT 'draft'::text NOT NULL,
    claim_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    supersedes_version integer,
    erased_at timestamp with time zone,
    tombstone_hash text,
    tombstone_claim_id text,
    CONSTRAINT authority_bindings_depth_check CHECK (((delegation_depth >= 0) AND (delegation_depth <= 4))),
    CONSTRAINT authority_bindings_erasure_check CHECK ((((status = 'erased'::text) AND (purpose_statement_encrypted IS NULL) AND (scope_encrypted IS NULL) AND (approval_policy_encrypted IS NULL) AND (disclosure_policy_encrypted IS NULL) AND (erased_at IS NOT NULL) AND (tombstone_hash IS NOT NULL) AND (tombstone_claim_id IS NOT NULL)) OR ((status <> 'erased'::text) AND (scope_encrypted IS NOT NULL) AND (approval_policy_encrypted IS NOT NULL) AND (disclosure_policy_encrypted IS NOT NULL) AND (erased_at IS NULL) AND (tombstone_hash IS NULL) AND (tombstone_claim_id IS NULL)))),
    CONSTRAINT authority_bindings_id_check CHECK ((id ~ '^abn_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_bindings_parent_check CHECK ((((delegation_depth = 0) AND (parent_binding_id IS NULL) AND (parent_binding_version IS NULL)) OR ((delegation_depth > 0) AND (parent_binding_id IS NOT NULL) AND (parent_binding_version IS NOT NULL)))),
    CONSTRAINT authority_bindings_purpose_code_check CHECK (((purpose_code ~ '^[a-z][a-z0-9]*([._:-][a-z0-9]+)*$'::text) AND (purpose_code !~ '[0-9]{6,}'::text) AND (length(purpose_code) <= 128))),
    CONSTRAINT authority_bindings_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'pending_approval'::text, 'active'::text, 'suspended'::text, 'revoked'::text, 'replaced'::text, 'erased'::text]))),
    CONSTRAINT authority_bindings_validity_check CHECK ((expires_at > valid_from)),
    CONSTRAINT authority_bindings_version_check CHECK ((version > 0))
);
--> statement-breakpoint
CREATE TABLE public.authority_idempotency_keys (
    id text NOT NULL,
    operator_id text NOT NULL,
    route_key text NOT NULL,
    idempotency_key_hash text NOT NULL,
    request_hash text NOT NULL,
    state text DEFAULT 'started'::text NOT NULL,
    resource_type text,
    resource_id text,
    response_status integer,
    response_body jsonb,
    workflow_phase text,
    workflow_payload_encrypted text,
    lease_token_hash text,
    lease_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    response_readable_until timestamp with time zone,
    response_tombstone_hash text,
    CONSTRAINT authority_idempotency_keys_completion_check CHECK ((((state = 'started'::text) AND (response_status IS NULL) AND (response_body IS NULL)) OR ((state = 'completed'::text) AND (response_status IS NOT NULL) AND ((response_body IS NOT NULL) OR (response_tombstone_hash IS NOT NULL))))),
    CONSTRAINT authority_idempotency_keys_id_check CHECK ((id ~ '^aik_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_idempotency_keys_lease_pair_check CHECK ((((workflow_phase = ANY (ARRAY['initiating'::text, 'callback_verifying'::text])) AND (lease_token_hash IS NOT NULL) AND (lease_expires_at IS NOT NULL)) OR (((workflow_phase IS NULL) OR (workflow_phase <> ALL (ARRAY['initiating'::text, 'callback_verifying'::text]))) AND (lease_token_hash IS NULL) AND (lease_expires_at IS NULL)))),
    CONSTRAINT authority_idempotency_keys_response_status_check CHECK (((response_status IS NULL) OR ((response_status >= 100) AND (response_status <= 599)))),
    CONSTRAINT authority_idempotency_keys_state_check CHECK ((state = ANY (ARRAY['started'::text, 'completed'::text]))),
    CONSTRAINT authority_idempotency_keys_workflow_phase_check CHECK (((workflow_phase IS NULL) OR (workflow_phase = ANY (ARRAY['reserved'::text, 'initiating'::text, 'ready'::text, 'callback_verifying'::text, 'callback_verified'::text, 'completed'::text, 'failed'::text, 'erased'::text])))),
    CONSTRAINT authority_idempotency_keys_workflow_state_check CHECK (((workflow_phase IS NULL) OR ((workflow_phase IS NOT NULL) AND (workflow_payload_encrypted IS NOT NULL) AND (((state = 'started'::text) AND (workflow_phase = ANY (ARRAY['reserved'::text, 'initiating'::text, 'ready'::text, 'callback_verifying'::text, 'callback_verified'::text]))) OR ((state = 'completed'::text) AND (workflow_phase = ANY (ARRAY['completed'::text, 'failed'::text]))))) OR ((state = 'completed'::text) AND (workflow_phase = 'erased'::text) AND (workflow_payload_encrypted IS NULL))))
);
--> statement-breakpoint
CREATE TABLE public.authority_presentations (
    id text NOT NULL,
    operator_id text NOT NULL,
    authority_use_id text NOT NULL,
    binding_id text NOT NULL,
    binding_version integer NOT NULL,
    receiver_id text NOT NULL,
    receiver_profile_version_id text NOT NULL,
    request_signing_key_id text NOT NULL,
    response_encryption_key_id text NOT NULL,
    nonce_hash text NOT NULL,
    state_hash text,
    signed_request_hash text NOT NULL,
    request_payload_encrypted text,
    requested_fact_ids text[] NOT NULL,
    presentation_jti_hash text NOT NULL,
    payload_hash text,
    disclosure_manifest jsonb NOT NULL,
    proof_refs jsonb NOT NULL,
    signing_key_id text,
    signing_algorithm text,
    key_management_algorithm text,
    content_encryption_algorithm text,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    prepared_at timestamp with time zone,
    delivered_at timestamp with time zone,
    last_error_code text,
    erased_at timestamp with time zone,
    tombstone_hash text,
    tombstone_claim_id text,
    CONSTRAINT authority_presentations_erasure_check CHECK ((((status = 'erased'::text) AND (erased_at IS NOT NULL) AND (tombstone_hash IS NOT NULL) AND (tombstone_claim_id IS NOT NULL)) OR ((status <> 'erased'::text) AND (erased_at IS NULL) AND (tombstone_hash IS NULL) AND (tombstone_claim_id IS NULL)))),
    CONSTRAINT authority_presentations_id_check CHECK ((id ~ '^prs_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_presentations_request_scrub_check CHECK ((((status = ANY (ARRAY['pending'::text, 'prepared'::text, 'delivered'::text])) AND (request_payload_encrypted IS NOT NULL)) OR ((status = ANY (ARRAY['delivery_failed'::text, 'accepted'::text, 'rejected'::text, 'expired'::text, 'erased'::text])) AND (request_payload_encrypted IS NULL)))),
    CONSTRAINT authority_presentations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'prepared'::text, 'delivered'::text, 'delivery_failed'::text, 'accepted'::text, 'rejected'::text, 'expired'::text, 'erased'::text])))
);
--> statement-breakpoint
CREATE TABLE public.authority_principals (
    id text NOT NULL,
    operator_id text NOT NULL,
    kind text NOT NULL,
    label_encrypted text,
    status text DEFAULT 'active'::text NOT NULL,
    superseded_by_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    erased_at timestamp with time zone,
    tombstone_hash text,
    tombstone_claim_id text,
    CONSTRAINT authority_principals_erasure_check CHECK ((((status = 'erased'::text) AND (label_encrypted IS NULL) AND (erased_at IS NOT NULL) AND (tombstone_hash IS NOT NULL) AND (tombstone_claim_id IS NOT NULL)) OR ((status <> 'erased'::text) AND (erased_at IS NULL) AND (tombstone_hash IS NULL) AND (tombstone_claim_id IS NULL)))),
    CONSTRAINT authority_principals_id_check CHECK ((id ~ '^prn_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_principals_kind_check CHECK ((kind = ANY (ARRAY['person'::text, 'organisation'::text]))),
    CONSTRAINT authority_principals_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text, 'erased'::text])))
);
--> statement-breakpoint
CREATE TABLE public.authority_profile_versions (
    id text NOT NULL,
    owner_operator_id text,
    profile_kind text NOT NULL,
    profile_key text NOT NULL,
    version integer NOT NULL,
    receiver_id text,
    schema_uri text NOT NULL,
    schema_version text NOT NULL,
    adapter_key text NOT NULL,
    adapter_version integer NOT NULL,
    config_json jsonb NOT NULL,
    content_hash text NOT NULL,
    claim_id text,
    status text DEFAULT 'draft'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT authority_profile_versions_id_check CHECK ((id ~ '^apv_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_profile_versions_kind_check CHECK ((profile_kind = ANY (ARRAY['proof'::text, 'domain'::text, 'receiver'::text]))),
    CONSTRAINT authority_profile_versions_receiver_check CHECK ((((profile_kind = 'receiver'::text) AND (receiver_id IS NOT NULL) AND (owner_operator_id IS NOT NULL)) OR ((profile_kind <> 'receiver'::text) AND (receiver_id IS NULL)))),
    CONSTRAINT authority_profile_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'active'::text, 'retired'::text, 'revoked'::text]))),
    CONSTRAINT authority_profile_versions_version_check CHECK (((version > 0) AND (adapter_version > 0)))
);
--> statement-breakpoint
CREATE TABLE public.authority_proof_dependencies (
    derived_proof_id text NOT NULL,
    derived_proof_version integer NOT NULL,
    operator_id text NOT NULL,
    source_proof_id text NOT NULL,
    source_proof_version integer NOT NULL,
    relation text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT authority_proof_dependencies_not_self_check CHECK (((derived_proof_id <> source_proof_id) OR (derived_proof_version <> source_proof_version))),
    CONSTRAINT authority_proof_dependencies_relation_check CHECK ((relation = ANY (ARRAY['verified_from'::text, 'translated_from'::text, 'composed_from'::text])))
);
--> statement-breakpoint
CREATE TABLE public.authority_proofs (
    id text NOT NULL,
    version integer NOT NULL,
    operator_id text NOT NULL,
    subject_principal_id text NOT NULL,
    represented_principal_id text,
    profile_version_id text NOT NULL,
    proof_kind text NOT NULL,
    source_kind text NOT NULL,
    legacy_identity_claim_id text,
    issuer_identifier text NOT NULL,
    issuer_key_thumbprint text,
    original_relying_party_identifier text,
    schema_uri text NOT NULL,
    schema_version text NOT NULL,
    native_format text NOT NULL,
    native_evidence_encrypted text,
    normalized_facts_encrypted text,
    native_evidence_hash text NOT NULL,
    normalized_facts_hash text,
    verification_method text NOT NULL,
    verifier_identifier text NOT NULL,
    verifier_version text NOT NULL,
    assurance_uri text,
    verified_at timestamp with time zone NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    last_status_result text,
    last_status_checked_at timestamp with time zone,
    status_fresh_until timestamp with time zone,
    status text DEFAULT 'pending'::text NOT NULL,
    supersedes_version integer,
    claim_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    erased_at timestamp with time zone,
    tombstone_hash text,
    tombstone_claim_id text,
    CONSTRAINT authority_proofs_erasure_check CHECK ((((status = 'erased'::text) AND (native_evidence_encrypted IS NULL) AND (normalized_facts_encrypted IS NULL) AND (erased_at IS NOT NULL) AND (tombstone_hash IS NOT NULL) AND (tombstone_claim_id IS NOT NULL)) OR ((status <> 'erased'::text) AND (erased_at IS NULL) AND (tombstone_hash IS NULL) AND (tombstone_claim_id IS NULL)))),
    CONSTRAINT authority_proofs_id_check CHECK ((id ~ '^prf_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_proofs_kind_check CHECK ((proof_kind = ANY (ARRAY['identity'::text, 'capacity'::text, 'mandate'::text, 'consent'::text, 'signature'::text, 'domain'::text, 'workload'::text]))),
    CONSTRAINT authority_proofs_source_check CHECK ((source_kind = ANY (ARRAY['legacy_identity_claim'::text, 'external_native'::text, 'stack_derived'::text]))),
    CONSTRAINT authority_proofs_source_storage_check CHECK ((((source_kind = 'legacy_identity_claim'::text) AND (legacy_identity_claim_id IS NOT NULL) AND (native_evidence_encrypted IS NULL) AND (normalized_facts_encrypted IS NULL) AND (normalized_facts_hash IS NULL)) OR ((source_kind <> 'legacy_identity_claim'::text) AND (legacy_identity_claim_id IS NULL) AND ((native_evidence_encrypted IS NOT NULL) OR (status = 'erased'::text))))),
    CONSTRAINT authority_proofs_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'suspended'::text, 'revoked'::text, 'replaced'::text, 'erased'::text]))),
    CONSTRAINT authority_proofs_status_result_check CHECK (((last_status_result IS NULL) OR (last_status_result = ANY (ARRAY['valid'::text, 'revoked'::text, 'unknown'::text])))),
    CONSTRAINT authority_proofs_version_check CHECK ((version > 0))
);
--> statement-breakpoint
CREATE TABLE public.authority_receiver_keys (
    id text NOT NULL,
    receiver_id text NOT NULL,
    key_id text NOT NULL,
    use text NOT NULL,
    algorithm text NOT NULL,
    public_jwk jsonb NOT NULL,
    thumbprint text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT authority_receiver_keys_id_check CHECK ((id ~ '^rky_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_receiver_keys_status_check CHECK ((status = ANY (ARRAY['active'::text, 'retired'::text, 'revoked'::text]))),
    CONSTRAINT authority_receiver_keys_use_check CHECK ((use = ANY (ARRAY['request_signing'::text, 'response_encryption'::text, 'receipt_signing'::text, 'transport_mtls'::text]))),
    CONSTRAINT authority_receiver_keys_validity_check CHECK (((valid_until IS NULL) OR (valid_until > valid_from)))
);
--> statement-breakpoint
CREATE TABLE public.authority_receivers (
    id text NOT NULL,
    managed_by_operator_id text NOT NULL,
    mode text NOT NULL,
    canonical_identifier text NOT NULL,
    display_name text NOT NULL,
    proxy_service_connection_id text,
    current_profile_version_id text,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    CONSTRAINT authority_receivers_id_check CHECK ((id ~ '^rcv_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_receivers_mode_check CHECK ((mode = ANY (ARRAY['native'::text, 'proxy_bridge'::text, 'internal'::text]))),
    CONSTRAINT authority_receivers_proxy_connection_check CHECK ((((mode = ANY (ARRAY['native'::text, 'internal'::text])) AND (proxy_service_connection_id IS NULL)) OR ((mode = 'proxy_bridge'::text) AND (proxy_service_connection_id IS NOT NULL)))),
    CONSTRAINT authority_receivers_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'suspended'::text, 'revoked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.authority_uses (
    id text NOT NULL,
    operator_id text NOT NULL,
    binding_id text NOT NULL,
    binding_version integer NOT NULL,
    passport_jti text NOT NULL,
    mission_id text,
    agent_id text NOT NULL,
    agent_key_thumbprint text NOT NULL,
    receiver_id text NOT NULL,
    receiver_profile_version_id text NOT NULL,
    domain_profile_version_id text,
    receiver_request_id text NOT NULL,
    action_uri text NOT NULL,
    resource_hash text,
    request_hash text NOT NULL,
    effective_scope_hash text NOT NULL,
    proof_set_hash text NOT NULL,
    disclosure_manifest jsonb NOT NULL,
    verification_mode text NOT NULL,
    proof_strength text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    denial_code text,
    intent_claim_id text,
    outcome_claim_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    authorized_at timestamp with time zone,
    dispatched_at timestamp with time zone,
    completed_at timestamp with time zone,
    result_hash text,
    CONSTRAINT authority_uses_id_check CHECK ((id ~ '^aus_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT authority_uses_proof_strength_check CHECK ((proof_strength = ANY (ARRAY['native_issuer_evidence'::text, 'native_stack_attestation'::text, 'proxy_stack_enforced'::text]))),
    CONSTRAINT authority_uses_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'waiting_approval'::text, 'authorized'::text, 'denied'::text, 'dispatched'::text, 'succeeded'::text, 'failed'::text]))),
    CONSTRAINT authority_uses_verification_mode_check CHECK ((verification_mode = ANY (ARRAY['native_receiver'::text, 'proxy_mediated'::text])))
);
--> statement-breakpoint
CREATE TABLE public.cmek_migrations (
    id text NOT NULL,
    operator_id text NOT NULL,
    direction text NOT NULL,
    table_name text NOT NULL,
    rows_total integer DEFAULT 0 NOT NULL,
    rows_done integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    error text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT cmek_migrations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text])))
);
--> statement-breakpoint
CREATE TABLE public.connect_links (
    id text NOT NULL,
    operator_id text NOT NULL,
    member_id text,
    token_hash text NOT NULL,
    service_id text NOT NULL,
    provider text NOT NULL,
    method text NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    connection_id text,
    created_via text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    opened_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT connect_links_method_check CHECK ((method = ANY (ARRAY['oauth'::text, 'key'::text]))),
    CONSTRAINT connect_links_status_check CHECK ((((status = ANY (ARRAY['pending'::text, 'expired'::text])) AND (connection_id IS NULL)) OR ((status = 'connected'::text) AND (connection_id IS NOT NULL) AND (completed_at IS NOT NULL)))),
    CONSTRAINT connect_links_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);
--> statement-breakpoint
CREATE TABLE public.control_decisions (
    id text NOT NULL,
    operator_id text NOT NULL,
    socket_id text,
    account_id text,
    agent_id text,
    action_type text NOT NULL,
    decider text NOT NULL,
    verdict text NOT NULL,
    reason_code text,
    cause text,
    latency_ms integer NOT NULL,
    charged boolean DEFAULT false NOT NULL,
    request_digest text NOT NULL,
    request jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    evidence jsonb,
    CONSTRAINT control_decisions_decider_check CHECK ((decider = ANY (ARRAY['none'::text, 'hosted'::text, 'remote'::text]))),
    CONSTRAINT control_decisions_verdict_check CHECK ((verdict = ANY (ARRAY['allow'::text, 'deny'::text, 'unavailable'::text])))
);
--> statement-breakpoint
CREATE TABLE public.control_event_outbox (
    operator_id text NOT NULL,
    seq bigint NOT NULL,
    entry_id text NOT NULL,
    event jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    gap_announced boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_event_outbox_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'dead'::text])))
);
--> statement-breakpoint
CREATE TABLE public.control_policies (
    id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text,
    name text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    definition jsonb NOT NULL,
    definition_digest text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    last_change text DEFAULT 'create'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_policies_revision_check CHECK ((revision >= 1)),
    CONSTRAINT control_policies_status_check CHECK ((status = ANY (ARRAY['active'::text, 'deleted'::text])))
);
--> statement-breakpoint
CREATE TABLE public.control_policy_revisions (
    policy_id text NOT NULL,
    revision integer NOT NULL,
    operator_id text NOT NULL,
    agent_id text,
    definition jsonb NOT NULL,
    definition_digest text NOT NULL,
    change text NOT NULL,
    actor text NOT NULL,
    approval_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_policy_revisions_change_check CHECK ((change = ANY (ARRAY['create'::text, 'start_from_access'::text, 'tighten'::text, 'loosen'::text, 'delete'::text])))
);
--> statement-breakpoint
CREATE TABLE public.control_reviews (
    id text NOT NULL,
    operator_id text NOT NULL,
    account_id text NOT NULL,
    agent_id text NOT NULL,
    policy_id text NOT NULL,
    policy_revision integer NOT NULL,
    rule_section text NOT NULL,
    rule_id text NOT NULL,
    action_type text NOT NULL,
    call_digest text NOT NULL,
    summary text NOT NULL,
    governance_approval_id text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    consuming_owner_hash text,
    expires_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    amount_cents bigint,
    payment_surface text,
    CONSTRAINT control_reviews_owner_check CHECK (((consuming_owner_hash IS NULL) OR (consuming_owner_hash ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT control_reviews_payment_check CHECK ((((payment_surface IS NULL) AND (amount_cents IS NULL)) OR ((payment_surface = ANY (ARRAY['card'::text, 'wallet'::text])) AND (amount_cents IS NOT NULL) AND (amount_cents >= 0)))),
    CONSTRAINT control_reviews_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'consuming'::text, 'consumed'::text, 'rejected'::text, 'expired'::text])))
);
--> statement-breakpoint
CREATE TABLE public.control_sockets (
    operator_id text NOT NULL,
    socket_id text NOT NULL,
    decision_mode text DEFAULT 'auto'::text NOT NULL,
    decision_url text,
    decision_candidate_url text,
    decision_timeout_ms integer DEFAULT 1500 NOT NULL,
    decision_candidate_timeout_ms integer,
    decision_secret_encrypted text,
    decision_secret_previous_encrypted text,
    decision_secret_rotated_at timestamp with time zone,
    decision_status text DEFAULT 'unverified'::text NOT NULL,
    decision_verified_at timestamp with time zone,
    decision_bad_answers integer DEFAULT 0 NOT NULL,
    checked_types text[],
    events_url text,
    events_secret_encrypted text,
    events_secret_previous_encrypted text,
    events_secret_rotated_at timestamp with time zone,
    events_status text DEFAULT 'off'::text NOT NULL,
    events_verified_at timestamp with time zone,
    events_last_seq bigint DEFAULT 0 NOT NULL,
    events_acked_seq bigint DEFAULT 0 NOT NULL,
    events_attempts integer DEFAULT 0 NOT NULL,
    events_client_errors integer DEFAULT 0 NOT NULL,
    events_first_failure_at timestamp with time zone,
    events_next_attempt_at timestamp with time zone,
    events_lease_until timestamp with time zone,
    events_last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT control_sockets_decision_mode_check CHECK ((decision_mode = ANY (ARRAY['auto'::text, 'none'::text, 'hosted'::text, 'remote'::text]))),
    CONSTRAINT control_sockets_decision_status_check CHECK ((decision_status = ANY (ARRAY['unverified'::text, 'enforcing'::text, 'paused'::text]))),
    CONSTRAINT control_sockets_events_active_check CHECK (((events_status <> ALL (ARRAY['active'::text, 'failing'::text])) OR ((events_url IS NOT NULL) AND (events_secret_encrypted IS NOT NULL)))),
    CONSTRAINT control_sockets_events_status_check CHECK ((events_status = ANY (ARRAY['off'::text, 'unverified'::text, 'active'::text, 'failing'::text]))),
    CONSTRAINT control_sockets_remote_check CHECK (((decision_mode <> 'remote'::text) OR ((decision_url IS NOT NULL) AND (decision_secret_encrypted IS NOT NULL) AND (decision_status <> 'unverified'::text)))),
    CONSTRAINT control_sockets_seq_check CHECK ((events_acked_seq <= events_last_seq)),
    CONSTRAINT control_sockets_timeout_check CHECK (((decision_timeout_ms >= 300) AND (decision_timeout_ms <= 2000)))
);
--> statement-breakpoint
CREATE TABLE public.dropoffs (
    id text NOT NULL,
    operator_id text NOT NULL,
    from_agent_id text NOT NULL,
    to_agent_id text NOT NULL,
    schema jsonb NOT NULL,
    status text DEFAULT 'created'::text NOT NULL,
    on_expire text DEFAULT 'notify'::text NOT NULL,
    payload_hash text,
    payload_encrypted text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deposited_at timestamp with time zone,
    collected_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    mission_id text,
    deposited_bytes bigint DEFAULT 0 NOT NULL,
    payload_envelope_version integer DEFAULT 2 NOT NULL,
    provenance jsonb,
    CONSTRAINT dropoffs_deposited_bytes_nonnegative_check CHECK ((deposited_bytes >= 0)),
    CONSTRAINT dropoffs_payload_envelope_version_check CHECK ((payload_envelope_version = ANY (ARRAY[1, 2]))),
    CONSTRAINT dropoffs_payload_lifecycle_check CHECK ((((status = 'deposited'::text) AND (payload_encrypted IS NOT NULL)) OR ((status <> 'deposited'::text) AND (payload_encrypted IS NULL)))),
    CONSTRAINT dropoffs_status_check CHECK ((status = ANY (ARRAY['created'::text, 'deposited'::text, 'collected'::text, 'expired'::text])))
);
--> statement-breakpoint
CREATE TABLE public.erased_operators (
    operator_id text NOT NULL,
    erased_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.evidence_pack_artifacts (
    pack_id text NOT NULL,
    claim_id text NOT NULL,
    operator_id text NOT NULL,
    object_key text NOT NULL,
    byte_size integer NOT NULL,
    manifest_sha256 text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT evidence_pack_artifacts_byte_size_check CHECK ((byte_size > 0)),
    CONSTRAINT evidence_pack_artifacts_manifest_sha256_check CHECK ((manifest_sha256 ~ '^[0-9a-f]{64}$'::text))
);
--> statement-breakpoint
CREATE TABLE public.external_anchors (
    id text NOT NULL,
    operator_id text NOT NULL,
    anchored_at_ms bigint NOT NULL,
    chain_head_hash text NOT NULL,
    chain_head_at_audit_position integer NOT NULL,
    registry text NOT NULL,
    permalink text NOT NULL,
    commit_sha text NOT NULL,
    chain_head_signature text NOT NULL,
    stack_system_attestation text
);
--> statement-breakpoint
CREATE TABLE public.fleet_memberships (
    id text NOT NULL,
    policy_id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    enrolled_by text NOT NULL,
    enrollment_key_hash text NOT NULL,
    enrollment_payload_hash text NOT NULL,
    identity_expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE public.fleet_mission_starts (
    id text NOT NULL,
    operator_id text NOT NULL,
    policy_id text NOT NULL,
    agent_id text NOT NULL,
    key_hash text NOT NULL,
    payload_hash text NOT NULL,
    mission_id text NOT NULL,
    state text DEFAULT 'starting'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT fleet_mission_starts_state_check CHECK ((state = ANY (ARRAY['starting'::text, 'ready'::text])))
);
--> statement-breakpoint
CREATE TABLE public.fleet_missions (
    mission_id text NOT NULL,
    policy_id text NOT NULL,
    policy_revision integer NOT NULL,
    membership_id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    access jsonb NOT NULL,
    limits jsonb NOT NULL,
    authority_binding_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    session_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    operations jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT fleet_missions_policy_revision_check CHECK ((policy_revision > 0))
);
--> statement-breakpoint
CREATE TABLE public.fleet_operations (
    id text NOT NULL,
    operator_id text NOT NULL,
    policy_id text NOT NULL,
    policy_revision integer NOT NULL,
    mission_id text NOT NULL,
    agent_id text NOT NULL,
    operation_key_hash text NOT NULL,
    request_hash text NOT NULL,
    producer text NOT NULL,
    rule_id text NOT NULL,
    state text DEFAULT 'reserved'::text NOT NULL,
    reserved_spend_cents bigint DEFAULT 0 NOT NULL,
    reserved_bytes bigint DEFAULT 0 NOT NULL,
    window_start timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    settled_at timestamp with time zone,
    intent_claim_id text,
    proxy_operation_id text,
    CONSTRAINT fleet_operations_policy_revision_check CHECK ((policy_revision > 0)),
    CONSTRAINT fleet_operations_reserved_bytes_check CHECK ((reserved_bytes >= 0)),
    CONSTRAINT fleet_operations_reserved_spend_cents_check CHECK ((reserved_spend_cents >= 0)),
    CONSTRAINT fleet_operations_state_check CHECK ((state = ANY (ARRAY['reserved'::text, 'dispatched'::text, 'settled'::text, 'unknown'::text, 'cancelled'::text])))
);
--> statement-breakpoint
CREATE TABLE public.fleet_policies (
    id text NOT NULL,
    operator_id text NOT NULL,
    root_agent_id text NOT NULL,
    revision integer NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT fleet_policies_revision_check CHECK ((revision > 0)),
    CONSTRAINT fleet_policies_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.fleet_policy_revisions (
    policy_id text NOT NULL,
    revision integer NOT NULL,
    definition jsonb NOT NULL,
    approved_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT fleet_policy_revisions_revision_check CHECK ((revision > 0))
);
--> statement-breakpoint
CREATE TABLE public.governance_approvals (
    id text NOT NULL,
    operator_id text NOT NULL,
    member_id text,
    action text NOT NULL,
    resource_id text NOT NULL,
    payload_hash text NOT NULL,
    summary text NOT NULL,
    requested_via text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_by_member_id text,
    consumed_idempotency_key_hash text,
    policy_preview jsonb,
    decided_by_partner_operator_id text,
    decided_via text,
    decided_mcp_session_hash text,
    decided_elicitation_id text,
    decided_oauth_client_id text,
    decided_chat_identity_id text,
    decided_chat_request_id text,
    CONSTRAINT governance_approvals_authority_idempotency_check CHECK ((((consumed_idempotency_key_hash IS NULL) AND ((action <> ALL (ARRAY['fleet_policy_activate'::text, 'authority_proof_erase'::text, 'authority_binding_activate'::text, 'authority_receiver_key_add'::text, 'authority_profile_activate'::text, 'authority_principal_erase'::text, 'authority_binding_erase'::text, 'authority_presentation_erase'::text, 'account_open'::text])) OR (status <> 'consumed'::text))) OR ((consumed_idempotency_key_hash ~ '^[0-9a-f]{64}$'::text) AND (action = ANY (ARRAY['fleet_policy_activate'::text, 'authority_proof_erase'::text, 'authority_binding_activate'::text, 'authority_receiver_key_add'::text, 'authority_profile_activate'::text, 'authority_principal_erase'::text, 'authority_binding_erase'::text, 'authority_presentation_erase'::text, 'account_open'::text])) AND (status = 'consumed'::text) AND (consumed_at IS NOT NULL)))),
    CONSTRAINT governance_approvals_decided_via_check CHECK (((decided_via IS NULL) OR (decided_via = ANY (ARRAY['dashboard'::text, 'bearer_reject'::text])) OR ((decided_via = 'chat_elicitation'::text) AND (decided_mcp_session_hash ~ '^[0-9a-f]{64}$'::text) AND (decided_elicitation_id IS NOT NULL) AND (decided_oauth_client_id IS NOT NULL)) OR ((decided_via = ANY (ARRAY['chat_telegram'::text, 'chat_sms'::text, 'chat_slack'::text])) AND (decided_chat_identity_id IS NOT NULL) AND (decided_chat_request_id IS NOT NULL)))),
    CONSTRAINT governance_approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'consumed'::text, 'expired'::text])))
);
--> statement-breakpoint
CREATE TABLE public.identity_claims (
    id text NOT NULL,
    operator_id text NOT NULL,
    provider_id text NOT NULL,
    provider_key text NOT NULL,
    layer text NOT NULL,
    claim_type text NOT NULL,
    assurance_level text NOT NULL,
    verified_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    assertion_encrypted text NOT NULL,
    payload_encrypted text,
    delegated_scopes jsonb,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    claim_id text
);
--> statement-breakpoint
CREATE TABLE public.identity_providers (
    id text NOT NULL,
    name text NOT NULL,
    provider_key text NOT NULL,
    supported_layers jsonb NOT NULL,
    claim_types jsonb NOT NULL,
    assurance_level text NOT NULL,
    verification_endpoint text,
    jwks_uri text,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.identity_verification_sessions (
    id text NOT NULL,
    operator_id text NOT NULL,
    provider_key text NOT NULL,
    session_ref text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    requested_claims jsonb NOT NULL,
    provider_data text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    initiated_by text,
    CONSTRAINT identity_verification_sessions_initiated_by_check CHECK (((initiated_by IS NULL) OR (initiated_by = ANY (ARRAY['owner'::text, 'member'::text, 'authority'::text])))),
    CONSTRAINT identity_verification_sessions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'completed'::text, 'failed'::text])))
);
--> statement-breakpoint
CREATE TABLE public.inbound_webhook_receipts (
    webhook_id text NOT NULL,
    provider_message_id text NOT NULL,
    seen_at timestamp with time zone DEFAULT now() NOT NULL,
    state text DEFAULT 'completed'::text NOT NULL,
    body_hash text,
    attempt_id text,
    lease_expires_at timestamp with time zone,
    metered_at timestamp with time zone,
    scan_verdict text,
    completed_at timestamp with time zone,
    CONSTRAINT inbound_webhook_receipts_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'processing'::text, 'completed'::text])))
);
--> statement-breakpoint
CREATE TABLE public.inbound_webhooks (
    id text NOT NULL,
    operator_id text NOT NULL,
    provider text NOT NULL,
    slug text NOT NULL,
    forward_url text,
    webhook_secret_encrypted text NOT NULL,
    agent_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    last_block_at timestamp with time zone,
    total_calls integer DEFAULT 0 NOT NULL,
    total_blocked integer DEFAULT 0 NOT NULL,
    created_via_grant_id text,
    generic_config jsonb,
    provider_signing_secret_encrypted text
);
--> statement-breakpoint
CREATE TABLE public.intent_approvals (
    id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    passport_jti text NOT NULL,
    intent_claim_id text NOT NULL,
    simulated_claim_id text,
    status text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    decided_by_member_id text,
    notes text,
    block_future boolean DEFAULT false NOT NULL,
    consuming_owner_hash text,
    fleet_policy_id text,
    fleet_policy_revision integer,
    fleet_mission_id text,
    fleet_request_hash text,
    fleet_review_key text,
    fleet_review_encrypted text,
    fleet_review_key_ref text,
    CONSTRAINT ia_consuming_owner_check CHECK ((((status = ANY (ARRAY['approved'::text, 'consuming'::text, 'consumed'::text])) OR (consuming_owner_hash IS NULL)) AND ((consuming_owner_hash IS NULL) OR (consuming_owner_hash ~ '^[0-9a-f]{64}$'::text)))),
    CONSTRAINT ia_fleet_binding_complete CHECK ((((fleet_policy_id IS NULL) AND (fleet_policy_revision IS NULL) AND (fleet_mission_id IS NULL) AND (fleet_request_hash IS NULL) AND (fleet_review_key IS NULL)) OR ((fleet_policy_id IS NOT NULL) AND (fleet_policy_revision IS NOT NULL) AND (fleet_policy_revision > 0) AND (fleet_mission_id IS NOT NULL) AND (fleet_request_hash IS NOT NULL) AND (fleet_review_key IS NOT NULL) AND (fleet_request_hash ~ '^[0-9a-f]{64}$'::text) AND (fleet_review_key ~ '^[0-9a-f]{64}$'::text)))),
    CONSTRAINT ia_fleet_review_custody_complete CHECK ((((fleet_review_encrypted IS NULL) AND (fleet_review_key_ref IS NULL)) OR ((fleet_review_encrypted IS NOT NULL) AND (fleet_review_key_ref IS NOT NULL) AND (fleet_policy_id IS NOT NULL)))),
    CONSTRAINT intent_approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'consuming'::text, 'consumed'::text, 'expired'::text])))
);
--> statement-breakpoint
CREATE TABLE public.llm_usage (
    id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    passport_jti text NOT NULL,
    mission_id text,
    provider text NOT NULL,
    model text NOT NULL,
    prompt_tokens integer NOT NULL,
    completion_tokens integer NOT NULL,
    total_tokens integer NOT NULL,
    provider_cost_cents integer,
    markup_cents integer,
    total_cost_cents integer,
    wallet_debited boolean DEFAULT false NOT NULL,
    streaming boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    provider_cost_microcents bigint,
    markup_microcents bigint,
    total_cost_microcents bigint,
    cost_basis text,
    cached_prompt_tokens integer,
    surface text DEFAULT 'gateway'::text NOT NULL,
    provider_payer text DEFAULT 'customer_provider'::text NOT NULL,
    stack_fee_payer text DEFAULT 'stack_wallet'::text NOT NULL,
    wallet_hold_id text,
    wallet_fee_kind text,
    wallet_fee_microcents bigint,
    wallet_fee_microcents_remaining bigint,
    skill_id text,
    invocation_id text,
    sealed_step_index integer,
    CONSTRAINT llm_usage_provider_payer_check CHECK ((provider_payer = ANY (ARRAY['customer_provider'::text, 'stack_plan'::text, 'stack_wallet'::text, 'stack_comped'::text]))),
    CONSTRAINT llm_usage_sealed_step_check CHECK (((sealed_step_index IS NULL) OR (sealed_step_index >= 0))),
    CONSTRAINT llm_usage_stack_fee_payer_check CHECK ((stack_fee_payer = ANY (ARRAY['stack_plan'::text, 'stack_wallet'::text, 'stack_comped'::text, 'none'::text]))),
    CONSTRAINT llm_usage_surface_check CHECK ((surface = ANY (ARRAY['gateway'::text, 'sealed_execution'::text, 'prompt_injection_l3'::text, 'intent_deviation'::text, 'memory'::text]))),
    CONSTRAINT llm_usage_wallet_fee_pair_check CHECK ((((wallet_fee_kind IS NULL) AND (wallet_fee_microcents IS NULL) AND (wallet_fee_microcents_remaining IS NULL)) OR ((wallet_fee_kind IS NOT NULL) AND (wallet_fee_microcents >= 0) AND (wallet_fee_microcents_remaining >= 0) AND (wallet_fee_microcents_remaining <= wallet_fee_microcents))))
);
--> statement-breakpoint
CREATE TABLE public.magic_link_tokens (
    id text NOT NULL,
    email text NOT NULL,
    token_hash text NOT NULL,
    code_hash text,
    intent text NOT NULL,
    operator_id text,
    used boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    member_id text,
    browser_binding_hash text
);
--> statement-breakpoint
CREATE TABLE public.mission_outputs (
    mission_id text NOT NULL,
    operator_id text NOT NULL,
    output_digest text NOT NULL,
    output_encrypted text NOT NULL,
    key_ref text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mission_outputs_output_digest_check CHECK ((output_digest ~ '^[a-f0-9]{64}$'::text))
);
--> statement-breakpoint
CREATE TABLE public.missions (
    mission_id text NOT NULL,
    claim_id text NOT NULL,
    operator_id text NOT NULL,
    intent_summary text NOT NULL,
    intent_services text[] DEFAULT '{}'::text[] NOT NULL,
    expected_counterparties text[] DEFAULT '{}'::text[] NOT NULL,
    max_actions integer,
    max_dropoff_bytes bigint,
    coverage_cap_cents bigint,
    max_duration_seconds integer,
    max_concurrent_intents integer,
    max_actions_per_service jsonb DEFAULT '{}'::jsonb NOT NULL,
    cap_behavior jsonb DEFAULT '{}'::jsonb NOT NULL,
    baseline_profile jsonb,
    expected_output_shape jsonb,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_reason text,
    terminal_state text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    passport_jti text,
    assigned_agent_id text,
    authorization_digest text
);
--> statement-breakpoint
CREATE TABLE public.notification_channel_verifications (
    id text NOT NULL,
    channel_id text,
    destination_id text,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    code_hash text
);
--> statement-breakpoint
CREATE TABLE public.notification_channels (
    id text NOT NULL,
    operator_id text NOT NULL,
    destination_id text,
    destination_ids jsonb,
    channel_type text NOT NULL,
    destination text NOT NULL,
    events text[] NOT NULL,
    min_severity text DEFAULT 'warning'::text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    webhook_secret_encrypted text
);
--> statement-breakpoint
CREATE TABLE public.notification_destinations (
    id text NOT NULL,
    operator_id text NOT NULL,
    channel_type text NOT NULL,
    destination text NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    webhook_secret_encrypted text
);
--> statement-breakpoint
CREATE TABLE public.oauth_authorization_codes (
    code_hash text NOT NULL,
    client_id text NOT NULL,
    operator_id text NOT NULL,
    member_id text,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    resource text NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method text DEFAULT 'S256'::text NOT NULL,
    nonce text,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE public.oauth_clients (
    id text NOT NULL,
    client_secret_hash text,
    client_type text NOT NULL,
    client_name text NOT NULL,
    redirect_uris jsonb NOT NULL,
    grant_types jsonb NOT NULL,
    response_types jsonb NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    scope text,
    software_id text,
    software_version text,
    metadata_url text,
    operator_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.oauth_device_codes (
    device_code_hash text NOT NULL,
    user_code text NOT NULL,
    client_id text NOT NULL,
    scope text NOT NULL,
    resource text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    operator_id text,
    member_id text,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    interval_seconds integer DEFAULT 5 NOT NULL,
    last_polled_at timestamp with time zone,
    approved_at timestamp with time zone,
    denied_at timestamp with time zone,
    CONSTRAINT oauth_device_codes_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text, 'expired'::text])))
);
--> statement-breakpoint
CREATE TABLE public.oauth_refresh_tokens (
    token_hash text NOT NULL,
    token_family_id text NOT NULL,
    client_id text NOT NULL,
    operator_id text NOT NULL,
    member_id text,
    scope text NOT NULL,
    resource text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    replaced_by_hash text,
    revoked_at timestamp with time zone,
    revoked_reason text,
    last_used_at timestamp with time zone,
    last_used_ip text,
    last_used_ua text,
    replacement_token_encrypted text,
    replacement_retry_expires_at timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE public.oidc_idp_configs (
    id text NOT NULL,
    operator_id text NOT NULL,
    display_name text,
    issuer_uri text NOT NULL,
    client_id text NOT NULL,
    client_secret_encrypted text NOT NULL,
    audience text,
    redirect_uri text NOT NULL,
    scopes_json jsonb DEFAULT '["openid", "email", "profile"]'::jsonb NOT NULL,
    claim_mapping_policy_json jsonb,
    discovery_cached_json jsonb,
    jwks_cached_jwks_json jsonb,
    jwks_cached_at timestamp with time zone,
    jwks_cache_ttl_seconds integer DEFAULT 300 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    allowed_return_origins jsonb,
    sso_slug text,
    sso_login_enabled boolean DEFAULT false NOT NULL,
    default_member_role text DEFAULT 'standard'::text NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.operator_decision_sources (
    decision_id text NOT NULL,
    operator_id text NOT NULL,
    source_type text NOT NULL,
    source_id text NOT NULL,
    CONSTRAINT operator_decision_sources_type_check CHECK ((source_type = ANY (ARRAY['checkout'::text, 'security_event'::text, 'detector_claim'::text, 'approval'::text])))
);
--> statement-breakpoint
CREATE TABLE public.operator_decisions (
    id text NOT NULL,
    claim_id text NOT NULL,
    operator_id text NOT NULL,
    mission_id text NOT NULL,
    idempotency_key text NOT NULL,
    action text NOT NULL,
    effect text NOT NULL,
    effect_scope text NOT NULL,
    target_agent_id text,
    author_kind text NOT NULL,
    author_member_id text,
    author_role text,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    author_partner_operator_id text,
    CONSTRAINT operator_decisions_author_check CHECK ((((author_kind = 'operator_owner'::text) AND (author_member_id IS NULL) AND (author_role IS NULL) AND (author_partner_operator_id IS NULL)) OR ((author_kind = 'team_member'::text) AND (author_member_id IS NOT NULL) AND (author_role = ANY (ARRAY['standard'::text, 'admin'::text])) AND (author_partner_operator_id IS NULL)) OR ((author_kind = 'partner_admin'::text) AND (author_partner_operator_id IS NOT NULL) AND (action = ANY (ARRAY['governance_approved'::text, 'governance_rejected'::text])) AND (((author_member_id IS NULL) AND (author_role IS NULL)) OR ((author_member_id IS NOT NULL) AND (author_role = 'admin'::text)))))),
    CONSTRAINT operator_decisions_effect_scope_check CHECK ((effect_scope = ANY (ARRAY['mission'::text, 'agent_global'::text])))
);
--> statement-breakpoint
CREATE TABLE public.operator_detector_config (
    id text NOT NULL,
    operator_id text NOT NULL,
    detector_key text NOT NULL,
    custom_patterns jsonb DEFAULT '[]'::jsonb NOT NULL,
    whitelist_patterns jsonb DEFAULT '[]'::jsonb NOT NULL,
    severity_overrides jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.operator_email_changes (
    id text NOT NULL,
    operator_id text NOT NULL,
    new_email text NOT NULL,
    old_email text NOT NULL,
    confirm_token_hash text NOT NULL,
    cancel_token_hash text NOT NULL,
    requested_by_member_id text,
    expires_at timestamp with time zone NOT NULL,
    confirmed_at timestamp with time zone,
    cancelled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    delivery_ready_at timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE public.operator_email_delivery_jobs (
    id text NOT NULL,
    operator_id text NOT NULL,
    email_change_id text NOT NULL,
    kind text DEFAULT 'completion_notice'::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    claim_id text,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT operator_email_delivery_jobs_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT operator_email_delivery_jobs_error_code_check CHECK (((last_error_code IS NULL) OR (last_error_code = 'delivery_failed'::text))),
    CONSTRAINT operator_email_delivery_jobs_kind_check CHECK ((kind = 'completion_notice'::text)),
    CONSTRAINT operator_email_delivery_jobs_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text])))
);
--> statement-breakpoint
CREATE TABLE public.operator_erasure_jobs (
    operator_id text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    claim_id text,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT operator_erasure_jobs_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT operator_erasure_jobs_error_code_check CHECK (((last_error_code IS NULL) OR (last_error_code = ANY (ARRAY['archive_store_not_durable'::text, 'archive_list_failed'::text, 'archive_delete_failed'::text, 'archive_verify_failed'::text, 'database_delete_failed'::text, 'memory_erase_failed'::text])))),
    CONSTRAINT operator_erasure_jobs_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text])))
);
--> statement-breakpoint
CREATE TABLE public.operator_oauth_apps (
    id text NOT NULL,
    operator_id text NOT NULL,
    provider text NOT NULL,
    client_id text NOT NULL,
    client_secret_encrypted text NOT NULL,
    scopes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.operator_pii_config (
    id text NOT NULL,
    operator_id text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    threshold double precision,
    countries jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.operator_signing_keys (
    kid text NOT NULL,
    operator_id text NOT NULL,
    private_key_wrapped text NOT NULL,
    public_jwk jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    active_from timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    revoked_at timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE public.operators (
    id text NOT NULL,
    email text NOT NULL,
    tier text DEFAULT 'free'::text NOT NULL,
    is_admin boolean DEFAULT false NOT NULL,
    is_platform_staff boolean DEFAULT false NOT NULL,
    api_key_hash text NOT NULL,
    stripe_customer_id text,
    stripe_subscription_id text,
    billing_period_start timestamp with time zone,
    billing_period_end timestamp with time zone,
    identity_claim_ttl text DEFAULT '1y'::text NOT NULL,
    identity_claim_inheritance text DEFAULT 'auto'::text NOT NULL,
    identity_auto_revoke boolean DEFAULT false NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    comped boolean DEFAULT false NOT NULL,
    suspended_at timestamp with time zone,
    suspended_reason text,
    suspended_by text,
    deleted_at timestamp with time zone,
    cmek_key_arn text,
    cmek_status text DEFAULT 'none'::text NOT NULL,
    cmek_activated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_partner boolean DEFAULT false NOT NULL,
    parent_operator_id text,
    external_customer_id text,
    partner_providers jsonb,
    provisioned_via_grant_id text,
    claimed_at timestamp with time zone,
    purchased_seats integer DEFAULT 0 NOT NULL,
    audit_retention_days_override integer,
    owner_session_revision text DEFAULT '0'::text NOT NULL,
    limit_overrides jsonb,
    identity_verified_at timestamp with time zone,
    spend_frozen_at timestamp with time zone,
    spend_frozen_reason text,
    controls_status text DEFAULT 'off'::text NOT NULL,
    platform_status text DEFAULT 'none'::text NOT NULL,
    platform_subscription_id text,
    platform_trial_started_at timestamp with time zone,
    controls_subscription_id text,
    controls_trial_started_at timestamp with time zone,
    CONSTRAINT operators_cmek_status_check CHECK ((cmek_status = ANY (ARRAY['none'::text, 'migrating'::text, 'active'::text, 'revoking'::text, 'revoked'::text]))),
    CONSTRAINT operators_controls_status_check CHECK ((controls_status = ANY (ARRAY['off'::text, 'trialing'::text, 'active'::text, 'lapsed'::text]))),
    CONSTRAINT operators_limit_overrides_billing_root_check CHECK (((parent_operator_id IS NULL) OR (limit_overrides IS NULL))),
    CONSTRAINT operators_limit_overrides_object_check CHECK (((limit_overrides IS NULL) OR (jsonb_typeof(limit_overrides) = 'object'::text))),
    CONSTRAINT operators_platform_status_check CHECK ((platform_status = ANY (ARRAY['none'::text, 'incomplete'::text, 'trialing'::text, 'active'::text, 'past_due'::text, 'lapsed'::text, 'canceled'::text]))),
    CONSTRAINT operators_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'soft_deleted'::text, 'deleted'::text]))),
    CONSTRAINT operators_tier_check CHECK ((tier = ANY (ARRAY['free'::text, 'developer'::text, 'pro'::text, 'business'::text, 'enterprise'::text])))
);
--> statement-breakpoint
CREATE TABLE public.partner_grants (
    id text NOT NULL,
    partner_operator_id text NOT NULL,
    user_operator_id text NOT NULL,
    external_customer_id text,
    token_hash text NOT NULL,
    scopes jsonb NOT NULL,
    allowed_providers jsonb NOT NULL,
    status text DEFAULT 'pending_consent'::text NOT NULL,
    user_provisioned boolean NOT NULL,
    consent_token_hash text,
    consent_expires_at timestamp with time zone,
    consented_at timestamp with time zone,
    optout_token_hash text,
    revoked_at timestamp with time zone,
    revoked_by text,
    revoke_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT partner_grants_status_check CHECK ((status = ANY (ARRAY['pending_consent'::text, 'active'::text, 'declined'::text, 'expired'::text, 'revoked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.passport_authority_bindings (
    passport_jti text NOT NULL,
    operator_id text NOT NULL,
    binding_id text NOT NULL,
    binding_version integer NOT NULL,
    binding_claim_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.passport_checkouts (
    id text NOT NULL,
    passport_jti text NOT NULL,
    operator_id text NOT NULL,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    services_used text[],
    tool_calls jsonb,
    actions_count integer DEFAULT 0 NOT NULL,
    delegations text[],
    summary text,
    review_status text DEFAULT 'pending'::text NOT NULL,
    review_flags jsonb,
    reviewed_at timestamp with time zone,
    mission_id text,
    CONSTRAINT passport_checkouts_review_status_check CHECK ((review_status = ANY (ARRAY['pending'::text, 'clean'::text, 'flagged'::text, 'blocked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.passport_checkpoints (
    id text NOT NULL,
    passport_jti text NOT NULL,
    operator_id text NOT NULL,
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    services_used text[],
    tool_calls jsonb,
    actions_count integer DEFAULT 0 NOT NULL,
    delegations text[],
    summary text,
    total_actions integer DEFAULT 0 NOT NULL,
    total_services text[],
    claim_id text
);
--> statement-breakpoint
CREATE TABLE public.passport_claims (
    claim_id text NOT NULL,
    passport_id text,
    type text NOT NULL,
    body_json jsonb NOT NULL,
    claim_hash text NOT NULL,
    signature text NOT NULL,
    attached_at timestamp with time zone DEFAULT now() NOT NULL,
    operator_id text,
    subject text,
    envelope_version integer,
    claim_version integer,
    envelope_cose text,
    issuer text,
    issued_at_ms bigint,
    receipt jsonb,
    revoked_at timestamp with time zone,
    revoked_reason text,
    source_operation_id text,
    source_role text
);
--> statement-breakpoint
CREATE TABLE public.passport_reviews (
    id text NOT NULL,
    checkout_id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    decision text NOT NULL,
    notes text,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    block_future boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.passports (
    jti text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    session_id text NOT NULL,
    delegation_depth integer DEFAULT 0 NOT NULL,
    parent_passport_id text,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    intent_summary text,
    intent_services text[],
    intent_refs jsonb,
    intent_delegates boolean DEFAULT false NOT NULL,
    estimated_duration_seconds integer,
    checkpoint_interval_seconds integer,
    last_checkpoint_at timestamp with time zone,
    checkpoint_count integer DEFAULT 0 NOT NULL,
    checked_out_at timestamp with time zone,
    checkout_status text,
    checkout_flags jsonb,
    identity_claim_ids jsonb,
    mission_ids text[],
    CONSTRAINT passports_checkout_status_check CHECK ((checkout_status = ANY (ARRAY['clean'::text, 'flagged'::text, 'blocked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.proxy_accounting_receipts (
    id text NOT NULL,
    operator_id text NOT NULL,
    accounting_period text NOT NULL,
    operation_key_hash text NOT NULL,
    evaluation_hash text NOT NULL,
    verdict text NOT NULL,
    period_sequence integer NOT NULL,
    allowance_units integer DEFAULT 1 NOT NULL,
    overage_units_10000th_cent bigint DEFAULT 0 NOT NULL,
    wallet_obligation_id text NOT NULL,
    wallet_transaction_id text,
    wallet_state text DEFAULT 'none'::text NOT NULL,
    evaluated_at timestamp with time zone DEFAULT now() NOT NULL,
    wallet_committed_at timestamp with time zone,
    CONSTRAINT proxy_accounting_receipts_values_check CHECK (((accounting_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'::text) AND (period_sequence > 0) AND (allowance_units = 1) AND (overage_units_10000th_cent >= 0))),
    CONSTRAINT proxy_accounting_receipts_verdict_check CHECK ((verdict = ANY (ARRAY['admitted'::text, 'denied'::text]))),
    CONSTRAINT proxy_accounting_receipts_wallet_check CHECK ((((overage_units_10000th_cent = 0) AND (wallet_state = 'none'::text) AND (wallet_transaction_id IS NULL) AND (wallet_committed_at IS NULL)) OR ((overage_units_10000th_cent > 0) AND (wallet_state = 'pending'::text) AND (wallet_transaction_id IS NULL) AND (wallet_committed_at IS NULL)) OR ((overage_units_10000th_cent > 0) AND (wallet_state = 'committed'::text) AND (wallet_transaction_id IS NOT NULL) AND (wallet_committed_at IS NOT NULL))))
);
--> statement-breakpoint
CREATE TABLE public.proxy_operation_attempts (
    id text NOT NULL,
    operator_id text NOT NULL,
    operation_id text NOT NULL,
    attempt_number integer NOT NULL,
    dispatch_owner_hash text NOT NULL,
    dispatch_fence integer NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    request_evidence_hash text NOT NULL,
    transport_evidence_hash text,
    provider_request_id_hash text,
    outcome text DEFAULT 'pending'::text NOT NULL,
    response_status integer,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    late_evidence_at timestamp with time zone,
    contradictory_evidence_hash text,
    CONSTRAINT proxy_operation_attempts_completion_check CHECK ((((outcome = 'pending'::text) AND (completed_at IS NULL)) OR ((outcome <> 'pending'::text) AND (completed_at IS NOT NULL)))),
    CONSTRAINT proxy_operation_attempts_number_check CHECK ((((attempt_number >= 1) AND (attempt_number <= 3)) AND (dispatch_fence > 0))),
    CONSTRAINT proxy_operation_attempts_outcome_check CHECK ((outcome = ANY (ARRAY['pending'::text, 'response_received'::text, 'outcome_unknown'::text, 'reconciled'::text, 'contradictory'::text]))),
    CONSTRAINT proxy_operation_attempts_owner_hash_check CHECK ((dispatch_owner_hash ~ '^[0-9a-f]{64}$'::text))
);
--> statement-breakpoint
CREATE TABLE public.proxy_operation_evidence (
    id text NOT NULL,
    operator_id text NOT NULL,
    operation_id text NOT NULL,
    kind text NOT NULL,
    evidence_hash text NOT NULL,
    reconciliation_state text,
    resource_hash text,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT proxy_operation_evidence_kind_check CHECK ((kind = ANY (ARRAY['reconciliation'::text, 'late'::text, 'contradictory'::text])))
);
--> statement-breakpoint
CREATE TABLE public.proxy_operation_replacement_acknowledgements (
    id text NOT NULL,
    operator_id text NOT NULL,
    original_operation_id text NOT NULL,
    replacement_operation_key_hash text NOT NULL,
    replacement_request_hash text NOT NULL,
    warning_version integer NOT NULL,
    warning_text text NOT NULL,
    warning_hash text NOT NULL,
    human_author_kind text NOT NULL,
    human_author_id text NOT NULL,
    dashboard_session_family_id text NOT NULL,
    dashboard_session_token_hash text NOT NULL,
    acknowledged_at timestamp with time zone DEFAULT now() NOT NULL,
    consumed_at timestamp with time zone,
    consumed_by_operation_id text,
    CONSTRAINT proxy_operation_replacement_author_check CHECK ((human_author_kind = ANY (ARRAY['operator_owner'::text, 'team_member'::text]))),
    CONSTRAINT proxy_operation_replacement_consumption_check CHECK ((((consumed_at IS NULL) AND (consumed_by_operation_id IS NULL)) OR ((consumed_at IS NOT NULL) AND (consumed_by_operation_id IS NOT NULL)))),
    CONSTRAINT proxy_operation_replacement_hashes_check CHECK (((replacement_operation_key_hash ~ '^[0-9a-f]{64}$'::text) AND (replacement_request_hash ~ '^sha256:[0-9a-f]{64}$'::text) AND (warning_hash ~ '^sha256:[0-9a-f]{64}$'::text) AND (dashboard_session_token_hash ~ '^[0-9a-f]{64}$'::text)))
);
--> statement-breakpoint
CREATE TABLE public.proxy_operations (
    id text NOT NULL,
    operator_id text NOT NULL,
    operation_key_hash text NOT NULL,
    request_hash text NOT NULL,
    effect_correlation_hash text NOT NULL,
    tombstone_hash text NOT NULL,
    prepared_request_version integer DEFAULT 1 NOT NULL,
    prepared_request_encrypted text,
    prepared_request_key_ref text,
    prepared_request_readable_until timestamp with time zone NOT NULL,
    agent_id text NOT NULL,
    passport_jti text NOT NULL,
    authority_use_id text,
    approval_id text,
    service_connection_id text NOT NULL,
    service_id text NOT NULL,
    credential_version integer NOT NULL,
    provider text NOT NULL,
    method text NOT NULL,
    destination_config_hash text NOT NULL,
    scope_commitment_hash text NOT NULL,
    scope_descriptor_version integer DEFAULT 1 NOT NULL,
    scope_descriptor_encrypted text,
    scope_descriptor_key_ref text,
    destination_origin text NOT NULL,
    pathname_hash text NOT NULL,
    query_hash text NOT NULL,
    header_names jsonb NOT NULL,
    headers_hash text NOT NULL,
    body_hash text,
    body_bytes bigint DEFAULT 0 NOT NULL,
    adapter_kind text DEFAULT 'generic'::text NOT NULL,
    native_idempotency_key_hash text,
    provider_account_hash text,
    retry_deadline timestamp with time zone,
    reconciliation_state text DEFAULT 'not_required'::text NOT NULL,
    reconciliation_resource_hash text,
    reconciliation_evidence_hash text,
    reconciliation_provider_status text,
    reconciliation_checked_at timestamp with time zone,
    contradictory_evidence_hash text,
    late_evidence_at timestamp with time zone,
    delivery_state text DEFAULT 'admitted'::text NOT NULL,
    replay_state text DEFAULT 'none'::text NOT NULL,
    accounting_state text DEFAULT 'reserved'::text NOT NULL,
    admission_owner_hash text NOT NULL,
    admission_fence integer DEFAULT 1 NOT NULL,
    admission_lease_expires_at timestamp with time zone NOT NULL,
    dispatch_owner_hash text,
    dispatch_fence integer DEFAULT 0 NOT NULL,
    dispatch_lease_expires_at timestamp with time zone,
    dispatch_started_at timestamp with time zone,
    transport_attempts integer DEFAULT 0 NOT NULL,
    response_status integer,
    response_hash text,
    response_envelope_version integer,
    response_encrypted text,
    response_key_ref text,
    response_ciphertext_bytes bigint,
    response_readable_until timestamp with time zone,
    response_received_at timestamp with time zone,
    outcome_unknown_at timestamp with time zone,
    capacity_reserved_bytes bigint DEFAULT 0 NOT NULL,
    capacity_used_bytes bigint DEFAULT 0 NOT NULL,
    capacity_released_at timestamp with time zone,
    accounting_period text NOT NULL,
    accounting_units integer DEFAULT 1 NOT NULL,
    accounting_cents bigint DEFAULT 0 NOT NULL,
    accounting_obligation_id text NOT NULL,
    wallet_transaction_id text,
    accounting_reserved_at timestamp with time zone DEFAULT now() NOT NULL,
    accounting_committed_at timestamp with time zone,
    accounting_released_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    erased_at timestamp with time zone,
    post_response_work_state text DEFAULT 'none'::text NOT NULL,
    post_response_context_version integer,
    post_response_context_encrypted text,
    post_response_context_key_ref text,
    post_response_owner_hash text,
    post_response_lease_expires_at timestamp with time zone,
    post_response_attempts integer DEFAULT 0 NOT NULL,
    post_response_credential_at timestamp with time zone,
    post_response_audit_at timestamp with time zone,
    post_response_claims_at timestamp with time zone,
    post_response_intent_claim_id text,
    post_response_outcome_claim_id text,
    post_response_security_at timestamp with time zone,
    post_response_analytics_at timestamp with time zone,
    post_response_authority_at timestamp with time zone,
    post_response_completed_at timestamp with time zone,
    post_response_next_attempt_at timestamp with time zone,
    CONSTRAINT proxy_operations_accounting_amount_check CHECK (((accounting_units = 1) AND (accounting_cents >= 0) AND (accounting_period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'::text))),
    CONSTRAINT proxy_operations_accounting_state_check CHECK ((accounting_state = ANY (ARRAY['reserved'::text, 'committed'::text, 'released'::text]))),
    CONSTRAINT proxy_operations_accounting_timestamps_check CHECK ((((accounting_state = 'reserved'::text) AND (accounting_committed_at IS NULL) AND (accounting_released_at IS NULL)) OR ((accounting_state = 'committed'::text) AND (accounting_committed_at IS NOT NULL) AND (accounting_released_at IS NULL)) OR ((accounting_state = 'released'::text) AND (accounting_committed_at IS NULL) AND (accounting_released_at IS NOT NULL)))),
    CONSTRAINT proxy_operations_adapter_binding_check CHECK ((((adapter_kind = 'generic'::text) AND (native_idempotency_key_hash IS NULL) AND (provider_account_hash IS NULL) AND (retry_deadline IS NULL) AND (reconciliation_state = 'not_required'::text)) OR ((adapter_kind = 'stripe'::text) AND (native_idempotency_key_hash IS NOT NULL) AND (provider_account_hash IS NOT NULL) AND (retry_deadline IS NOT NULL) AND (retry_deadline <= (created_at + '23:00:00'::interval)) AND (reconciliation_state = ANY (ARRAY['pending'::text, 'confirmed'::text, 'not_found'::text, 'contradictory'::text, 'expired'::text]))))),
    CONSTRAINT proxy_operations_adapter_check CHECK ((adapter_kind = ANY (ARRAY['generic'::text, 'stripe'::text]))),
    CONSTRAINT proxy_operations_capacity_check CHECK (((body_bytes >= 0) AND (capacity_reserved_bytes >= 0) AND (capacity_used_bytes >= 0) AND (capacity_used_bytes <= capacity_reserved_bytes))),
    CONSTRAINT proxy_operations_credential_version_check CHECK ((credential_version > 0)),
    CONSTRAINT proxy_operations_delivery_state_check CHECK ((delivery_state = ANY (ARRAY['admitted'::text, 'dispatching'::text, 'response_received'::text, 'outcome_unknown'::text]))),
    CONSTRAINT proxy_operations_dispatch_check CHECK ((((delivery_state = 'admitted'::text) AND (dispatch_owner_hash IS NULL) AND (dispatch_fence = 0) AND (dispatch_started_at IS NULL)) OR ((delivery_state <> 'admitted'::text) AND (dispatch_owner_hash IS NOT NULL) AND (dispatch_fence > 0) AND (dispatch_started_at IS NOT NULL)))),
    CONSTRAINT proxy_operations_effect_correlation_hash_check CHECK ((effect_correlation_hash ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT proxy_operations_erasure_check CHECK ((((replay_state = ANY (ARRAY['expired'::text, 'erased'::text])) AND (prepared_request_encrypted IS NULL) AND (prepared_request_key_ref IS NULL) AND (scope_descriptor_encrypted IS NULL) AND (scope_descriptor_key_ref IS NULL) AND (capacity_used_bytes = 0) AND (capacity_released_at IS NOT NULL)) OR (replay_state <> ALL (ARRAY['expired'::text, 'erased'::text])))),
    CONSTRAINT proxy_operations_fence_check CHECK (((admission_fence > 0) AND (dispatch_fence >= 0) AND ((transport_attempts >= 0) AND (transport_attempts <= 3)))),
    CONSTRAINT proxy_operations_method_check CHECK ((method = ANY (ARRAY['POST'::text, 'PUT'::text, 'PATCH'::text, 'DELETE'::text]))),
    CONSTRAINT proxy_operations_owner_hash_check CHECK (((admission_owner_hash ~ '^[0-9a-f]{64}$'::text) AND ((dispatch_owner_hash IS NULL) OR (dispatch_owner_hash ~ '^[0-9a-f]{64}$'::text)))),
    CONSTRAINT proxy_operations_post_response_attempts_check CHECK ((post_response_attempts >= 0)),
    CONSTRAINT proxy_operations_post_response_lease_check CHECK ((((post_response_work_state = 'processing'::text) AND (post_response_owner_hash ~ '^[0-9a-f]{64}$'::text) AND (post_response_lease_expires_at IS NOT NULL)) OR ((post_response_work_state <> 'processing'::text) AND (post_response_owner_hash IS NULL) AND (post_response_lease_expires_at IS NULL)))),
    CONSTRAINT proxy_operations_post_response_schedule_check CHECK ((((post_response_work_state = 'pending'::text) AND (post_response_next_attempt_at IS NOT NULL)) OR ((post_response_work_state <> 'pending'::text) AND (post_response_next_attempt_at IS NULL)))),
    CONSTRAINT proxy_operations_post_response_work_check CHECK ((((post_response_work_state = 'none'::text) AND (post_response_context_encrypted IS NULL) AND (post_response_context_key_ref IS NULL)) OR ((post_response_work_state = ANY (ARRAY['pending'::text, 'processing'::text, 'waiting_provider'::text])) AND (post_response_context_version = 1) AND (post_response_context_encrypted IS NOT NULL) AND (post_response_context_key_ref IS NOT NULL) AND (post_response_completed_at IS NULL)) OR ((post_response_work_state = 'completed'::text) AND (post_response_context_encrypted IS NULL) AND (post_response_context_key_ref IS NULL) AND (post_response_completed_at IS NOT NULL)) OR ((post_response_work_state = 'expired'::text) AND (post_response_context_encrypted IS NULL) AND (post_response_context_key_ref IS NULL) AND (post_response_completed_at IS NULL)))),
    CONSTRAINT proxy_operations_reconciliation_evidence_check CHECK ((((reconciliation_state = ANY (ARRAY['pending'::text, 'not_required'::text])) AND (reconciliation_evidence_hash IS NULL) AND (reconciliation_provider_status IS NULL)) OR ((reconciliation_state = 'confirmed'::text) AND (reconciliation_evidence_hash ~ '^sha256:[0-9a-f]{64}$'::text) AND (reconciliation_provider_status = ANY (ARRAY['pending'::text, 'requires_action'::text, 'succeeded'::text, 'failed'::text, 'canceled'::text]))) OR ((reconciliation_state = ANY (ARRAY['not_found'::text, 'contradictory'::text, 'expired'::text])) AND (reconciliation_evidence_hash ~ '^sha256:[0-9a-f]{64}$'::text) AND (reconciliation_provider_status IS NULL)))),
    CONSTRAINT proxy_operations_replay_state_check CHECK ((replay_state = ANY (ARRAY['none'::text, 'screening'::text, 'available'::text, 'expired'::text, 'erased'::text]))),
    CONSTRAINT proxy_operations_response_check CHECK ((((replay_state = 'available'::text) AND (delivery_state = 'response_received'::text) AND ((response_status >= 100) AND (response_status <= 599)) AND (response_hash IS NOT NULL) AND (response_envelope_version = 1) AND (response_encrypted IS NOT NULL) AND (response_key_ref IS NOT NULL) AND (response_ciphertext_bytes IS NOT NULL) AND (response_readable_until IS NOT NULL) AND (response_received_at IS NOT NULL)) OR ((replay_state <> 'available'::text) AND (response_encrypted IS NULL) AND (response_key_ref IS NULL) AND (response_ciphertext_bytes IS NULL))))
);
--> statement-breakpoint
CREATE TABLE public.receiver_transaction_receipts (
    id text NOT NULL,
    operator_id text NOT NULL,
    authority_use_id text NOT NULL,
    presentation_id text,
    receiver_id text NOT NULL,
    receiver_profile_version_id text NOT NULL,
    receiver_key_id text NOT NULL,
    receipt_jti_hash text NOT NULL,
    native_format text NOT NULL,
    native_receipt_encrypted text,
    receipt_hash text NOT NULL,
    request_hash text NOT NULL,
    result_hash text,
    outcome text NOT NULL,
    external_transaction_ref_hash text,
    verified_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    claim_id text,
    erased_at timestamp with time zone,
    tombstone_hash text,
    tombstone_claim_id text,
    CONSTRAINT receiver_transaction_receipts_erasure_check CHECK ((((erased_at IS NOT NULL) AND (native_receipt_encrypted IS NULL) AND (tombstone_hash IS NOT NULL) AND (tombstone_claim_id IS NOT NULL)) OR ((erased_at IS NULL) AND (tombstone_hash IS NULL) AND (tombstone_claim_id IS NULL)))),
    CONSTRAINT receiver_transaction_receipts_id_check CHECK ((id ~ '^rtr_[A-Za-z0-9_-]+$'::text)),
    CONSTRAINT receiver_transaction_receipts_outcome_check CHECK ((outcome = ANY (ARRAY['accepted'::text, 'rejected'::text, 'failed'::text])))
);
--> statement-breakpoint
CREATE TABLE public.security_events (
    id text NOT NULL,
    operator_id text NOT NULL,
    agent_id text NOT NULL,
    passport_jti text,
    signal_type text NOT NULL,
    severity text DEFAULT 'warning'::text NOT NULL,
    message text NOT NULL,
    metadata jsonb,
    resolved boolean DEFAULT false NOT NULL,
    resolved_by text,
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    claim_id text,
    mission_id text
);
--> statement-breakpoint
CREATE TABLE public.service_configurations (
    id text NOT NULL,
    operator_id text NOT NULL,
    service_id text NOT NULL,
    provider text NOT NULL,
    mode text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.service_connections (
    id text NOT NULL,
    operator_id text NOT NULL,
    service_id text NOT NULL,
    provider text NOT NULL,
    scopes jsonb NOT NULL,
    credential_ref text NOT NULL,
    credential_encrypted text NOT NULL,
    connected_by text,
    member_id text,
    status text DEFAULT 'active'::text NOT NULL,
    proxy_enabled boolean DEFAULT true NOT NULL,
    verification_status text DEFAULT 'unknown'::text,
    verified_at timestamp with time zone,
    connected_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    created_via_grant_id text,
    allowed_hosts jsonb,
    credential_version integer DEFAULT 1 NOT NULL,
    oauth_managed boolean DEFAULT false NOT NULL,
    CONSTRAINT scon_credential_version_check CHECK ((credential_version > 0)),
    CONSTRAINT service_connections_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'revoked'::text]))),
    CONSTRAINT service_connections_verification_status_check CHECK ((verification_status = ANY (ARRAY['healthy'::text, 'unhealthy'::text, 'unknown'::text])))
);
--> statement-breakpoint
CREATE TABLE public.service_identity_requirements (
    id text NOT NULL,
    service_id text NOT NULL,
    layer text NOT NULL,
    requires_claim text NOT NULL,
    minimum_assurance text NOT NULL,
    accepted_providers jsonb NOT NULL,
    required_scopes jsonb,
    requires_pii boolean DEFAULT false NOT NULL,
    lawful_basis text,
    operator_id text NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.services (
    id text NOT NULL,
    provider text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    oauth_auth_url text NOT NULL,
    oauth_token_url text NOT NULL,
    scopes_available jsonb NOT NULL,
    available boolean DEFAULT true NOT NULL,
    operator_id text,
    CONSTRAINT services_owner_shape_check CHECK ((((operator_id IS NULL) AND ("left"(provider, 7) <> 'custom_'::text)) OR ((operator_id IS NOT NULL) AND ("left"(provider, 7) = 'custom_'::text) AND (available = false))))
);
--> statement-breakpoint
CREATE TABLE public.spiffe_trust_domains (
    id text NOT NULL,
    operator_id text NOT NULL,
    trust_domain text NOT NULL,
    display_name text,
    jwks_uri text NOT NULL,
    audience text,
    jwks_cache_ttl_seconds integer DEFAULT 300 NOT NULL,
    jwks_cached_jwks_json jsonb,
    jwks_cached_at timestamp with time zone,
    spiffe_id_mapping_policy_json jsonb NOT NULL,
    rate_limit_per_second integer,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.team_members (
    id text NOT NULL,
    operator_id text NOT NULL,
    email text NOT NULL,
    name text NOT NULL,
    role text DEFAULT 'standard'::text NOT NULL,
    api_key_hash text,
    key_prefix text,
    allowed_connections jsonb,
    status text DEFAULT 'invited'::text NOT NULL,
    last_used_at timestamp with time zone,
    invited_at timestamp with time zone DEFAULT now() NOT NULL,
    joined_at timestamp with time zone,
    revoked_at timestamp with time zone,
    invite_token_hash text,
    invite_expires_at timestamp with time zone,
    CONSTRAINT team_members_status_check CHECK ((status = ANY (ARRAY['invited'::text, 'active'::text, 'revoked'::text])))
);
--> statement-breakpoint
CREATE TABLE public.twin_runs (
    id text NOT NULL,
    mission_id text NOT NULL,
    real_passport_jti text NOT NULL,
    twin_passport_jti text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    evaluated_at timestamp with time zone,
    divergence_claim_id text,
    status text DEFAULT 'running'::text NOT NULL,
    claim_pairs jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT twin_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'evaluated'::text, 'failed'::text])))
);
--> statement-breakpoint
CREATE TABLE public.usage_daily (
    operator_id text NOT NULL,
    day date NOT NULL,
    actions integer DEFAULT 0 NOT NULL,
    agents_registered integer DEFAULT 0 NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    actions_total integer,
    actions_detail_complete boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE public.usage_daily_by_action (
    operator_id text NOT NULL,
    day date NOT NULL,
    action text NOT NULL,
    count integer NOT NULL,
    computed_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT usage_daily_by_action_count_nonnegative CHECK ((count >= 0))
);
--> statement-breakpoint
CREATE TABLE public.usage_monthly_allowances (
    operator_id text NOT NULL,
    month date NOT NULL,
    tier text NOT NULL,
    actions_limit integer,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT usage_monthly_allowances_limit_nonnegative CHECK (((actions_limit IS NULL) OR (actions_limit >= 0))),
    CONSTRAINT usage_monthly_allowances_tier_check CHECK ((tier = ANY (ARRAY['free'::text, 'developer'::text, 'pro'::text, 'business'::text, 'enterprise'::text])))
);
--> statement-breakpoint
CREATE TABLE public.wimse_issuers (
    id text NOT NULL,
    operator_id text NOT NULL,
    issuer_uri text NOT NULL,
    display_name text,
    jwks_uri text NOT NULL,
    audience text,
    jwks_cache_ttl_seconds integer DEFAULT 300 NOT NULL,
    jwks_cached_jwks_json jsonb,
    jwks_cached_at timestamp with time zone,
    workload_id_mapping_policy_json jsonb NOT NULL,
    rate_limit_per_second integer,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE ONLY public.admin_actions
    ADD CONSTRAINT admin_actions_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.agent_service_grants
    ADD CONSTRAINT agent_service_grants_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.audit_archive_segments
    ADD CONSTRAINT audit_archive_segments_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (entry_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_request_authoriser_unique UNIQUE (request_id, authoriser_principal_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_requests
    ADD CONSTRAINT authority_approval_requests_exact_unique UNIQUE (binding_id, binding_version, phase, group_key, request_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_requests
    ADD CONSTRAINT authority_approval_requests_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_requests
    ADD CONSTRAINT authority_approval_requests_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_binding_proofs
    ADD CONSTRAINT authority_binding_proofs_pk PRIMARY KEY (binding_id, binding_version, proof_id, proof_version, role);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_claim_id_key UNIQUE (claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_id_version_operator_unique UNIQUE (id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_pk PRIMARY KEY (id, version);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_idempotency_keys
    ADD CONSTRAINT authority_idempotency_keys_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_idempotency_keys
    ADD CONSTRAINT authority_idempotency_keys_operator_route_key_unique UNIQUE (operator_id, route_key, idempotency_key_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_idempotency_keys
    ADD CONSTRAINT authority_idempotency_keys_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_authority_use_id_key UNIQUE (authority_use_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_presentation_jti_hash_key UNIQUE (presentation_jti_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_receiver_nonce_unique UNIQUE (receiver_id, nonce_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_signed_request_unique UNIQUE (signed_request_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_principals
    ADD CONSTRAINT authority_principals_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_principals
    ADD CONSTRAINT authority_principals_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_profile_versions
    ADD CONSTRAINT authority_profile_versions_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proof_dependencies
    ADD CONSTRAINT authority_proof_dependencies_pk PRIMARY KEY (derived_proof_id, derived_proof_version, source_proof_id, source_proof_version, relation);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_claim_id_key UNIQUE (claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_id_version_operator_unique UNIQUE (id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_pk PRIMARY KEY (id, version);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receiver_keys
    ADD CONSTRAINT authority_receiver_keys_id_receiver_unique UNIQUE (id, receiver_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receiver_keys
    ADD CONSTRAINT authority_receiver_keys_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receiver_keys
    ADD CONSTRAINT authority_receiver_keys_receiver_key_use_unique UNIQUE (receiver_id, key_id, use);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receiver_keys
    ADD CONSTRAINT authority_receiver_keys_receiver_thumbprint_use_unique UNIQUE (receiver_id, thumbprint, use);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receivers
    ADD CONSTRAINT authority_receivers_id_operator_unique UNIQUE (id, managed_by_operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receivers
    ADD CONSTRAINT authority_receivers_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_operator_receiver_hash_unique UNIQUE (operator_id, receiver_id, request_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_receiver_request_unique UNIQUE (receiver_id, receiver_request_id);
--> statement-breakpoint
ALTER TABLE ONLY public.cmek_migrations
    ADD CONSTRAINT cmek_migrations_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.connect_links
    ADD CONSTRAINT connect_links_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.control_decisions
    ADD CONSTRAINT control_decisions_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.control_event_outbox
    ADD CONSTRAINT control_event_outbox_pkey PRIMARY KEY (operator_id, seq);
--> statement-breakpoint
ALTER TABLE ONLY public.control_policies
    ADD CONSTRAINT control_policies_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.control_policy_revisions
    ADD CONSTRAINT control_policy_revisions_pkey PRIMARY KEY (policy_id, revision);
--> statement-breakpoint
ALTER TABLE ONLY public.control_reviews
    ADD CONSTRAINT control_reviews_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.control_sockets
    ADD CONSTRAINT control_sockets_pkey PRIMARY KEY (operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.control_sockets
    ADD CONSTRAINT control_sockets_socket_id_key UNIQUE (socket_id);
--> statement-breakpoint
ALTER TABLE ONLY public.dropoffs
    ADD CONSTRAINT dropoffs_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.erased_operators
    ADD CONSTRAINT erased_operators_pkey PRIMARY KEY (operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.evidence_pack_artifacts
    ADD CONSTRAINT evidence_pack_artifacts_pkey PRIMARY KEY (pack_id);
--> statement-breakpoint
ALTER TABLE ONLY public.external_anchors
    ADD CONSTRAINT external_anchors_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_memberships
    ADD CONSTRAINT fleet_enrollment_key_unique UNIQUE (policy_id, enrollment_key_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_memberships
    ADD CONSTRAINT fleet_member_agent_unique UNIQUE (agent_id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_memberships
    ADD CONSTRAINT fleet_memberships_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_mission_starts
    ADD CONSTRAINT fleet_mission_starts_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_missions
    ADD CONSTRAINT fleet_missions_pkey PRIMARY KEY (mission_id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operation_key_unique UNIQUE (mission_id, operation_key_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_policies
    ADD CONSTRAINT fleet_policies_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_policy_revisions
    ADD CONSTRAINT fleet_policy_revisions_pkey PRIMARY KEY (policy_id, revision);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_policies
    ADD CONSTRAINT fleet_policy_root_unique UNIQUE (root_agent_id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_mission_starts
    ADD CONSTRAINT fleet_start_key_unique UNIQUE (policy_id, agent_id, key_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.governance_approvals
    ADD CONSTRAINT governance_approvals_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.identity_claims
    ADD CONSTRAINT identity_claims_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.identity_providers
    ADD CONSTRAINT identity_providers_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.identity_providers
    ADD CONSTRAINT identity_providers_provider_key_unique UNIQUE (provider_key);
--> statement-breakpoint
ALTER TABLE ONLY public.identity_verification_sessions
    ADD CONSTRAINT identity_verification_sessions_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.inbound_webhook_receipts
    ADD CONSTRAINT inbound_webhook_receipts_webhook_id_provider_message_id_pk PRIMARY KEY (webhook_id, provider_message_id);
--> statement-breakpoint
ALTER TABLE ONLY public.inbound_webhooks
    ADD CONSTRAINT inbound_webhooks_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.magic_link_tokens
    ADD CONSTRAINT magic_link_tokens_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.magic_link_tokens
    ADD CONSTRAINT magic_link_tokens_token_hash_key UNIQUE (token_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.mission_outputs
    ADD CONSTRAINT mission_outputs_pkey PRIMARY KEY (mission_id);
--> statement-breakpoint
ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_mission_id_operator_id_key UNIQUE (mission_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_pkey PRIMARY KEY (mission_id);
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channel_verifications
    ADD CONSTRAINT notification_channel_verifications_channel_id_unique UNIQUE (channel_id);
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channel_verifications
    ADD CONSTRAINT notification_channel_verifications_destination_id_unique UNIQUE (destination_id);
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channel_verifications
    ADD CONSTRAINT notification_channel_verifications_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channels
    ADD CONSTRAINT notification_channels_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.notification_destinations
    ADD CONSTRAINT notification_destinations_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_pkey PRIMARY KEY (code_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_pkey PRIMARY KEY (device_code_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_user_code_unique UNIQUE (user_code);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (token_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.oidc_idp_configs
    ADD CONSTRAINT oidc_idp_configs_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decision_sources
    ADD CONSTRAINT operator_decision_sources_decision_id_source_type_source_id_pk PRIMARY KEY (decision_id, source_type, source_id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decision_sources
    ADD CONSTRAINT operator_decision_sources_operator_id_source_type_source_id_key UNIQUE (operator_id, source_type, source_id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_claim_id_unique UNIQUE (claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_id_operator_id_key UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_operator_id_idempotency_key_key UNIQUE (operator_id, idempotency_key);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_detector_config
    ADD CONSTRAINT operator_detector_config_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_changes
    ADD CONSTRAINT operator_email_changes_cancel_token_hash_key UNIQUE (cancel_token_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_changes
    ADD CONSTRAINT operator_email_changes_confirm_token_hash_key UNIQUE (confirm_token_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_changes
    ADD CONSTRAINT operator_email_changes_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_delivery_jobs
    ADD CONSTRAINT operator_email_delivery_jobs_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_erasure_jobs
    ADD CONSTRAINT operator_erasure_jobs_pkey PRIMARY KEY (operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_oauth_apps
    ADD CONSTRAINT operator_oauth_apps_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_pii_config
    ADD CONSTRAINT operator_pii_config_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_signing_keys
    ADD CONSTRAINT operator_signing_keys_pkey PRIMARY KEY (kid);
--> statement-breakpoint
ALTER TABLE ONLY public.operators
    ADD CONSTRAINT operators_api_key_hash_unique UNIQUE (api_key_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.operators
    ADD CONSTRAINT operators_email_unique UNIQUE (email);
--> statement-breakpoint
ALTER TABLE ONLY public.operators
    ADD CONSTRAINT operators_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.operators
    ADD CONSTRAINT operators_stripe_customer_id_unique UNIQUE (stripe_customer_id);
--> statement-breakpoint
ALTER TABLE ONLY public.partner_grants
    ADD CONSTRAINT partner_grants_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.partner_grants
    ADD CONSTRAINT partner_grants_token_hash_unique UNIQUE (token_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_authority_bindings
    ADD CONSTRAINT passport_authority_bindings_pk PRIMARY KEY (passport_jti, binding_id, binding_version);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkouts
    ADD CONSTRAINT passport_checkouts_passport_jti_unique UNIQUE (passport_jti);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkouts
    ADD CONSTRAINT passport_checkouts_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkpoints
    ADD CONSTRAINT passport_checkpoints_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_claims
    ADD CONSTRAINT passport_claims_pkey PRIMARY KEY (claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_reviews
    ADD CONSTRAINT passport_reviews_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.passports
    ADD CONSTRAINT passports_pkey PRIMARY KEY (jti);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_accounting_receipts
    ADD CONSTRAINT proxy_accounting_receipts_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_attempts
    ADD CONSTRAINT proxy_operation_attempts_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_evidence
    ADD CONSTRAINT proxy_operation_evidence_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_replacement_acknowledgements
    ADD CONSTRAINT proxy_operation_replacement_acknowledgements_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_authority_use_id_key UNIQUE (authority_use_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_claim_id_key UNIQUE (claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_id_operator_unique UNIQUE (id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_receipt_jti_hash_key UNIQUE (receipt_jti_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_configurations
    ADD CONSTRAINT service_configurations_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_connections
    ADD CONSTRAINT service_connections_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_identity_requirements
    ADD CONSTRAINT service_identity_requirements_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.spiffe_trust_domains
    ADD CONSTRAINT spiffe_trust_domains_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_api_key_hash_unique UNIQUE (api_key_hash);
--> statement-breakpoint
ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.twin_runs
    ADD CONSTRAINT twin_runs_pkey PRIMARY KEY (id);
--> statement-breakpoint
ALTER TABLE ONLY public.usage_daily_by_action
    ADD CONSTRAINT usage_daily_by_action_pkey PRIMARY KEY (operator_id, day, action);
--> statement-breakpoint
ALTER TABLE ONLY public.usage_daily
    ADD CONSTRAINT usage_daily_pkey PRIMARY KEY (operator_id, day);
--> statement-breakpoint
ALTER TABLE ONLY public.usage_monthly_allowances
    ADD CONSTRAINT usage_monthly_allowances_operator_id_month_pk PRIMARY KEY (operator_id, month);
--> statement-breakpoint
ALTER TABLE ONLY public.wimse_issuers
    ADD CONSTRAINT wimse_issuers_pkey PRIMARY KEY (id);
--> statement-breakpoint
CREATE UNIQUE INDEX agents_id_operator_idx ON public.agents USING btree (id, operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX agents_operator_name_idx ON public.agents USING btree (operator_id, name);
--> statement-breakpoint
CREATE INDEX audit_agent_idx ON public.audit_log USING btree (agent_id);
--> statement-breakpoint
CREATE UNIQUE INDEX audit_archive_operator_object_key_idx ON public.audit_archive_segments USING btree (operator_id, object_key);
--> statement-breakpoint
CREATE INDEX audit_archive_operator_range_idx ON public.audit_archive_segments USING btree (operator_id, from_timestamp, to_timestamp);
--> statement-breakpoint
CREATE INDEX audit_archive_retention_due_idx ON public.audit_archive_segments USING btree (to_timestamp, retention_next_attempt_at);
--> statement-breakpoint
CREATE INDEX audit_layer_action_idx ON public.audit_log USING btree (layer, action);
--> statement-breakpoint
CREATE INDEX audit_operator_idx ON public.audit_log USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX audit_operator_timestamp_idx ON public.audit_log USING btree (operator_id, "timestamp", entry_id);
--> statement-breakpoint
CREATE INDEX audit_passport_idx ON public.audit_log USING btree (passport_jti);
--> statement-breakpoint
CREATE INDEX audit_timestamp_idx ON public.audit_log USING btree ("timestamp");
--> statement-breakpoint
CREATE INDEX audit_trace_idx ON public.audit_log USING btree (trace_id);
--> statement-breakpoint
CREATE INDEX authority_approval_requests_operator_status_expiry_idx ON public.authority_approval_requests USING btree (operator_id, status, expires_at);
--> statement-breakpoint
CREATE INDEX authority_binding_proofs_proof_idx ON public.authority_binding_proofs USING btree (operator_id, proof_id, proof_version);
--> statement-breakpoint
CREATE INDEX authority_bindings_agent_status_idx ON public.authority_bindings USING btree (operator_id, agent_id, status);
--> statement-breakpoint
CREATE INDEX authority_bindings_claim_idx ON public.authority_bindings USING btree (claim_id);
--> statement-breakpoint
CREATE INDEX authority_bindings_lineage_idx ON public.authority_bindings USING btree (operator_id, lineage_root_id, lineage_root_version, delegation_depth);
--> statement-breakpoint
CREATE INDEX authority_bindings_missions_idx ON public.authority_bindings USING gin (mission_ids);
--> statement-breakpoint
CREATE INDEX authority_bindings_parent_idx ON public.authority_bindings USING btree (operator_id, parent_binding_id, parent_binding_version);
--> statement-breakpoint
CREATE INDEX authority_bindings_principal_status_idx ON public.authority_bindings USING btree (operator_id, principal_id, status);
--> statement-breakpoint
CREATE INDEX authority_bindings_receiver_status_idx ON public.authority_bindings USING btree (receiver_id, status);
--> statement-breakpoint
CREATE INDEX authority_idempotency_keys_expires_idx ON public.authority_idempotency_keys USING btree (expires_at);
--> statement-breakpoint
CREATE INDEX authority_idempotency_keys_operator_state_created_idx ON public.authority_idempotency_keys USING btree (operator_id, state, created_at);
--> statement-breakpoint
CREATE INDEX authority_idempotency_keys_operator_workflow_lease_idx ON public.authority_idempotency_keys USING btree (operator_id, workflow_phase, lease_expires_at);
--> statement-breakpoint
CREATE INDEX authority_principals_operator_kind_idx ON public.authority_principals USING btree (operator_id, kind);
--> statement-breakpoint
CREATE INDEX authority_principals_operator_status_idx ON public.authority_principals USING btree (operator_id, status);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_principals_superseded_unique_idx ON public.authority_principals USING btree (operator_id, superseded_by_id) WHERE (superseded_by_id IS NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_profile_versions_catalog_content_idx ON public.authority_profile_versions USING btree (profile_kind, content_hash) WHERE (owner_operator_id IS NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_profile_versions_catalog_logical_idx ON public.authority_profile_versions USING btree (profile_kind, profile_key, version) WHERE (owner_operator_id IS NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_profile_versions_id_owner_idx ON public.authority_profile_versions USING btree (id, owner_operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_profile_versions_operator_content_idx ON public.authority_profile_versions USING btree (owner_operator_id, profile_kind, content_hash) WHERE (owner_operator_id IS NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_profile_versions_operator_logical_idx ON public.authority_profile_versions USING btree (owner_operator_id, profile_kind, profile_key, version) WHERE (owner_operator_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX authority_profile_versions_owner_status_idx ON public.authority_profile_versions USING btree (owner_operator_id, status);
--> statement-breakpoint
CREATE INDEX authority_profile_versions_receiver_version_idx ON public.authority_profile_versions USING btree (receiver_id, version);
--> statement-breakpoint
CREATE INDEX authority_proof_dependencies_source_idx ON public.authority_proof_dependencies USING btree (operator_id, source_proof_id, source_proof_version);
--> statement-breakpoint
CREATE INDEX authority_proofs_active_expiry_idx ON public.authority_proofs USING btree (operator_id, expires_at) WHERE (status = 'active'::text);
--> statement-breakpoint
CREATE INDEX authority_proofs_claim_idx ON public.authority_proofs USING btree (claim_id);
--> statement-breakpoint
CREATE INDEX authority_proofs_legacy_identity_idx ON public.authority_proofs USING btree (operator_id, legacy_identity_claim_id);
--> statement-breakpoint
CREATE INDEX authority_proofs_represented_kind_idx ON public.authority_proofs USING btree (operator_id, represented_principal_id, proof_kind);
--> statement-breakpoint
CREATE INDEX authority_proofs_subject_kind_status_idx ON public.authority_proofs USING btree (operator_id, subject_principal_id, proof_kind, status);
--> statement-breakpoint
CREATE INDEX authority_receiver_keys_receiver_use_status_idx ON public.authority_receiver_keys USING btree (receiver_id, use, status);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_receivers_internal_identifier_idx ON public.authority_receivers USING btree (managed_by_operator_id, canonical_identifier) WHERE (mode = 'internal'::text);
--> statement-breakpoint
CREATE INDEX authority_receivers_manager_status_idx ON public.authority_receivers USING btree (managed_by_operator_id, status);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_receivers_native_identifier_idx ON public.authority_receivers USING btree (canonical_identifier) WHERE (mode = 'native'::text);
--> statement-breakpoint
CREATE UNIQUE INDEX authority_receivers_proxy_identifier_idx ON public.authority_receivers USING btree (managed_by_operator_id, canonical_identifier) WHERE (mode = 'proxy_bridge'::text);
--> statement-breakpoint
CREATE INDEX authority_uses_binding_idx ON public.authority_uses USING btree (operator_id, binding_id, binding_version);
--> statement-breakpoint
CREATE INDEX authority_uses_mission_idx ON public.authority_uses USING btree (operator_id, mission_id);
--> statement-breakpoint
CREATE INDEX authority_uses_passport_idx ON public.authority_uses USING btree (operator_id, passport_jti);
--> statement-breakpoint
CREATE INDEX authority_uses_status_idx ON public.authority_uses USING btree (operator_id, status);
--> statement-breakpoint
CREATE INDEX chk_claim_idx ON public.passport_checkpoints USING btree (claim_id);
--> statement-breakpoint
CREATE INDEX chk_operator_idx ON public.passport_checkpoints USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX chk_passport_idx ON public.passport_checkpoints USING btree (passport_jti);
--> statement-breakpoint
CREATE INDEX claim_expires_idx ON public.identity_claims USING btree (expires_at);
--> statement-breakpoint
CREATE INDEX claim_layer_idx ON public.identity_claims USING btree (layer);
--> statement-breakpoint
CREATE INDEX claim_operator_idx ON public.identity_claims USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX claim_provider_idx ON public.identity_claims USING btree (provider_key);
--> statement-breakpoint
CREATE UNIQUE INDEX cmek_migrations_op_direction_table_idx ON public.cmek_migrations USING btree (operator_id, direction, table_name);
--> statement-breakpoint
CREATE INDEX cmek_migrations_status_idx ON public.cmek_migrations USING btree (status);
--> statement-breakpoint
CREATE INDEX connect_links_operator_status_idx ON public.connect_links USING btree (operator_id, status);
--> statement-breakpoint
CREATE UNIQUE INDEX connect_links_token_hash_uidx ON public.connect_links USING btree (token_hash);
--> statement-breakpoint
CREATE INDEX control_decisions_account_created_idx ON public.control_decisions USING btree (account_id, created_at);
--> statement-breakpoint
CREATE INDEX control_decisions_operator_created_idx ON public.control_decisions USING btree (operator_id, created_at);
--> statement-breakpoint
CREATE INDEX control_event_outbox_status_idx ON public.control_event_outbox USING btree (operator_id, status, seq);
--> statement-breakpoint
CREATE INDEX control_policies_operator_idx ON public.control_policies USING btree (operator_id, status);
--> statement-breakpoint
CREATE UNIQUE INDEX control_policies_scope_unique ON public.control_policies USING btree (operator_id, COALESCE(agent_id, ''::text)) WHERE (status = 'active'::text);
--> statement-breakpoint
CREATE INDEX control_policy_revisions_operator_idx ON public.control_policy_revisions USING btree (operator_id, created_at);
--> statement-breakpoint
CREATE INDEX control_reviews_account_idx ON public.control_reviews USING btree (account_id, status);
--> statement-breakpoint
CREATE UNIQUE INDEX control_reviews_approval_unique ON public.control_reviews USING btree (governance_approval_id);
--> statement-breakpoint
CREATE UNIQUE INDEX control_reviews_call_unique ON public.control_reviews USING btree (operator_id, call_digest) WHERE (status = ANY (ARRAY['pending'::text, 'approved'::text, 'consuming'::text]));
--> statement-breakpoint
CREATE INDEX control_reviews_operator_idx ON public.control_reviews USING btree (operator_id, created_at);
--> statement-breakpoint
CREATE INDEX cout_operator_idx ON public.passport_checkouts USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX cout_status_idx ON public.passport_checkouts USING btree (review_status);
--> statement-breakpoint
CREATE INDEX dropoff_expires_idx ON public.dropoffs USING btree (expires_at);
--> statement-breakpoint
CREATE INDEX dropoff_from_agent_idx ON public.dropoffs USING btree (from_agent_id);
--> statement-breakpoint
CREATE INDEX dropoff_mission_idx ON public.dropoffs USING btree (operator_id, mission_id);
--> statement-breakpoint
CREATE INDEX dropoff_operator_idx ON public.dropoffs USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX dropoff_status_idx ON public.dropoffs USING btree (status);
--> statement-breakpoint
CREATE INDEX dropoff_to_agent_idx ON public.dropoffs USING btree (to_agent_id);
--> statement-breakpoint
CREATE INDEX dropoffs_mission_idx ON public.dropoffs USING btree (mission_id) WHERE (mission_id IS NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX evidence_pack_artifacts_claim_idx ON public.evidence_pack_artifacts USING btree (claim_id);
--> statement-breakpoint
CREATE UNIQUE INDEX evidence_pack_artifacts_object_key_idx ON public.evidence_pack_artifacts USING btree (object_key);
--> statement-breakpoint
CREATE INDEX evidence_pack_artifacts_operator_idx ON public.evidence_pack_artifacts USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX ext_anchors_op_time_idx ON public.external_anchors USING btree (operator_id, anchored_at_ms);
--> statement-breakpoint
CREATE INDEX fleet_member_policy_idx ON public.fleet_memberships USING btree (policy_id);
--> statement-breakpoint
CREATE INDEX fleet_operation_budget_idx ON public.fleet_operations USING btree (policy_id, created_at);
--> statement-breakpoint
CREATE INDEX fleet_operation_mission_idx ON public.fleet_operations USING btree (mission_id);
--> statement-breakpoint
CREATE INDEX fleet_operations_proxy_recovery_idx ON public.fleet_operations USING btree (proxy_operation_id) WHERE (state = ANY (ARRAY['dispatched'::text, 'unknown'::text]));
--> statement-breakpoint
CREATE INDEX grant_agent_idx ON public.agent_service_grants USING btree (agent_id);
--> statement-breakpoint
CREATE UNIQUE INDEX grant_agent_scon_idx ON public.agent_service_grants USING btree (agent_id, service_connection_id);
--> statement-breakpoint
CREATE UNIQUE INDEX gvr_decided_chat_request_uidx ON public.governance_approvals USING btree (decided_chat_request_id) WHERE (decided_chat_request_id IS NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX gvr_decided_elicitation_uidx ON public.governance_approvals USING btree (decided_elicitation_id) WHERE (decided_elicitation_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX gvr_operator_idx ON public.governance_approvals USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX gvr_operator_status_idx ON public.governance_approvals USING btree (operator_id, status);
--> statement-breakpoint
CREATE UNIQUE INDEX ia_fleet_review_key_unique ON public.intent_approvals USING btree (operator_id, fleet_review_key);
--> statement-breakpoint
CREATE UNIQUE INDEX ia_id_operator_idx ON public.intent_approvals USING btree (id, operator_id);
--> statement-breakpoint
CREATE INDEX ia_intent_claim_idx ON public.intent_approvals USING btree (intent_claim_id);
--> statement-breakpoint
CREATE INDEX ia_operator_idx ON public.intent_approvals USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX ia_passport_idx ON public.intent_approvals USING btree (passport_jti);
--> statement-breakpoint
CREATE INDEX ia_status_idx ON public.intent_approvals USING btree (status);
--> statement-breakpoint
CREATE INDEX idc_claim_idx ON public.identity_claims USING btree (claim_id);
--> statement-breakpoint
CREATE UNIQUE INDEX identity_claims_id_operator_idx ON public.identity_claims USING btree (id, operator_id);
--> statement-breakpoint
CREATE INDEX idx_admin_actions_admin ON public.admin_actions USING btree (admin_operator_id);
--> statement-breakpoint
CREATE INDEX idx_admin_actions_created ON public.admin_actions USING btree (created_at);
--> statement-breakpoint
CREATE INDEX idx_admin_actions_target ON public.admin_actions USING btree (target_operator_id);
--> statement-breakpoint
CREATE INDEX idx_secevt_agent ON public.security_events USING btree (agent_id);
--> statement-breakpoint
CREATE INDEX idx_secevt_claim ON public.security_events USING btree (claim_id);
--> statement-breakpoint
CREATE INDEX idx_secevt_operator ON public.security_events USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX idx_secevt_passport ON public.security_events USING btree (passport_jti);
--> statement-breakpoint
CREATE INDEX idx_secevt_type ON public.security_events USING btree (signal_type);
--> statement-breakpoint
CREATE INDEX inbound_webhook_receipts_seen_at_idx ON public.inbound_webhook_receipts USING btree (seen_at);
--> statement-breakpoint
CREATE UNIQUE INDEX inbound_webhooks_lookup_idx ON public.inbound_webhooks USING btree (provider, slug);
--> statement-breakpoint
CREATE INDEX inbound_webhooks_operator_idx ON public.inbound_webhooks USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX ivsess_operator_idx ON public.identity_verification_sessions USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX ivsess_session_ref_idx ON public.identity_verification_sessions USING btree (session_ref);
--> statement-breakpoint
CREATE INDEX ivsess_status_idx ON public.identity_verification_sessions USING btree (status);
--> statement-breakpoint
CREATE INDEX llm_usage_mission_idx ON public.llm_usage USING btree (mission_id) WHERE (mission_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX llm_usage_operator_surface_time_idx ON public.llm_usage USING btree (operator_id, surface, created_at);
--> statement-breakpoint
CREATE INDEX llm_usage_operator_time_idx ON public.llm_usage USING btree (operator_id, created_at);
--> statement-breakpoint
CREATE INDEX llm_usage_passport_time_idx ON public.llm_usage USING btree (passport_jti, created_at);
--> statement-breakpoint
CREATE INDEX llm_usage_wallet_fee_pending_idx ON public.llm_usage USING btree (operator_id, wallet_fee_kind, created_at, id) WHERE (wallet_fee_microcents_remaining > 0);
--> statement-breakpoint
CREATE UNIQUE INDEX member_invite_token_hash_idx ON public.team_members USING btree (invite_token_hash);
--> statement-breakpoint
CREATE UNIQUE INDEX member_operator_email_idx ON public.team_members USING btree (operator_id, email);
--> statement-breakpoint
CREATE INDEX member_operator_idx ON public.team_members USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX mission_outputs_operator_idx ON public.mission_outputs USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX missions_active_idx ON public.missions USING btree (operator_id) WHERE ((completed_at IS NULL) AND (revoked_at IS NULL));
--> statement-breakpoint
CREATE INDEX missions_claim_idx ON public.missions USING btree (claim_id);
--> statement-breakpoint
CREATE INDEX missions_expires_active_idx ON public.missions USING btree (expires_at) WHERE ((completed_at IS NULL) AND (revoked_at IS NULL));
--> statement-breakpoint
CREATE INDEX missions_operator_started_idx ON public.missions USING btree (operator_id, started_at DESC);
--> statement-breakpoint
CREATE INDEX mlt_email_idx ON public.magic_link_tokens USING btree (email);
--> statement-breakpoint
CREATE INDEX mlt_expires_idx ON public.magic_link_tokens USING btree (expires_at);
--> statement-breakpoint
CREATE INDEX mlt_member_idx ON public.magic_link_tokens USING btree (member_id);
--> statement-breakpoint
CREATE INDEX nch_destination_idx ON public.notification_channels USING btree (destination_id);
--> statement-breakpoint
CREATE INDEX nch_operator_idx ON public.notification_channels USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX ndst_operator_idx ON public.notification_destinations USING btree (operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX ndst_operator_type_dest_idx ON public.notification_destinations USING btree (operator_id, channel_type, destination);
--> statement-breakpoint
CREATE INDEX oac_client_expires_idx ON public.oauth_authorization_codes USING btree (client_id, expires_at);
--> statement-breakpoint
CREATE INDEX oapp_operator_idx ON public.operator_oauth_apps USING btree (operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX oapp_operator_provider_idx ON public.operator_oauth_apps USING btree (operator_id, provider);
--> statement-breakpoint
CREATE INDEX oclient_operator_idx ON public.oauth_clients USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX odc_expires_idx ON public.oauth_device_codes USING btree (expires_at);
--> statement-breakpoint
CREATE UNIQUE INDEX odc_operator_detector_idx ON public.operator_detector_config USING btree (operator_id, detector_key);
--> statement-breakpoint
CREATE INDEX odc_operator_idx ON public.operator_detector_config USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX oidc_idp_active_idx ON public.oidc_idp_configs USING btree (active);
--> statement-breakpoint
CREATE INDEX oidc_idp_issuer_idx ON public.oidc_idp_configs USING btree (issuer_uri);
--> statement-breakpoint
CREATE UNIQUE INDEX oidc_idp_op_unique ON public.oidc_idp_configs USING btree (operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX oidc_idp_sso_slug_unique ON public.oidc_idp_configs USING btree (sso_slug);
--> statement-breakpoint
CREATE UNIQUE INDEX opc_operator_idx ON public.operator_pii_config USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX operator_decisions_mission_idx ON public.operator_decisions USING btree (operator_id, mission_id, decided_at);
--> statement-breakpoint
CREATE UNIQUE INDEX operator_email_changes_one_pending_idx ON public.operator_email_changes USING btree (operator_id) WHERE ((confirmed_at IS NULL) AND (cancelled_at IS NULL));
--> statement-breakpoint
CREATE INDEX operator_email_changes_operator_idx ON public.operator_email_changes USING btree (operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX operator_email_delivery_jobs_change_kind_idx ON public.operator_email_delivery_jobs USING btree (email_change_id, kind);
--> statement-breakpoint
CREATE INDEX operator_email_delivery_jobs_due_idx ON public.operator_email_delivery_jobs USING btree (next_attempt_at);
--> statement-breakpoint
CREATE INDEX operator_erasure_jobs_due_idx ON public.operator_erasure_jobs USING btree (next_attempt_at);
--> statement-breakpoint
CREATE UNIQUE INDEX operator_reviews_one_revision_per_prior_idx ON public.passport_claims USING btree (operator_id, ((body_json ->> 'prior_review_ref'::text))) WHERE ((type = 'operator_review'::text) AND ((body_json ->> 'prior_review_ref'::text) IS NOT NULL));
--> statement-breakpoint
CREATE UNIQUE INDEX operator_reviews_one_root_per_mission_idx ON public.passport_claims USING btree (operator_id, ((body_json ->> 'mission_ref'::text))) WHERE ((type = 'operator_review'::text) AND ((body_json ->> 'prior_review_ref'::text) IS NULL));
--> statement-breakpoint
CREATE UNIQUE INDEX operators_controls_subscription_unique ON public.operators USING btree (controls_subscription_id) WHERE (controls_subscription_id IS NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX operators_parent_external_customer_idx ON public.operators USING btree (parent_operator_id, external_customer_id) WHERE (external_customer_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX operators_parent_idx ON public.operators USING btree (parent_operator_id) WHERE (parent_operator_id IS NOT NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX operators_platform_subscription_unique ON public.operators USING btree (platform_subscription_id) WHERE (platform_subscription_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX ort_expires_idx ON public.oauth_refresh_tokens USING btree (expires_at);
--> statement-breakpoint
CREATE INDEX ort_family_idx ON public.oauth_refresh_tokens USING btree (token_family_id);
--> statement-breakpoint
CREATE INDEX ort_operator_expires_idx ON public.oauth_refresh_tokens USING btree (operator_id, expires_at);
--> statement-breakpoint
CREATE INDEX ort_replaced_by_idx ON public.oauth_refresh_tokens USING btree (replaced_by_hash) WHERE (replaced_by_hash IS NOT NULL);
--> statement-breakpoint
CREATE INDEX ort_retry_expiry_idx ON public.oauth_refresh_tokens USING btree (replacement_retry_expires_at) WHERE ((replacement_token_encrypted IS NOT NULL) AND (replacement_retry_expires_at IS NOT NULL));
--> statement-breakpoint
CREATE INDEX osk_op_active_idx ON public.operator_signing_keys USING btree (operator_id) WHERE ((retired_at IS NULL) AND (revoked_at IS NULL));
--> statement-breakpoint
CREATE INDEX osk_operator_idx ON public.operator_signing_keys USING btree (operator_id);
--> statement-breakpoint
CREATE UNIQUE INDEX partner_grants_ext_customer_idx ON public.partner_grants USING btree (partner_operator_id, external_customer_id) WHERE ((external_customer_id IS NOT NULL) AND (status = ANY (ARRAY['pending_consent'::text, 'active'::text])));
--> statement-breakpoint
CREATE UNIQUE INDEX partner_grants_live_pair_idx ON public.partner_grants USING btree (partner_operator_id, user_operator_id) WHERE (status = ANY (ARRAY['pending_consent'::text, 'active'::text]));
--> statement-breakpoint
CREATE INDEX partner_grants_partner_idx ON public.partner_grants USING btree (partner_operator_id);
--> statement-breakpoint
CREATE INDEX partner_grants_user_idx ON public.partner_grants USING btree (user_operator_id);
--> statement-breakpoint
CREATE INDEX passport_agent_idx ON public.passports USING btree (agent_id);
--> statement-breakpoint
CREATE INDEX passport_authority_bindings_binding_idx ON public.passport_authority_bindings USING btree (operator_id, binding_id, binding_version);
--> statement-breakpoint
CREATE INDEX passport_authority_bindings_operator_idx ON public.passport_authority_bindings USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX passport_checkouts_mission_idx ON public.passport_checkouts USING btree (operator_id, mission_id);
--> statement-breakpoint
CREATE INDEX passport_operator_idx ON public.passports USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX passport_session_idx ON public.passports USING btree (session_id);
--> statement-breakpoint
CREATE UNIQUE INDEX passports_jti_operator_idx ON public.passports USING btree (jti, operator_id);
--> statement-breakpoint
CREATE INDEX passports_mission_ids_gin_idx ON public.passports USING gin (mission_ids);
--> statement-breakpoint
CREATE INDEX pc_attached_at_idx ON public.passport_claims USING btree (attached_at);
--> statement-breakpoint
CREATE INDEX pc_claim_hash_idx ON public.passport_claims USING btree (claim_hash);
--> statement-breakpoint
CREATE UNIQUE INDEX pc_claim_id_operator_idx ON public.passport_claims USING btree (claim_id, operator_id);
--> statement-breakpoint
CREATE INDEX pc_issued_at_idx ON public.passport_claims USING btree (issued_at_ms);
--> statement-breakpoint
CREATE INDEX pc_observation_mission_source_idx ON public.passport_claims USING btree (operator_id, ((body_json ->> 'mission_ref'::text)), ((body_json ->> 'source_service'::text)), issued_at_ms DESC NULLS LAST) WHERE (type = 'entity_observation'::text);
--> statement-breakpoint
CREATE INDEX pc_operator_type_idx ON public.passport_claims USING btree (operator_id, type);
--> statement-breakpoint
CREATE INDEX pc_passport_idx ON public.passport_claims USING btree (passport_id);
--> statement-breakpoint
CREATE INDEX pc_passport_type_active_idx ON public.passport_claims USING btree (passport_id, type) WHERE (revoked_at IS NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX pc_source_operation_role_idx ON public.passport_claims USING btree (operator_id, source_operation_id, source_role) WHERE ((source_operation_id IS NOT NULL) AND (source_role IS NOT NULL));
--> statement-breakpoint
CREATE INDEX pc_type_idx ON public.passport_claims USING btree (type);
--> statement-breakpoint
CREATE INDEX prev_agent_idx ON public.passport_reviews USING btree (agent_id);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_accounting_receipts_logical_action_idx ON public.proxy_accounting_receipts USING btree (operator_id, accounting_period, operation_key_hash);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_accounting_receipts_obligation_idx ON public.proxy_accounting_receipts USING btree (operator_id, wallet_obligation_id);
--> statement-breakpoint
CREATE INDEX proxy_accounting_receipts_operator_period_idx ON public.proxy_accounting_receipts USING btree (operator_id, accounting_period);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_accounting_receipts_period_sequence_idx ON public.proxy_accounting_receipts USING btree (operator_id, accounting_period, period_sequence);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operation_attempts_operation_number_idx ON public.proxy_operation_attempts USING btree (operation_id, attempt_number);
--> statement-breakpoint
CREATE INDEX proxy_operation_attempts_operator_started_idx ON public.proxy_operation_attempts USING btree (operator_id, started_at);
--> statement-breakpoint
CREATE INDEX proxy_operation_evidence_operation_observed_idx ON public.proxy_operation_evidence USING btree (operation_id, observed_at);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operation_replacement_handle_idx ON public.proxy_operation_replacement_acknowledgements USING btree (operator_id, replacement_operation_key_hash);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operation_replacement_original_idx ON public.proxy_operation_replacement_acknowledgements USING btree (operator_id, original_operation_id);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operations_accounting_obligation_idx ON public.proxy_operations USING btree (operator_id, accounting_obligation_id);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operations_authority_use_idx ON public.proxy_operations USING btree (authority_use_id) WHERE (authority_use_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX proxy_operations_effect_correlation_idx ON public.proxy_operations USING btree (operator_id, effect_correlation_hash, delivery_state);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operations_id_operator_idx ON public.proxy_operations USING btree (id, operator_id);
--> statement-breakpoint
CREATE INDEX proxy_operations_operator_capacity_idx ON public.proxy_operations USING btree (operator_id, replay_state);
--> statement-breakpoint
CREATE INDEX proxy_operations_operator_delivery_idx ON public.proxy_operations USING btree (operator_id, delivery_state, created_at);
--> statement-breakpoint
CREATE UNIQUE INDEX proxy_operations_operator_key_idx ON public.proxy_operations USING btree (operator_id, operation_key_hash);
--> statement-breakpoint
CREATE INDEX proxy_operations_post_response_work_idx ON public.proxy_operations USING btree (post_response_work_state, post_response_next_attempt_at, post_response_lease_expires_at);
--> statement-breakpoint
CREATE INDEX proxy_operations_replay_expiry_idx ON public.proxy_operations USING btree (response_readable_until);
--> statement-breakpoint
CREATE INDEX receiver_transaction_receipts_receiver_received_idx ON public.receiver_transaction_receipts USING btree (receiver_id, received_at);
--> statement-breakpoint
CREATE UNIQUE INDEX scon_active_member_principal_idx ON public.service_connections USING btree (operator_id, provider, member_id) WHERE ((status = 'active'::text) AND (member_id IS NOT NULL));
--> statement-breakpoint
CREATE UNIQUE INDEX scon_active_shared_principal_idx ON public.service_connections USING btree (operator_id, provider) WHERE ((status = 'active'::text) AND (member_id IS NULL));
--> statement-breakpoint
CREATE UNIQUE INDEX scon_id_operator_idx ON public.service_connections USING btree (id, operator_id);
--> statement-breakpoint
CREATE INDEX scon_member_idx ON public.service_connections USING btree (member_id);
--> statement-breakpoint
CREATE INDEX scon_operator_idx ON public.service_connections USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX security_events_mission_idx ON public.security_events USING btree (operator_id, mission_id);
--> statement-breakpoint
CREATE UNIQUE INDEX services_catalog_provider_unique ON public.services USING btree (provider) WHERE (operator_id IS NULL);
--> statement-breakpoint
CREATE UNIQUE INDEX services_custom_operator_provider_unique ON public.services USING btree (operator_id, provider) WHERE (operator_id IS NOT NULL);
--> statement-breakpoint
CREATE INDEX spiffe_td_active_idx ON public.spiffe_trust_domains USING btree (active);
--> statement-breakpoint
CREATE UNIQUE INDEX spiffe_td_op_trust_unique ON public.spiffe_trust_domains USING btree (operator_id, trust_domain);
--> statement-breakpoint
CREATE INDEX spiffe_td_operator_idx ON public.spiffe_trust_domains USING btree (operator_id);
--> statement-breakpoint
CREATE INDEX svc_req_layer_idx ON public.service_identity_requirements USING btree (layer);
--> statement-breakpoint
CREATE INDEX svc_req_op_service_idx ON public.service_identity_requirements USING btree (operator_id, service_id);
--> statement-breakpoint
CREATE UNIQUE INDEX svc_req_op_service_layer_claim_unique ON public.service_identity_requirements USING btree (operator_id, service_id, layer, requires_claim);
--> statement-breakpoint
CREATE UNIQUE INDEX svcfg_operator_provider_idx ON public.service_configurations USING btree (operator_id, provider);
--> statement-breakpoint
CREATE INDEX twin_runs_mission_idx ON public.twin_runs USING btree (mission_id);
--> statement-breakpoint
CREATE INDEX twin_runs_real_passport_idx ON public.twin_runs USING btree (real_passport_jti);
--> statement-breakpoint
CREATE INDEX twin_runs_status_idx ON public.twin_runs USING btree (status);
--> statement-breakpoint
CREATE INDEX usage_daily_operator_day_idx ON public.usage_daily USING btree (operator_id, day);
--> statement-breakpoint
CREATE INDEX wimse_iss_active_idx ON public.wimse_issuers USING btree (active);
--> statement-breakpoint
CREATE UNIQUE INDEX wimse_iss_op_issuer_unique ON public.wimse_issuers USING btree (operator_id, issuer_uri);
--> statement-breakpoint
CREATE INDEX wimse_iss_operator_idx ON public.wimse_issuers USING btree (operator_id);
--> statement-breakpoint
CREATE TRIGGER authority_approval_decisions_immutable BEFORE DELETE OR UPDATE ON public.authority_approval_decisions FOR EACH ROW EXECUTE FUNCTION public.authority_reject_all_changes();
--> statement-breakpoint
CREATE TRIGGER authority_binding_proofs_immutable BEFORE DELETE OR UPDATE ON public.authority_binding_proofs FOR EACH ROW EXECUTE FUNCTION public.authority_reject_all_changes();
--> statement-breakpoint
CREATE TRIGGER authority_bindings_domain_profile_scope_guard BEFORE INSERT OR UPDATE OF domain_profile_version_id, operator_id ON public.authority_bindings FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('domain_profile_version_id', 'operator_id', 'domain');
--> statement-breakpoint
CREATE TRIGGER authority_bindings_guard_trigger BEFORE DELETE OR UPDATE ON public.authority_bindings FOR EACH ROW EXECUTE FUNCTION public.authority_bindings_guard();
--> statement-breakpoint
CREATE TRIGGER authority_bindings_receiver_profile_scope_guard BEFORE INSERT OR UPDATE OF receiver_profile_version_id, operator_id ON public.authority_bindings FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('receiver_profile_version_id', 'operator_id', 'receiver');
--> statement-breakpoint
CREATE TRIGGER authority_presentations_receiver_profile_scope_guard BEFORE INSERT OR UPDATE OF receiver_profile_version_id, operator_id ON public.authority_presentations FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('receiver_profile_version_id', 'operator_id', 'receiver');
--> statement-breakpoint
CREATE TRIGGER authority_profile_versions_guard_trigger BEFORE DELETE OR UPDATE ON public.authority_profile_versions FOR EACH ROW EXECUTE FUNCTION public.authority_profile_versions_guard();
--> statement-breakpoint
CREATE TRIGGER authority_proof_dependencies_immutable BEFORE DELETE OR UPDATE ON public.authority_proof_dependencies FOR EACH ROW EXECUTE FUNCTION public.authority_reject_all_changes();
--> statement-breakpoint
CREATE TRIGGER authority_proofs_profile_scope_guard BEFORE INSERT OR UPDATE OF profile_version_id, operator_id ON public.authority_proofs FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('profile_version_id', 'operator_id', 'proof');
--> statement-breakpoint
CREATE TRIGGER authority_uses_domain_profile_scope_guard BEFORE INSERT OR UPDATE OF domain_profile_version_id, operator_id ON public.authority_uses FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('domain_profile_version_id', 'operator_id', 'domain');
--> statement-breakpoint
CREATE TRIGGER authority_uses_receiver_profile_scope_guard BEFORE INSERT OR UPDATE OF receiver_profile_version_id, operator_id ON public.authority_uses FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('receiver_profile_version_id', 'operator_id', 'receiver');
--> statement-breakpoint
CREATE TRIGGER dropoffs_lifecycle_guard_trigger BEFORE INSERT OR UPDATE ON public.dropoffs FOR EACH ROW EXECUTE FUNCTION public.dropoffs_lifecycle_guard();
--> statement-breakpoint
CREATE TRIGGER erased_operators_no_change BEFORE DELETE OR UPDATE ON public.erased_operators FOR EACH ROW EXECUTE FUNCTION public.erased_operators_append_only();
--> statement-breakpoint
CREATE TRIGGER evidence_pack_artifacts_immutable BEFORE DELETE OR UPDATE ON public.evidence_pack_artifacts FOR EACH ROW EXECUTE FUNCTION public.reject_evidence_pack_artifact_mutation();
--> statement-breakpoint
CREATE TRIGGER operator_decision_sources_immutable BEFORE DELETE OR UPDATE ON public.operator_decision_sources FOR EACH ROW EXECUTE FUNCTION public.reject_operator_decision_mutation();
--> statement-breakpoint
CREATE TRIGGER operator_decisions_immutable BEFORE DELETE OR UPDATE ON public.operator_decisions FOR EACH ROW EXECUTE FUNCTION public.reject_operator_decision_mutation();
--> statement-breakpoint
CREATE TRIGGER proxy_operation_attempt_budget_trigger BEFORE INSERT ON public.proxy_operation_attempts FOR EACH ROW EXECUTE FUNCTION public.enforce_proxy_operation_attempt_budget();
--> statement-breakpoint
CREATE TRIGGER proxy_operation_evidence_append_only_trigger BEFORE DELETE OR UPDATE ON public.proxy_operation_evidence FOR EACH ROW EXECUTE FUNCTION public.protect_proxy_operation_evidence();
--> statement-breakpoint
CREATE TRIGGER receiver_transaction_receipts_profile_scope_guard BEFORE INSERT OR UPDATE OF receiver_profile_version_id, operator_id ON public.receiver_transaction_receipts FOR EACH ROW EXECUTE FUNCTION public.authority_profile_reference_guard('receiver_profile_version_id', 'operator_id', 'receiver');
--> statement-breakpoint
ALTER TABLE ONLY public.admin_actions
    ADD CONSTRAINT admin_actions_admin_operator_id_operators_id_fk FOREIGN KEY (admin_operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.admin_actions
    ADD CONSTRAINT admin_actions_target_operator_id_operators_id_fk FOREIGN KEY (target_operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.agent_service_grants
    ADD CONSTRAINT agent_service_grants_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.agent_service_grants
    ADD CONSTRAINT agent_service_grants_service_connection_id_service_connections_ FOREIGN KEY (service_connection_id) REFERENCES public.service_connections(id);
--> statement-breakpoint
ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.audit_archive_segments
    ADD CONSTRAINT audit_archive_segments_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_authoriser_operator_fk FOREIGN KEY (authoriser_principal_id, operator_id) REFERENCES public.authority_principals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_capacity_proof_operator_fk FOREIGN KEY (capacity_proof_id, capacity_proof_version, operator_id) REFERENCES public.authority_proofs(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_decision_proof_operator_fk FOREIGN KEY (decision_proof_id, decision_proof_version, operator_id) REFERENCES public.authority_proofs(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_identity_proof_operator_fk FOREIGN KEY (identity_proof_id, identity_proof_version, operator_id) REFERENCES public.authority_proofs(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_decisions
    ADD CONSTRAINT authority_approval_decisions_request_operator_fk FOREIGN KEY (request_id, operator_id) REFERENCES public.authority_approval_requests(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_requests
    ADD CONSTRAINT authority_approval_requests_binding_operator_fk FOREIGN KEY (binding_id, binding_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_requests
    ADD CONSTRAINT authority_approval_requests_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_approval_requests
    ADD CONSTRAINT authority_approval_requests_use_operator_fk FOREIGN KEY (authority_use_id, operator_id) REFERENCES public.authority_uses(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_binding_proofs
    ADD CONSTRAINT authority_binding_proofs_authoriser_operator_fk FOREIGN KEY (authoriser_principal_id, operator_id) REFERENCES public.authority_principals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_binding_proofs
    ADD CONSTRAINT authority_binding_proofs_binding_operator_fk FOREIGN KEY (binding_id, binding_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_binding_proofs
    ADD CONSTRAINT authority_binding_proofs_proof_operator_fk FOREIGN KEY (proof_id, proof_version, operator_id) REFERENCES public.authority_proofs(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_agent_operator_fk FOREIGN KEY (agent_id, operator_id) REFERENCES public.agents(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_claim_operator_fk FOREIGN KEY (claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_domain_profile_version_id_fkey FOREIGN KEY (domain_profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_parent_operator_fk FOREIGN KEY (parent_binding_id, parent_binding_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_principal_operator_fk FOREIGN KEY (principal_id, operator_id) REFERENCES public.authority_principals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_receiver_operator_fk FOREIGN KEY (receiver_id, operator_id) REFERENCES public.authority_receivers(id, managed_by_operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_receiver_profile_version_id_fkey FOREIGN KEY (receiver_profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_root_operator_fk FOREIGN KEY (lineage_root_id, lineage_root_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_tombstone_claim_id_fkey FOREIGN KEY (tombstone_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_bindings
    ADD CONSTRAINT authority_bindings_tombstone_claim_operator_fk FOREIGN KEY (tombstone_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_idempotency_keys
    ADD CONSTRAINT authority_idempotency_keys_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_binding_operator_fk FOREIGN KEY (binding_id, binding_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_receiver_operator_fk FOREIGN KEY (receiver_id, operator_id) REFERENCES public.authority_receivers(id, managed_by_operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_receiver_profile_version_id_fkey FOREIGN KEY (receiver_profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_request_key_receiver_fk FOREIGN KEY (request_signing_key_id, receiver_id) REFERENCES public.authority_receiver_keys(id, receiver_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_response_key_receiver_fk FOREIGN KEY (response_encryption_key_id, receiver_id) REFERENCES public.authority_receiver_keys(id, receiver_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_tombstone_claim_id_fkey FOREIGN KEY (tombstone_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_tombstone_claim_operator_fk FOREIGN KEY (tombstone_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_presentations
    ADD CONSTRAINT authority_presentations_use_operator_fk FOREIGN KEY (authority_use_id, operator_id) REFERENCES public.authority_uses(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_principals
    ADD CONSTRAINT authority_principals_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_principals
    ADD CONSTRAINT authority_principals_superseded_operator_fk FOREIGN KEY (superseded_by_id, operator_id) REFERENCES public.authority_principals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_principals
    ADD CONSTRAINT authority_principals_tombstone_claim_id_fkey FOREIGN KEY (tombstone_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_principals
    ADD CONSTRAINT authority_principals_tombstone_claim_operator_fk FOREIGN KEY (tombstone_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_profile_versions
    ADD CONSTRAINT authority_profile_versions_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_profile_versions
    ADD CONSTRAINT authority_profile_versions_claim_owner_fk FOREIGN KEY (claim_id, owner_operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_profile_versions
    ADD CONSTRAINT authority_profile_versions_owner_operator_id_fkey FOREIGN KEY (owner_operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_profile_versions
    ADD CONSTRAINT authority_profile_versions_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES public.authority_receivers(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_profile_versions
    ADD CONSTRAINT authority_profile_versions_receiver_owner_fk FOREIGN KEY (receiver_id, owner_operator_id) REFERENCES public.authority_receivers(id, managed_by_operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proof_dependencies
    ADD CONSTRAINT authority_proof_dependencies_derived_operator_fk FOREIGN KEY (derived_proof_id, derived_proof_version, operator_id) REFERENCES public.authority_proofs(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proof_dependencies
    ADD CONSTRAINT authority_proof_dependencies_source_operator_fk FOREIGN KEY (source_proof_id, source_proof_version, operator_id) REFERENCES public.authority_proofs(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_claim_operator_fk FOREIGN KEY (claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_legacy_identity_claim_id_fkey FOREIGN KEY (legacy_identity_claim_id) REFERENCES public.identity_claims(id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_legacy_identity_operator_fk FOREIGN KEY (legacy_identity_claim_id, operator_id) REFERENCES public.identity_claims(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_profile_version_id_fkey FOREIGN KEY (profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_represented_operator_fk FOREIGN KEY (represented_principal_id, operator_id) REFERENCES public.authority_principals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_subject_operator_fk FOREIGN KEY (subject_principal_id, operator_id) REFERENCES public.authority_principals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_tombstone_claim_id_fkey FOREIGN KEY (tombstone_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_proofs
    ADD CONSTRAINT authority_proofs_tombstone_claim_operator_fk FOREIGN KEY (tombstone_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receiver_keys
    ADD CONSTRAINT authority_receiver_keys_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES public.authority_receivers(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receivers
    ADD CONSTRAINT authority_receivers_current_profile_fk FOREIGN KEY (current_profile_version_id, managed_by_operator_id) REFERENCES public.authority_profile_versions(id, owner_operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receivers
    ADD CONSTRAINT authority_receivers_managed_by_operator_id_fkey FOREIGN KEY (managed_by_operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_receivers
    ADD CONSTRAINT authority_receivers_proxy_connection_operator_fk FOREIGN KEY (proxy_service_connection_id, managed_by_operator_id) REFERENCES public.service_connections(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_agent_operator_fk FOREIGN KEY (agent_id, operator_id) REFERENCES public.agents(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_binding_operator_fk FOREIGN KEY (binding_id, binding_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_domain_profile_version_id_fkey FOREIGN KEY (domain_profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_intent_claim_id_fkey FOREIGN KEY (intent_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_intent_claim_operator_fk FOREIGN KEY (intent_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_mission_operator_fk FOREIGN KEY (mission_id, operator_id) REFERENCES public.missions(mission_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_outcome_claim_id_fkey FOREIGN KEY (outcome_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_outcome_claim_operator_fk FOREIGN KEY (outcome_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_passport_operator_fk FOREIGN KEY (passport_jti, operator_id) REFERENCES public.passports(jti, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_receiver_operator_fk FOREIGN KEY (receiver_id, operator_id) REFERENCES public.authority_receivers(id, managed_by_operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.authority_uses
    ADD CONSTRAINT authority_uses_receiver_profile_version_id_fkey FOREIGN KEY (receiver_profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.cmek_migrations
    ADD CONSTRAINT cmek_migrations_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.connect_links
    ADD CONSTRAINT connect_links_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.control_decisions
    ADD CONSTRAINT control_decisions_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.control_event_outbox
    ADD CONSTRAINT control_event_outbox_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.control_policies
    ADD CONSTRAINT control_policies_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.control_policy_revisions
    ADD CONSTRAINT control_policy_revisions_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.control_reviews
    ADD CONSTRAINT control_reviews_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.control_sockets
    ADD CONSTRAINT control_sockets_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.dropoffs
    ADD CONSTRAINT dropoffs_from_agent_id_agents_id_fk FOREIGN KEY (from_agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.dropoffs
    ADD CONSTRAINT dropoffs_mission_operator_fk FOREIGN KEY (mission_id, operator_id) REFERENCES public.missions(mission_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.dropoffs
    ADD CONSTRAINT dropoffs_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.dropoffs
    ADD CONSTRAINT dropoffs_to_agent_id_agents_id_fk FOREIGN KEY (to_agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.evidence_pack_artifacts
    ADD CONSTRAINT evidence_pack_artifacts_claim_id_passport_claims_claim_id_fk FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.evidence_pack_artifacts
    ADD CONSTRAINT evidence_pack_artifacts_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.external_anchors
    ADD CONSTRAINT external_anchors_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_memberships
    ADD CONSTRAINT fleet_memberships_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_memberships
    ADD CONSTRAINT fleet_memberships_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_memberships
    ADD CONSTRAINT fleet_memberships_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.fleet_policies(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_mission_starts
    ADD CONSTRAINT fleet_mission_starts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_mission_starts
    ADD CONSTRAINT fleet_mission_starts_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_mission_starts
    ADD CONSTRAINT fleet_mission_starts_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.fleet_policies(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_missions
    ADD CONSTRAINT fleet_missions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_missions
    ADD CONSTRAINT fleet_missions_membership_id_fkey FOREIGN KEY (membership_id) REFERENCES public.fleet_memberships(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_missions
    ADD CONSTRAINT fleet_missions_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(mission_id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_missions
    ADD CONSTRAINT fleet_missions_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_missions
    ADD CONSTRAINT fleet_missions_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.fleet_policies(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_intent_claim_id_fkey FOREIGN KEY (intent_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_mission_id_fkey FOREIGN KEY (mission_id) REFERENCES public.missions(mission_id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.fleet_policies(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_proxy_operation_id_fkey FOREIGN KEY (proxy_operation_id) REFERENCES public.proxy_operations(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_policies
    ADD CONSTRAINT fleet_policies_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_policies
    ADD CONSTRAINT fleet_policies_root_agent_id_fkey FOREIGN KEY (root_agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.fleet_policy_revisions
    ADD CONSTRAINT fleet_policy_revisions_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.fleet_policies(id);
--> statement-breakpoint
ALTER TABLE ONLY public.governance_approvals
    ADD CONSTRAINT governance_approvals_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.identity_claims
    ADD CONSTRAINT identity_claims_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.identity_claims
    ADD CONSTRAINT identity_claims_provider_id_identity_providers_id_fk FOREIGN KEY (provider_id) REFERENCES public.identity_providers(id);
--> statement-breakpoint
ALTER TABLE ONLY public.identity_verification_sessions
    ADD CONSTRAINT identity_verification_sessions_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.inbound_webhook_receipts
    ADD CONSTRAINT inbound_webhook_receipts_webhook_id_inbound_webhooks_id_fk FOREIGN KEY (webhook_id) REFERENCES public.inbound_webhooks(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.inbound_webhooks
    ADD CONSTRAINT inbound_webhooks_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE SET NULL;
--> statement-breakpoint
ALTER TABLE ONLY public.inbound_webhooks
    ADD CONSTRAINT inbound_webhooks_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_fleet_mission_id_fkey FOREIGN KEY (fleet_mission_id) REFERENCES public.missions(mission_id);
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_fleet_policy_id_fkey FOREIGN KEY (fleet_policy_id) REFERENCES public.fleet_policies(id);
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_intent_claim_id_passport_claims_claim_id_fk FOREIGN KEY (intent_claim_id) REFERENCES public.passport_claims(claim_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_passport_jti_passports_jti_fk FOREIGN KEY (passport_jti) REFERENCES public.passports(jti) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.intent_approvals
    ADD CONSTRAINT intent_approvals_simulated_claim_id_passport_claims_claim_id_fk FOREIGN KEY (simulated_claim_id) REFERENCES public.passport_claims(claim_id) ON DELETE SET NULL;
--> statement-breakpoint
ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.magic_link_tokens
    ADD CONSTRAINT magic_link_tokens_member_id_team_members_id_fk FOREIGN KEY (member_id) REFERENCES public.team_members(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.magic_link_tokens
    ADD CONSTRAINT magic_link_tokens_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.mission_outputs
    ADD CONSTRAINT mission_outputs_mission_id_operator_id_fkey FOREIGN KEY (mission_id, operator_id) REFERENCES public.missions(mission_id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_assigned_agent_id_fkey FOREIGN KEY (assigned_agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_claim_id_passport_claims_claim_id_fk FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.missions
    ADD CONSTRAINT missions_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channel_verifications
    ADD CONSTRAINT notification_channel_verifications_channel_id_notification_chan FOREIGN KEY (channel_id) REFERENCES public.notification_channels(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channel_verifications
    ADD CONSTRAINT notification_channel_verifications_destination_id_notification_ FOREIGN KEY (destination_id) REFERENCES public.notification_destinations(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channels
    ADD CONSTRAINT notification_channels_destination_id_notification_destinations_ FOREIGN KEY (destination_id) REFERENCES public.notification_destinations(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.notification_channels
    ADD CONSTRAINT notification_channels_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.notification_destinations
    ADD CONSTRAINT notification_destinations_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_client_id_oauth_clients_id_fk FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_member_id_team_members_id_fk FOREIGN KEY (member_id) REFERENCES public.team_members(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_client_id_oauth_clients_id_fk FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_member_id_team_members_id_fk FOREIGN KEY (member_id) REFERENCES public.team_members(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_client_id_oauth_clients_id_fk FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_member_id_team_members_id_fk FOREIGN KEY (member_id) REFERENCES public.team_members(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.oidc_idp_configs
    ADD CONSTRAINT oidc_idp_configs_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decision_sources
    ADD CONSTRAINT operator_decision_sources_decision_operator_fk FOREIGN KEY (decision_id, operator_id) REFERENCES public.operator_decisions(id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_claim_id_passport_claims_claim_id_fk FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_mission_operator_fk FOREIGN KEY (mission_id, operator_id) REFERENCES public.missions(mission_id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_decisions
    ADD CONSTRAINT operator_decisions_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_detector_config
    ADD CONSTRAINT operator_detector_config_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_changes
    ADD CONSTRAINT operator_email_changes_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_delivery_jobs
    ADD CONSTRAINT operator_email_delivery_jobs_email_change_id_operator_email_cha FOREIGN KEY (email_change_id) REFERENCES public.operator_email_changes(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_email_delivery_jobs
    ADD CONSTRAINT operator_email_delivery_jobs_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_erasure_jobs
    ADD CONSTRAINT operator_erasure_jobs_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_oauth_apps
    ADD CONSTRAINT operator_oauth_apps_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.operator_pii_config
    ADD CONSTRAINT operator_pii_config_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operator_signing_keys
    ADD CONSTRAINT operator_signing_keys_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.operators
    ADD CONSTRAINT operators_parent_operator_id_fk FOREIGN KEY (parent_operator_id) REFERENCES public.operators(id) ON DELETE RESTRICT;
--> statement-breakpoint
ALTER TABLE ONLY public.partner_grants
    ADD CONSTRAINT partner_grants_partner_operator_id_operators_id_fk FOREIGN KEY (partner_operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.partner_grants
    ADD CONSTRAINT partner_grants_user_operator_id_operators_id_fk FOREIGN KEY (user_operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_authority_bindings
    ADD CONSTRAINT passport_authority_bindings_binding_claim_id_fkey FOREIGN KEY (binding_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_authority_bindings
    ADD CONSTRAINT passport_authority_bindings_binding_operator_fk FOREIGN KEY (binding_id, binding_version, operator_id) REFERENCES public.authority_bindings(id, version, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_authority_bindings
    ADD CONSTRAINT passport_authority_bindings_claim_operator_fk FOREIGN KEY (binding_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_authority_bindings
    ADD CONSTRAINT passport_authority_bindings_passport_operator_fk FOREIGN KEY (passport_jti, operator_id) REFERENCES public.passports(jti, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkouts
    ADD CONSTRAINT passport_checkouts_mission_operator_fk FOREIGN KEY (mission_id, operator_id) REFERENCES public.missions(mission_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkouts
    ADD CONSTRAINT passport_checkouts_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkouts
    ADD CONSTRAINT passport_checkouts_passport_jti_passports_jti_fk FOREIGN KEY (passport_jti) REFERENCES public.passports(jti);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkpoints
    ADD CONSTRAINT passport_checkpoints_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_checkpoints
    ADD CONSTRAINT passport_checkpoints_passport_jti_passports_jti_fk FOREIGN KEY (passport_jti) REFERENCES public.passports(jti);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_claims
    ADD CONSTRAINT passport_claims_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.passport_claims
    ADD CONSTRAINT passport_claims_passport_id_passports_jti_fk FOREIGN KEY (passport_id) REFERENCES public.passports(jti) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.passport_reviews
    ADD CONSTRAINT passport_reviews_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_reviews
    ADD CONSTRAINT passport_reviews_checkout_id_passport_checkouts_id_fk FOREIGN KEY (checkout_id) REFERENCES public.passport_checkouts(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passport_reviews
    ADD CONSTRAINT passport_reviews_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passports
    ADD CONSTRAINT passports_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id);
--> statement-breakpoint
ALTER TABLE ONLY public.passports
    ADD CONSTRAINT passports_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_accounting_receipts
    ADD CONSTRAINT proxy_accounting_receipts_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_attempts
    ADD CONSTRAINT proxy_operation_attempts_operation_operator_fk FOREIGN KEY (operation_id, operator_id) REFERENCES public.proxy_operations(id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_evidence
    ADD CONSTRAINT proxy_operation_evidence_operation_operator_fk FOREIGN KEY (operation_id, operator_id) REFERENCES public.proxy_operations(id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_replacement_acknowledgements
    ADD CONSTRAINT proxy_operation_replacement_consumed_operator_fk FOREIGN KEY (consumed_by_operation_id, operator_id) REFERENCES public.proxy_operations(id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_replacement_acknowledgements
    ADD CONSTRAINT proxy_operation_replacement_operator_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operation_replacement_acknowledgements
    ADD CONSTRAINT proxy_operation_replacement_original_operator_fk FOREIGN KEY (original_operation_id, operator_id) REFERENCES public.proxy_operations(id, operator_id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_agent_operator_fk FOREIGN KEY (agent_id, operator_id) REFERENCES public.agents(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_approval_operator_fk FOREIGN KEY (approval_id, operator_id) REFERENCES public.intent_approvals(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_authority_use_operator_fk FOREIGN KEY (authority_use_id, operator_id) REFERENCES public.authority_uses(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_connection_operator_fk FOREIGN KEY (service_connection_id, operator_id) REFERENCES public.service_connections(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_passport_operator_fk FOREIGN KEY (passport_jti, operator_id) REFERENCES public.passports(jti, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.proxy_operations
    ADD CONSTRAINT proxy_operations_service_id_services_id_fk FOREIGN KEY (service_id) REFERENCES public.services(id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_claim_operator_fk FOREIGN KEY (claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_key_receiver_fk FOREIGN KEY (receiver_key_id, receiver_id) REFERENCES public.authority_receiver_keys(id, receiver_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_presentation_operator_fk FOREIGN KEY (presentation_id, operator_id) REFERENCES public.authority_presentations(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_receiver_operator_fk FOREIGN KEY (receiver_id, operator_id) REFERENCES public.authority_receivers(id, managed_by_operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_receiver_profile_version_id_fkey FOREIGN KEY (receiver_profile_version_id) REFERENCES public.authority_profile_versions(id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_tombstone_claim_id_fkey FOREIGN KEY (tombstone_claim_id) REFERENCES public.passport_claims(claim_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_tombstone_claim_operator_fk FOREIGN KEY (tombstone_claim_id, operator_id) REFERENCES public.passport_claims(claim_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.receiver_transaction_receipts
    ADD CONSTRAINT receiver_transaction_receipts_use_operator_fk FOREIGN KEY (authority_use_id, operator_id) REFERENCES public.authority_uses(id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_claim_id_passport_claims_claim_id_fk FOREIGN KEY (claim_id) REFERENCES public.passport_claims(claim_id) ON DELETE SET NULL;
--> statement-breakpoint
ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_mission_operator_fk FOREIGN KEY (mission_id, operator_id) REFERENCES public.missions(mission_id, operator_id);
--> statement-breakpoint
ALTER TABLE ONLY public.security_events
    ADD CONSTRAINT security_events_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_configurations
    ADD CONSTRAINT service_configurations_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_configurations
    ADD CONSTRAINT service_configurations_service_id_services_id_fk FOREIGN KEY (service_id) REFERENCES public.services(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_connections
    ADD CONSTRAINT service_connections_member_id_team_members_id_fk FOREIGN KEY (member_id) REFERENCES public.team_members(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_connections
    ADD CONSTRAINT service_connections_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_connections
    ADD CONSTRAINT service_connections_service_id_services_id_fk FOREIGN KEY (service_id) REFERENCES public.services(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_identity_requirements
    ADD CONSTRAINT service_identity_requirements_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.service_identity_requirements
    ADD CONSTRAINT service_identity_requirements_service_id_services_id_fk FOREIGN KEY (service_id) REFERENCES public.services(id);
--> statement-breakpoint
ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.spiffe_trust_domains
    ADD CONSTRAINT spiffe_trust_domains_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.twin_runs
    ADD CONSTRAINT twin_runs_mission_id_missions_mission_id_fk FOREIGN KEY (mission_id) REFERENCES public.missions(mission_id) ON DELETE CASCADE NOT VALID;
--> statement-breakpoint
ALTER TABLE ONLY public.usage_daily_by_action
    ADD CONSTRAINT usage_daily_by_action_usage_day_fk FOREIGN KEY (operator_id, day) REFERENCES public.usage_daily(operator_id, day) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.usage_daily
    ADD CONSTRAINT usage_daily_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES public.operators(id);
--> statement-breakpoint
ALTER TABLE ONLY public.usage_monthly_allowances
    ADD CONSTRAINT usage_monthly_allowances_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
--> statement-breakpoint
ALTER TABLE ONLY public.wimse_issuers
    ADD CONSTRAINT wimse_issuers_operator_id_operators_id_fk FOREIGN KEY (operator_id) REFERENCES public.operators(id) ON DELETE CASCADE;
