import { evidenceAction, evidenceUrl, flowSourceLabel, observedKnowsEntity, redactRequestPath, safeErrorSummary, trailEntity, type IntentClaim } from '@stack/shared';
import type { Services } from '../../config/services.js';
import { flowMissionId, readObservedRows } from '../../lib/provenance.js';
import { proxyCallEntities } from '../../lib/proxy-observation.js';
import type {
  AdmittedGate,
  OutputScanResult,
  ParsedProxyRequest,
  ProxyCredentialInjection,
  RuntimeClaimIds,
  UpstreamResult,
  VerifiedProxyPassport,
} from './types.js';

/**
 * 11a. producer — emit intent_claim + intent_outcome
 *      + entity_observation triple for the success path. Gated on
 *      accountability != 'standard' by design (standard-
 *      mode passports are explicit opt-outs from signed-claim
 *      emission; emitting 3 signed claims per proxy call there is
 *      wasted KMS volume + DB write load). All three are
 *      fire-and-forget: a producer-side failure must NEVER alter
 *      the response the agent already saw.
 *
 * The entity_observation is NOT part of this gate: see observeEntities
 * below. Returns the claim ids the runtime authority use is finalised with.
 */
export async function emitIntentAndOutcomeClaims(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  gate: AdmittedGate,
  injection: ProxyCredentialInjection,
  result: UpstreamResult,
  outResult: OutputScanResult,
  start: number,
): Promise<RuntimeClaimIds> {
  const { input } = parsedRequest;
  const { jti, agentId, operatorId, mode, missionRef } = verified;
  const { resolvedUrl } = injection;
  let runtimeIntentClaimId: string | undefined;
  let runtimeOutcomeClaimId: string | undefined;
  if ((mode === 'enforced' || mode === 'logged') && result.status >= 200 && result.status < 400) {
    // when the approval gate admitted this call
    // the intent_outcome links to the ALREADY-approved IntentClaim
    // (no synthetic intent_claim duplicate). For logged mode (no
    // gate) we still emit the synthetic intent_claim as in 2.3.
    let intentClaimId: string | undefined;
    if (!gate.skipped) {
      intentClaimId = gate.intentClaimId;
    } else {
      const intentBody: IntentClaim = {
        type: 'intent_claim',
        intent_type: 'http_call',
        agent_id: agentId,
        named_intent: `${input.service}:http:proxy`,
        target: input.service,
        action: evidenceAction(input.method, input.url),
        parameters: { service: input.service, method: input.method, url: evidenceUrl(input.url), body: input.body },
        estimated_cost: { wallet_cents: 0, tokens: null, gas_gwei: null },
        accountability: mode,
        reason: null,
        requires: [],
        user_subject: null,
        mission_ref: missionRef,
        submitted_at: start,
      };
      try {
        const intentRes = await services.claimRegistry.registerClaim({
          operatorId,
          passportJti: jti,
          claimType: 'intent_claim',
          payload: intentBody,
        });
        intentClaimId = intentRes.claimId;
      } catch (err) {
        console.error('proxy intent_claim emission failed:', safeErrorSummary(err));
      }
    }
    runtimeIntentClaimId = intentClaimId;

    if (intentClaimId) {
      try {
        // hashlib import lives at the top of the file in other
        // routes; inline-import here is cheap since this block
        // only runs for non-standard modes.
        const { createHash } = await import('node:crypto');
        // Hash the ACTUAL call shape (independent of whether the
        // intent_claim was synthesised here or pre-approved via the
        // gate). Mirrors the 2.3 producer's behaviour pre-refactor.
        // The same parameters the intent states: its URL is the evidence form, with no query string, so the two
        // hashes agree and a guess at a query cannot be confirmed against a signed hash.
        const paramsForHash = {
          service: input.service,
          method: input.method,
          url: evidenceUrl(input.url),
          body: input.body,
        };
        const paramsHash = createHash('sha256').update(JSON.stringify(paramsForHash)).digest('hex');
        const responseBytes = typeof result.body === 'string'
          ? result.body
          : JSON.stringify(result.body ?? '');
        const responseHash = createHash('sha256').update(responseBytes).digest('hex');
        let host = '';
        let pathOnly = '';
        // The path the agent sent, not the resolved one (a credential field
        // can be interpolated into it), redacted: this is a signed claim.
        try { host = new URL(resolvedUrl).host; } catch { /* noop */ }
        try { pathOnly = new URL(input.url).pathname; } catch { /* noop */ }
        const outcomeMissionRef = missionRef;
        const outcomeResult = await services.claimRegistry.registerClaim({
          operatorId,
          passportJti: jti,
          claimType: 'intent_outcome',
          payload: {
            type: 'intent_outcome',
            intent_claim_ref: intentClaimId,
            status: 'succeeded',
            duration_ms: Date.now() - start,
            cost_actual: { wallet_cents: 0, tokens: null, gas_gwei: null },
            recorded_at: Date.now(),
            outcome_type: 'http_call',
            actual_target: host,
            actual_method_path: `${input.method} ${redactRequestPath(pathOnly)}`,
            actual_parameters_hash: paramsHash,
            status_code: result.status,
            response_body_hash: responseHash,
            latency_ms: Date.now() - start,
            redactions_count: outResult.redactedBody !== null ? 1 : 0,
            detector_fires_count: outResult.match !== null ? 1 : 0,
            ...(outcomeMissionRef ? { mission_ref: outcomeMissionRef } : {}),
          },
        });
        runtimeOutcomeClaimId = outcomeResult.claimId;
      } catch (err) {
        console.error('proxy intent_outcome emission failed:', safeErrorSummary(err));
      }

    }
  }
  return { intentClaimId: runtimeIntentClaimId, outcomeClaimId: runtimeOutcomeClaimId };
}

/**
 * 11b. Entity observation runs for EVERY accountability mode,
 *      including standard.
 *
 *      The triple above stays gated by design: three
 *      signed claims per proxy call in standard mode is wasted KMS
 *      volume and DB write load. That reasoning holds. But the
 *      data-flow rule reads entity_observation, and standard is the
 *      DEFAULT, so leaving this inside that gate made the rule inert
 *      for most agents — the guestbook attack would simply succeed
 *      because nothing had been recorded to compare against.
 *
 *      So standard mode emits ONE claim, not three, and only when
 *      there is something to record. A third of that cost, in exchange
 *      for the control working by default.
 */
export async function observeEntities(
  services: Services,
  parsedRequest: ParsedProxyRequest,
  verified: VerifiedProxyPassport,
  injection: ProxyCredentialInjection,
  result: UpstreamResult,
): Promise<void> {
  const { input } = parsedRequest;
  const { jti, agentId, operatorId, missionIds, missionRef } = verified;
  const { resolvedUrl } = injection;
  if (result.status >= 200 && result.status < 400) {
    // 11a. undeclared_target. A flag - never a
    //      block - when this call reaches a counterparty the passport
    //      has never dealt with and the operator did not pre-declare.
    //      The detector existed but only ran in /v1/intents/simulate, so
    //      a first-ever payment to a stranger was never flagged on a live
    //      call. Fire-and-forget: this is a review signal and must never
    //      add latency or alter the response.
    //
    //      Noise control is the operator's: declaring expected
    //      counterparties on the bound mission silences the expected
    //      ones, so only genuine strangers flag. The event message says
    //      exactly that - the nudge lives in the signal itself.
    void (async () => {
      try {
        const { extractEntities } = await import('@stack/shared');
        const outbound = extractEntities({ url: resolvedUrl, body: input.body }).map((c) =>
          c.entity.toLowerCase(),
        );
        if (outbound.length === 0 || !services.passportClaimsRepo) return;

        // By Mission, like the data-flow rule: a counterparty this job
        // already dealt with under an earlier Passport is not new.
        const observedRows = await readObservedRows(services, {
          operatorId, passportJti: jti, missionId: flowMissionId(missionIds),
        });
        const observed = new Set<string>();
        for (const row of observedRows) {
          for (const e of row.entities ?? []) observed.add(String(e).toLowerCase());
        }
        // Pre-declared counterparties on the bound mission are treated
        // as already-known, so an operator who declares up front is not
        // flagged on first touch.
        if (missionRef && services.mission?.findById) {
          try {
            const m = await services.mission.findById(missionRef);
            for (const cp of (m as { expected_counterparties?: unknown[] } | null)
              ?.expected_counterparties ?? []) {
              if (typeof cp === 'string') observed.add(cp.toLowerCase());
            }
          } catch {
            // mission unresolved / cross-tenant — no pre-declaration.
          }
        }

        // An observation is kept as a one-way digest (or, if recorded before
        // that, as text): either form counts as dealt with.
        const undeclared = outbound.filter((e) => !observedKnowsEntity(observed, e));
        if (undeclared.length === 0) return;

        await services.securityEvent.record({
          operatorId,
          agentId,
          passportJti: jti,
          signalType: 'undeclared_target',
          severity: 'warning', // a review flag, not a block
          message:
            `Call reached ${undeclared.length} counterparty this passport has not ` +
            `dealt with before: ${undeclared.slice(0, 5).join(', ')}. ` +
            `Declare expected counterparties on the mission to silence expected ones.`,
          metadata: {
            undeclared_entities: undeclared.slice(0, 20),
            destination_service: input.service,
            review_flag: true,
          },
          missionIds,
        });
      } catch (err) {
        console.error('[producer] undeclared_target flag failed:', safeErrorSummary(err));
      }
    })();

    try {
      const { collectStrings, contentFingerprints } = await import('@stack/shared');
      // Extract from URL + headers + a bounded snippet of the
      // response body (raw bytes in scope here — never persisted,
      // only walked by extractEntities). Body is JSON-walked when
      // possible so nested fields are seen.
      let parsedBody: unknown = result.body;
      if (typeof result.body === 'string') {
        try { parsedBody = JSON.parse(result.body); } catch { parsedBody = result.body; }
      }
      // What was READ (the answer) AND what the call SENT (its URL and
      // body, the counterparty it CONTACTED). The sent side is there for
      // the undeclared_target flag, which treats an observed counterparty
      // as known, so a call must record who it contacted or every repeat
      // to the same party would flag again. The part of it that is only
      // the request's own URL is listed again in `request_entities`, so
      // the data-flow rule does not take what the agent sent for content
      // it read (lib/proxy-observation.ts). Deduped by value, capped at
      // the claim schema's 256.
      const { candidates, requestEntities } = proxyCallEntities({
        service: input.service,
        method: input.method,
        resolvedUrl,
        requestBody: input.body,
        responseHeaders: result.headers,
        responseBody: parsedBody,
      });
      // Content fingerprints of what was READ. The entity catalogue
      // cannot see an ordinary name, so without these the data-flow
      // rule could not act on the case it exists for: an agent mailing
      // a list of names it read somewhere else. One-way hashes only —
      // the text itself is never recorded.
      const readText = collectStrings(parsedBody).join(' ');
      const fingerprints = readText ? contentFingerprints(readText) : [];
      if (candidates.length > 0 || fingerprints.length > 0) {
        const entityMissionRef = missionRef;
        await services.claimRegistry.registerClaim({
          operatorId,
          passportJti: jti,
          claimType: 'entity_observation',
          payload: {
            type: 'entity_observation',
            // One-way digests: the trail never keeps an address, a name or an
            // id a proxied call read or sent, only what lets the wall and the
            // undeclared-counterparty check recognise it again.
            entities: candidates.map((c) => trailEntity(c.entity)),
            entity_types: candidates.map((c) => c.entity_type),
            // The ones of those that are only the request's own URL: sent, not read.
            ...(requestEntities.length > 0 ? { request_entities: requestEntities } : {}),
            agent_id: agentId,
            // Typed provenance. This used to live only in the untyped
            // metadata blob below, which the schema does not validate
            // and nothing read.
            // The service and the connection it was read through: the data-flow rule treats two
            // connections of one service as two sources.
            source_service: flowSourceLabel(input.service, injection.connectionId),
            content_fingerprints: fingerprints,
            metadata: {
              extraction_method: 'regex',
              source: 'proxy_http_call',
              service: input.service,
            },
            observed_at: Date.now(),
            ...(entityMissionRef ? { mission_ref: entityMissionRef } : {}),
          },
        });
      }
    } catch (err) {
      console.error('proxy entity_observation emission failed:', safeErrorSummary(err));
    }
  }
}
