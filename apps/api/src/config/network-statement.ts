// The detection rule set STACK's network signs, checked by a self-managed install.
//
// The statement is a compact JWS (`typ` `stack-detection-rules+jwt`, audience
// `stack:detection-rules`, issuer `getstack.run`, EdDSA) signed by STACK's
// deployment key. The install checks it against STACK's published keys (the
// network's `jwks.json`, fetched over https and kept by `jose`), so a proxy or a
// mirror between the install and STACK cannot hand it rules. The same format is
// what the SDK's `verifyDetectionRules` reads for a customer's own code; the
// engine does not depend on the SDK at run time, so the few lines are here.

import { createLocalJWKSet, createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWK, type JWTVerifyGetKey } from 'jose';
import { DETECTION_RULES_AUDIENCE, DETECTION_RULES_TYP, PASSPORT_ISSUER } from '@stack/shared';

/** Where STACK's public keys come from: its `jwks.json` URL, or the keys themselves (a test, an air-gapped check). */
export type StatementKeySource = { jwksUrl: string } | { jwks: { keys: JWK[] } };

export interface RulePack {
  id: string;
  direction: 'input' | 'output';
  rules: Array<{ id: string; severity: string; pattern: string; flags: string }>;
}

export interface VerifiedRuleSet {
  version: string;
  /** Orders rule sets: it goes up whenever a pattern changes. */
  revision: number;
  packs: RulePack[];
  expiresAt: Date;
}

export type StatementFailure = 'invalid' | 'expired' | 'revision_too_old';

export class StatementError extends Error {
  constructor(readonly reason: StatementFailure) {
    super(`The rule set statement was refused (${reason})`);
    this.name = 'StatementError';
  }
}

const remoteKeys = new Map<string, JWTVerifyGetKey>();

function resolver(source: StatementKeySource): JWTVerifyGetKey {
  if ('jwks' in source) return createLocalJWKSet(source.jwks);
  let remote = remoteKeys.get(source.jwksUrl);
  if (!remote) {
    remote = createRemoteJWKSet(new URL(source.jwksUrl));
    remoteKeys.set(source.jwksUrl, remote);
  }
  return remote;
}

/**
 * Check a statement and read the rule set in it. Throws `StatementError`: `expired`
 * for a statement past its time, `revision_too_old` for one that would move the
 * install back to an older set than it holds, `invalid` for anything else (a bad
 * signature, another kind of statement, a body that is not a rule set).
 */
export async function verifyRuleSetStatement(
  statement: string,
  options: { keys: StatementKeySource; now: Date; heldRevision?: number },
): Promise<VerifiedRuleSet> {
  let payload;
  try {
    ({ payload } = await jwtVerify(statement, resolver(options.keys), {
      algorithms: ['EdDSA'],
      typ: DETECTION_RULES_TYP,
      audience: DETECTION_RULES_AUDIENCE,
      issuer: PASSPORT_ISSUER,
      clockTolerance: 5,
      currentDate: options.now,
    }));
  } catch (error) {
    throw new StatementError(error instanceof joseErrors.JWTExpired ? 'expired' : 'invalid');
  }
  const rs = (payload as { rs?: { v?: unknown; version?: unknown; revision?: unknown; packs?: unknown } }).rs;
  if (!rs || rs.v !== 1 || typeof rs.version !== 'string' || !Number.isSafeInteger(rs.revision) || !Array.isArray(rs.packs) || typeof payload.exp !== 'number') {
    throw new StatementError('invalid');
  }
  const revision = rs.revision as number;
  if (options.heldRevision !== undefined && revision < options.heldRevision) throw new StatementError('revision_too_old');
  const packs: RulePack[] = [];
  for (const pack of rs.packs as unknown[]) {
    const p = pack as { id?: unknown; direction?: unknown; rules?: unknown } | null;
    if (!p || typeof p.id !== 'string' || (p.direction !== 'input' && p.direction !== 'output') || !Array.isArray(p.rules)) throw new StatementError('invalid');
    const rules: RulePack['rules'] = [];
    for (const rule of p.rules as unknown[]) {
      const r = rule as { id?: unknown; severity?: unknown; pattern?: unknown; flags?: unknown } | null;
      if (!r || typeof r.id !== 'string' || typeof r.severity !== 'string' || typeof r.pattern !== 'string') throw new StatementError('invalid');
      rules.push({ id: r.id, severity: r.severity, pattern: r.pattern, flags: typeof r.flags === 'string' ? r.flags : '' });
    }
    packs.push({ id: p.id, direction: p.direction, rules });
  }
  return { version: rs.version, revision, packs, expiresAt: new Date(payload.exp * 1000) };
}
