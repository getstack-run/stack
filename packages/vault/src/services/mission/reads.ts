// Operator-scoped mission reads. A scope, when given, must match the mission's operator and, for an
// agent, one of its assigned agents.

import { createHash } from 'node:crypto';
import { ServiceUnavailableError } from '@stack/shared';
import { ConflictError, NotFoundError } from '@stack/shared';
import { type MissionServiceDeps, type MissionView, type MissionListResult } from './types.js';
import { rowToView } from './helpers.js';

export async function findById(
  deps: MissionServiceDeps,
  missionId: string,
  scope?: { operatorId: string; agentId?: string },
): Promise<MissionView | null> {
  const row = await deps.repo.findById(missionId);
  if (scope && (!row || row.operator_id !== scope.operatorId)) return null;
  if (
    scope?.agentId &&
    !(await deps.repo.hasAgent(missionId, scope.operatorId, scope.agentId))
  )
    return null;
  return row ? rowToView(row) : null;
}

export async function readOutput(
  deps: MissionServiceDeps,
  missionId: string,
  actor: { operatorId: string; agentId?: string },
) {
  const mission = await deps.repo.findById(missionId);
  if (
    !mission ||
    mission.operator_id !== actor.operatorId ||
    (actor.agentId &&
      mission.assigned_agent_id !== actor.agentId &&
      !(await deps.repo.hasAgent(missionId, actor.operatorId, actor.agentId)))
  )
    throw new NotFoundError('mission', missionId);
  const stored = await deps.repo.findOutput(actor.operatorId, missionId);
  if (!stored) return null;
  if (!deps.kms) throw new ServiceUnavailableError();
  const plaintext = await deps.kms.decrypt(stored.output_encrypted, {
    operator_id: actor.operatorId,
    mission_id: missionId,
    store: 'mission_output',
  });
  const digest = createHash('sha256').update(plaintext).digest('hex');
  if (digest !== stored.output_digest || digest !== stored.claim.output_digest)
    throw new ConflictError('Conflict');
  const decoded = JSON.parse(plaintext) as { salt: string; output: unknown };
  if (typeof decoded.salt !== 'string' || !/^[a-f0-9]{64}$/.test(decoded.salt))
    throw new ConflictError('Conflict');
  return { output: decoded.output, output_salt: decoded.salt, output_digest: digest };
}

export async function listByOperator(
  deps: MissionServiceDeps,
  operatorId: string,
  opts?: {
    status?: 'active' | 'completed' | 'revoked' | 'paused';
    agentId?: string;
    page?: number;
    limit?: number;
  },
): Promise<MissionListResult> {
  const page = opts?.page ?? 1;
  const limit = opts?.limit ?? 50;
  const [rows, total] = await Promise.all([
    deps.repo.listByOperator(operatorId, opts),
    deps.repo.countByOperator(operatorId, opts?.status, opts?.agentId),
  ]);
  const counts = await deps.repo.countEvidenceByMissionIds(
    operatorId,
    rows.map((row) => row.mission_id),
  );
  return {
    items: rows.map((row) => {
      const evidence = counts.get(row.mission_id);
      return {
        ...rowToView(row),
        dossier_count: evidence?.dossier_count ?? 0,
        evidence_pack_count: evidence?.evidence_pack_count ?? 0,
      };
    }),
    page,
    limit,
    total,
    has_more: page * limit < total,
  };
}

export async function listPassports(
  deps: MissionServiceDeps,
  operatorId: string,
  missionId: string,
  opts: { agentId?: string; page?: number; limit?: number },
) {
  const mission = await findById(deps, missionId, {
    operatorId,
    ...(opts.agentId ? { agentId: opts.agentId } : {}),
  });
  if (!mission || mission.operator_id !== operatorId)
    throw new NotFoundError('Mission', missionId);
  return deps.repo.listPassports(operatorId, missionId, opts);
}
