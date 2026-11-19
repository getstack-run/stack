import {
  createDb,
  operators,
  serviceIdentityRequirements,
  services,
} from '@stack/shared';
import { and, eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import { IdentityRepository } from './identity-repo.js';

const DATABASE_URL = process.env['DATABASE_URL'];
const describeWithDb = DATABASE_URL ? describe : describe.skip;

describeWithDb('IdentityRepository requirement replacement', () => {
  const db = createDb(DATABASE_URL!);
  const repo = new IdentityRepository(db);

  it('replaces or removes one operator service policy in one transaction', async () => {
    const suffix = Math.random().toString(36).slice(2);
    const operatorId = `op_req_${suffix}`;
    const otherOperatorId = `op_req_other_${suffix}`;
    const serviceId = `svc_req_${suffix}`;
    const provider = `provider_req_${suffix}`;
    const requirement = (
      id: string,
      principalOperatorId: string,
      layer: string,
      claim: string,
    ) => ({
      id,
      operator_id: principalOperatorId,
      service_id: serviceId,
      layer,
      requires_claim: claim,
      minimum_assurance: 'substantial',
      accepted_providers: ['stripe_identity'],
      requires_pii: layer === 'identity',
      lawful_basis: layer === 'identity' ? 'contract' : null,
    });

    await db.insert(operators).values([
      { id: operatorId, email: `${operatorId}@test.invalid`, api_key_hash: `hash_${operatorId}` },
      { id: otherOperatorId, email: `${otherOperatorId}@test.invalid`, api_key_hash: `hash_${otherOperatorId}` },
    ]);
    await db.insert(services).values({
      id: serviceId,
      provider,
      name: 'Requirement transaction test',
      description: 'Test service',
      oauth_auth_url: '',
      oauth_token_url: '',
      scopes_available: ['*'],
      available: false,
    });

    try {
      await db.insert(serviceIdentityRequirements).values([
        requirement(`sir_old_a_${suffix}`, operatorId, 'humanity', 'verified_human'),
        requirement(`sir_old_b_${suffix}`, operatorId, 'delegation', 'delegated_access'),
        requirement(`sir_foreign_${suffix}`, otherOperatorId, 'humanity', 'foreign_claim'),
      ]);

      const replaced = await repo.replaceRequirements(
        operatorId,
        serviceId,
        requirement(`sir_new_${suffix}`, operatorId, 'identity', 'verified_identity'),
      );
      expect(replaced).toHaveLength(1);
      expect(replaced[0]).toMatchObject({ requires_claim: 'verified_identity' });
      await expect(repo.findRequirementsByService(otherOperatorId, serviceId)).resolves.toHaveLength(1);

      const concurrent = await Promise.all([
        repo.replaceRequirements(
          operatorId,
          serviceId,
          requirement(`sir_race_a_${suffix}`, operatorId, 'humanity', 'race_a'),
        ),
        repo.replaceRequirements(
          operatorId,
          serviceId,
          requirement(`sir_race_b_${suffix}`, operatorId, 'delegation', 'race_b'),
        ),
      ]);
      expect(concurrent.every((rows) => rows.length === 1)).toBe(true);
      const afterRace = await repo.findRequirementsByService(operatorId, serviceId);
      expect(afterRace).toHaveLength(1);
      expect(['race_a', 'race_b']).toContain(afterRace[0]?.requires_claim);

      await expect(repo.replaceRequirements(operatorId, serviceId, null)).resolves.toEqual([]);
      await expect(repo.findRequirementsByService(operatorId, serviceId)).resolves.toEqual([]);
      await expect(repo.findRequirementsByService(otherOperatorId, serviceId)).resolves.toHaveLength(1);
    } finally {
      await db.delete(serviceIdentityRequirements).where(eq(serviceIdentityRequirements.service_id, serviceId));
      await db.delete(services).where(eq(services.id, serviceId));
      await db.delete(operators).where(
        and(
          eq(operators.id, operatorId),
        ),
      );
      await db.delete(operators).where(eq(operators.id, otherOperatorId));
    }
  });
});
