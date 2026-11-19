import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { FleetEnrollmentInput, ForbiddenError } from '@stack/shared';
import type { Services } from '../config/services.js';
import { fleetWorkloadVerifier, verifyFleetWorkload } from '../lib/fleet-workload.js';

/** Identity comes from the pinned workload issuer. No STACK agent key exists yet. */
export function registerFleetWorkloadRoutes(app: FastifyInstance, services: Services) {
  const verifier = fleetWorkloadVerifier(services);
  const params = z.object({ id: z.string().regex(/^flp_[\w-]+$/).max(128) });
  async function identity(policyId: string, authorization: string | undefined) {
    if (!authorization?.startsWith('Bearer ')) throw new ForbiddenError();
    return verifyFleetWorkload(verifier, policyId, authorization.slice(7));
  }
  app.post<{ Params: { id: string } }>('/v1/fleets/:id/workload/enrollment-challenges', async (request) => {
    const { id } = params.parse(request.params);
    z.object({}).strict().parse(request.body ?? {});
    const principal = await identity(id, request.headers.authorization);
    return services.fleet.workloadEnrollmentChallenge(id, principal);
  });
  app.post<{ Params: { id: string } }>('/v1/fleets/:id/workload/enroll', async (request, reply) => {
    const { id } = params.parse(request.params);
    const body = FleetEnrollmentInput.parse(request.body);
    const principal = await identity(id, request.headers.authorization);
    const enrolled = await services.fleet.enrollWorkload(id, principal, body);
    return reply.status(201).send(enrolled);
  });
}
