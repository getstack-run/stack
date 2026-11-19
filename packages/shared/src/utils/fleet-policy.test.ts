import { describe, expect, it } from 'vitest';
import { FleetAccess, FleetPolicyInput } from '../schemas/fleet.js';
import { assertFleetLimitsNarrow, fleetAccessNarrows, fleetDigest, resolveFleetAccess } from './fleet-policy.js';

const access = (channel: string | string[]) => FleetAccess.parse({ connection_id: 'scon_slack', scopes: ['chat:write'], intents: [{ name: 'slack.post_to_channel', params: { channel } }] });
const limits = { max_actions: 20, max_concurrent_actions: 4, max_duration_seconds: 900 };
const policy = FleetPolicyInput.parse({ name: 'Support', rules: [{ id: 'post', effect: 'allow', access: access(['C123', 'C456']) }], limits, window_seconds: 3600, max_members: 100, max_enrollments_per_hour: 100, identity_lease_seconds: 3600, provisioner_agent_ids: ['agt_controller'], expires_at: '2030-01-01T00:00:00Z' });

describe('fleet authority resolution', () => {
  it('narrows channel allowlists into a specific Mission target', () => {
    const result = resolveFleetAccess(policy, [access('C123')]);
    expect(result[0]?.constraints).toContainEqual({ path: 'body.channel', op: 'eq', value: 'C123' });
    expect(result[0]?.effect).toBe('allow');
  });
  it('rejects a foreign channel, connection, scope or incoming data source without dropping it', () => {
    for (const entry of [access('C789'), { ...access('C123'), connection_id: 'scon_other' }, { ...access('C123'), scopes: ['chat:write', 'admin'] }, { ...access('C123'), allow_data_from: ['secret'] }]) {
      expect(() => resolveFleetAccess(policy, [entry])).toThrow();
    }
  });
  it('does not authorize another action on the permitted channel', () => {
    const deletion = { ...access('C123'), intents: [{ name: 'slack.delete_message', params: { channel: 'C123' } }] };
    // Unknown intent names also fail closed before a Passport is created.
    expect(() => resolveFleetAccess(policy, [deletion])).toThrow();
  });
  it('preserves explicit review and deny precedence', () => {
    const review = { ...policy, rules: [...policy.rules, { id: 'review', effect: 'review' as const, access: access('C123') }] };
    expect(resolveFleetAccess(review, [access('C123')])[0]?.effect).toBe('review');
    expect(() => resolveFleetAccess({ ...review, rules: [...review.rules, { id: 'deny', effect: 'deny', access: access('C123') }] }, [access('C123')])).toThrow();
  });
  it('rejects broader or missing bounded limits', () => {
    expect(() => assertFleetLimitsNarrow({ ...limits, max_actions: 21 }, limits)).toThrow();
    expect(() => assertFleetLimitsNarrow(limits, { ...limits, max_spend_cents: 100 })).toThrow();
    expect(() => assertFleetLimitsNarrow({ ...limits, max_actions: 10 }, limits)).not.toThrow();
  });
  it('will not prove arbitrary regex implication or silently remove a constraint', () => {
    expect(fleetAccessNarrows({ ...access('C123'), intents: [] }, access('C123'))).toBe(false);
  });
  it('binds canonical payload identity while preserving array ordering', () => {
    expect(fleetDigest({ b: 2, a: 1 })).toBe(fleetDigest({ a: 1, b: 2 }));
    expect(fleetDigest(['a', 'b'])).not.toBe(fleetDigest(['b', 'a']));
  });
});
