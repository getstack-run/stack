import { describe, expect, it, vi } from 'vitest';
import { InvalidRequestError, NotFoundError } from '@stack/shared';
import { EngineRegistries } from '../config/registries.js';
import { OpenBody, missionOpenInput, missionRecipientPins, recipientPinsHash } from './missions.js';

const open = (extra: Record<string, unknown> = {}) => OpenBody.parse({ intent_summary: 'Reply to a customer', ...extra });

function services(resolve?: (input: { operatorId: string; agentId: string; messageId: string }) => Promise<{ recipients: string[] } | null>) {
  const registries = new EngineRegistries();
  if (resolve) registries.messageSenders.register(resolve);
  return { registries };
}

describe('the recipients a Mission opens with', () => {
  it('has none unless the caller names them', async () => {
    expect(await missionRecipientPins(services(), 'op_a', 'agt_a', open())).toBeNull();
    expect(missionOpenInput('op_a', open(), 'agt_a', null)).not.toHaveProperty('recipient_pins');
  });

  it('pins the list it was given at every recipient field, an address in either case', async () => {
    const pins = await missionRecipientPins(services(), 'op_a', 'agt_a', open({ recipients: ['Ana@Example.com', '+14155550123'] }));
    expect(pins).toEqual([{ path: '*', op: 'in', value: ['Ana@Example.com', 'ana@example.com', '+14155550123'] }]);
    expect(missionOpenInput('op_a', open(), 'agt_a', pins)).toMatchObject({ recipient_pins: pins });
  });

  it('keeps named fields pinned beside the list, one pin per field', async () => {
    const pins = await missionRecipientPins(services(), 'op_a', undefined, open({
      recipients: ['ana@example.com'],
      recipient_pins: [{ path: 'url.pathname', op: 'eq', value: '/api/v10/channels/123/messages' }],
    }));
    expect(pins?.map((pin) => pin.path)).toEqual(['*', 'url.pathname']);
    await expect(missionRecipientPins(services(), 'op_a', undefined, open({
      recipients: ['ana@example.com'], recipient_pins: [{ path: '*', op: 'eq', value: 'b@example.com' }],
    }))).rejects.toThrow(InvalidRequestError);
  });

  it('refuses a pin that is not a recipient field, a list for eq and a value for in', () => {
    expect(() => open({ recipient_pins: [{ path: 'secret', op: 'eq', value: 'x' }] })).toThrow();
    expect(() => open({ recipient_pins: [{ path: 'body.to', op: 'eq', value: ['a@x.com'] }] })).toThrow();
    expect(() => open({ recipient_pins: [{ path: 'body.to', op: 'in', value: 'a@x.com' }] })).toThrow();
    expect(() => open({ recipient_pins: [{ path: 'body.to', op: 'matches', value: '.*' }] })).toThrow();
    expect(() => open({ recipient_pins: [{ path: 'body.to', op: 'eq', value: 'a@x.com' }, { path: 'body.to', op: 'in', value: ['b@x.com'] }] })).toThrow();
    expect(() => open({ recipients: [] })).toThrow();
  });

  it('pins a Mission that replies to a message to the sender, in one call, together with a list', async () => {
    const resolve = vi.fn(async () => ({ recipients: ['dana@millbrook.example'] }));
    const pins = await missionRecipientPins(services(resolve), 'op_a', 'agt_a', open({ reply_to_message: 'amsg_1', recipients: ['boss@millbrook.example', 'DANA@millbrook.example'] }));
    expect(resolve).toHaveBeenCalledWith({ operatorId: 'op_a', agentId: 'agt_a', messageId: 'amsg_1' });
    // The sender already listed in another case is one entry, not two.
    expect(pins).toEqual([{ path: '*', op: 'in', value: ['boss@millbrook.example', 'DANA@millbrook.example', 'dana@millbrook.example'] }]);
  });

  it('reads a message the agent cannot reply to as not found, and a deployment with no messages the same', async () => {
    await expect(missionRecipientPins(services(async () => null), 'op_a', 'agt_a', open({ reply_to_message: 'amsg_x' }))).rejects.toThrow(NotFoundError);
    await expect(missionRecipientPins(services(), 'op_a', 'agt_a', open({ reply_to_message: 'amsg_x' }))).rejects.toThrow(NotFoundError);
    await expect(missionRecipientPins(services(async () => ({ recipients: [] })), 'op_a', 'agt_a', open({ reply_to_message: 'amsg_x' }))).rejects.toThrow(NotFoundError);
  });

  it('asks the first resolver that knows the message', async () => {
    const registries = new EngineRegistries();
    registries.messageSenders.register(async () => null);
    registries.messageSenders.register(async () => ({ recipients: ['+14155550123'] }));
    expect(await missionRecipientPins({ registries }, 'op_a', 'agt_a', open({ reply_to_message: 'amsg_2' }))).toEqual([{ path: '*', op: 'in', value: ['+14155550123'] }]);
  });

  it('needs the agent it is for, since a message is an agent\'s', async () => {
    await expect(missionRecipientPins(services(async () => ({ recipients: ['a@x.com'] })), 'op_a', undefined, open({ reply_to_message: 'amsg_1' }))).rejects.toThrow(InvalidRequestError);
  });

  it('records what it was opened to send to as a hash, never the addresses', async () => {
    const pins = await missionRecipientPins(services(), 'op_a', 'agt_a', open({ recipients: ['ana@example.com'] }));
    const hash = recipientPinsHash(pins);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toContain('ana');
    expect(recipientPinsHash(null)).toBeUndefined();
  });
});
