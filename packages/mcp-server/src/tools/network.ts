import { z } from 'zod';
import {
  Base64Url256Schema,
  CreateNetworkSubscriptionInput,
  InstallIdSchema,
  InstallKeyIdSchema,
  NetworkSubscriptionIdSchema,
  PublishRevocationInput,
  RegisterInstallInput,
  RevokeNetworkInput,
  VerifyCountersignatureInput,
} from '@stack/shared';
import type { ToolContext, ToolRegistrar } from './context.js';
import { toolJson } from './shared.js';
import { hint, type StackToolAnnotation } from '../tool-annotations.js';

// The STACK network: self-hosted installs, revocation across companies, and the
// checks a counterparty runs. These are the owner's and the counterparty's tools.
// An install itself signs its requests with its own key and is not an MCP client.
//
// Registering a KEY is deliberately not a tool: it needs the install's private
// key to sign a proof, and a chat must never hold a private key. Use the CLI
// (`network install key add`) or an SDK. The key challenge is not exposed either.
const KEY_NOTE = 'Registering a key for an install is not available here: it needs the install private key, which a chat never holds. Use the CLI (network install key add) or an SDK. Revoking a licence key is not available here either: it needs the key itself, a secret a chat should not hold. Use the CLI (network licence revoke) or an SDK.';

/** The title and hints of each tool in this group (the classification rule is in tool-annotations.ts). */
export const NETWORK_ANNOTATIONS: Readonly<Record<string, StackToolAnnotation>> = {
  // The STACK network: the owner's installs and revocations, and the checks a
  // counterparty runs. Subscriptions make STACK post to an address outside the
  // account, so they are open-world; the two checks only read what STACK signed.
  stack_list_network_installs: hint.read('List network installs'),
  stack_get_network_install: hint.read('Get network install'),
  stack_register_network_install: hint.write('Register network install'),
  stack_revoke_network_install_key: hint.destructive('Revoke network install key'),
  stack_revoke_network_install: hint.destructive('Revoke network install'),
  stack_publish_network_revocation: hint.destructive('Publish network revocation'),
  stack_list_network_subscriptions: hint.read('List network subscriptions'),
  stack_create_network_subscription: hint.write('Create network subscription', true),
  stack_delete_network_subscription: hint.destructive('Delete network subscription'),
  stack_resume_network_subscription: hint.write('Resume network subscription', true),
  stack_verify_countersignature: hint.read('Verify countersignature'),
  stack_get_verified_status: hint.read('Get STACK-verified status'),
};

/** The tools of this group the directory profile leaves out, each with its reason. */
export const NETWORK_DIRECTORY_EXCLUDED: Readonly<Record<string, string>> = {
  // The control socket moves where the account's agents' actions are decided
  // and where their record is sent. Its scope (accounts:manage) is withheld
  // from directory tokens.
  stack_list_network_installs: 'Needs accounts:manage, withheld from directory tokens: it lists the self-hosted installs allowed to have passports countersigned in the account\'s name.',
  stack_get_network_install: 'Needs accounts:manage, withheld from directory tokens: it shows one self-hosted install and its keys.',
  stack_register_network_install: 'Needs accounts:manage, withheld from directory tokens: it adds a self-hosted install that can later be given a key.',
  stack_revoke_network_install_key: 'Needs accounts:manage, withheld from directory tokens: it stops a key and publishes the revocation to other companies.',
  stack_revoke_network_install: 'Needs accounts:manage, withheld from directory tokens: it stops an install and publishes the revocation to other companies.',
  stack_publish_network_revocation: 'Needs accounts:manage, withheld from directory tokens: it publishes a revocation to other companies.',
  stack_list_network_subscriptions: 'Needs accounts:manage, withheld from directory tokens: it shows where STACK posts cross-company revocations.',
  stack_create_network_subscription: 'Needs accounts:manage, withheld from directory tokens: it makes STACK post to an address outside the account.',
  stack_delete_network_subscription: 'Needs accounts:manage, withheld from directory tokens: it removes a revocation subscription.',
  stack_resume_network_subscription: 'Needs accounts:manage, withheld from directory tokens: it makes STACK post to an address outside the account again.',
  stack_verify_countersignature: 'A public check that needs no OAuth scope; kept off the directory with the rest of the network tools, which are for operators building agent infrastructure.',
  stack_get_verified_status: 'A public check that needs no OAuth scope; kept off the directory with the rest of the network tools, which are for operators building agent infrastructure.',
};

/**
 * Installs, revocations and subscriptions: operator only. An agent context is
 * refused, so an agent cannot register, widen or remove its own way of being
 * vouched for. The two checks at the end read what STACK has signed and need no
 * special rights.
 */
export function registerNetworkTools(server: ToolRegistrar, ctx: ToolContext): void {
  const { api } = ctx;

  server.tool(
    'stack_list_network_installs',
    `List the self-hosted installs registered to the account, each with its keys: id, name, status (active or revoked), created_at, and for each key id, kid (its thumbprint), status, usable, valid_until and revoked_reason. Operator only. ${KEY_NOTE}`,
    {},
    async () => toolJson(await api('GET', '/v1/network/installs')),
  );

  server.tool(
    'stack_get_network_install',
    'Get one self-hosted install and its keys. Operator only.',
    { install_id: InstallIdSchema.describe('Install id (ins_*) from stack_list_network_installs') },
    async ({ install_id }) => toolJson(await api('GET', `/v1/network/installs/${encodeURIComponent(install_id)}`)),
  );

  server.tool(
    'stack_register_network_install',
    `Register a self-hosted install by name. It can sign nothing until it has a key, and a key cannot be registered from a chat. Operator only. ${KEY_NOTE} Returns the install.`,
    { name: RegisterInstallInput.shape.name.describe('A name for the install, e.g. the site or team that runs it') },
    async ({ name }) => toolJson(await api('POST', '/v1/network/installs', { name })),
  );

  server.tool(
    'stack_revoke_network_install_key',
    'Stop one key of an install at once. Its signed requests are refused from the next call, every countersignature made under it stops being live, and the revocation is published for counterparties. Never needs approval and is never charged. Operator only. Returns the install.',
    {
      install_id: InstallIdSchema.describe('Install id (ins_*)'),
      key_id: InstallKeyIdSchema.describe('Key id (ink_*) from the install'),
      reason: RevokeNetworkInput.shape.reason.describe('Why, from a fixed list (for example key_compromise); it appears on the public list'),
    },
    async ({ install_id, key_id, reason }) =>
      toolJson(await api('POST', `/v1/network/installs/${encodeURIComponent(install_id)}/keys/${encodeURIComponent(key_id)}/revoke`, reason ? { reason } : {})),
  );

  server.tool(
    'stack_revoke_network_install',
    'Stop an install and all its keys at once and publish it for counterparties. Every countersignature the install made stops being live. Never needs approval and is never charged. Operator only. Returns the install.',
    {
      install_id: InstallIdSchema.describe('Install id (ins_*)'),
      reason: RevokeNetworkInput.shape.reason.describe('Why, from a fixed list (for example key_compromise); it appears on the public list'),
    },
    async ({ install_id, reason }) =>
      toolJson(await api('POST', `/v1/network/installs/${encodeURIComponent(install_id)}/revoke`, reason ? { reason } : {})),
  );

  server.tool(
    'stack_publish_network_revocation',
    'Publish a revocation across companies: a passport (subject: its digest), an agent (subject: its id), a key (subject: its thumbprint) or an install (subject: its id). Every revocation names the install it belongs to (install is required), and the subject must belong to it: an install is itself, a key one of its keys, a passport one STACK countersigned for it, an agent whose name STACK countersigned for it; anything else is not found. It appears, with its reason, on the public signed list counterparties read and is delivered to those subscribed. It only ever affects what is yours. Never needs approval and is never charged. Operator only. Returns the revocation.',
    {
      kind: PublishRevocationInput.shape.kind.describe('passport, agent, key or install'),
      subject: PublishRevocationInput.shape.subject.describe('A passport digest, an agent id, a key thumbprint or an install id'),
      install: PublishRevocationInput.shape.install.describe('The install the subject belongs to (ins_*), required'),
      reason: PublishRevocationInput.shape.reason.describe('Why, from a fixed list; it appears on the public list'),
    },
    async (input) => toolJson(await api('POST', '/v1/network/revocations', input)),
  );

  server.tool(
    'stack_list_network_subscriptions',
    'List the addresses STACK posts each new cross-company revocation to for this account: id, url, installs followed (null for all), status (active, failing or paused), last_delivered_seq and last_error. Operator only.',
    {},
    async () => toolJson(await api('GET', '/v1/network/subscriptions')),
  );

  server.tool(
    'stack_create_network_subscription',
    'Have STACK post each new revocation to an https address, in order and at least once, as a list signed with STACK\'s key, in a request signed as a Standard Webhooks message with the subscription\'s own secret (spec/webhooks/SPEC.md). The signing secret is not returned through MCP: an owner or admin gets one with POST /v1/network/subscriptions/{id}/rotate-secret through the REST API, the SDK or the CLI. Optionally follow only some installs. Operator only. Returns the subscription.',
    {
      url: CreateNetworkSubscriptionInput.shape.url.describe('An https address STACK can reach from the internet'),
      installs: CreateNetworkSubscriptionInput.shape.installs.describe('Follow only these installs (ins_*); omit to follow every revocation'),
    },
    async (input) => {
      const result = (await api('POST', '/v1/network/subscriptions', input)) as Record<string, unknown>;
      // The REST response carries the signing secret once. It never enters the assistant conversation.
      const { signing_secret: secret, signing_secret_note: _note, ...subscription } = result;
      return toolJson({
        ...subscription,
        signing_secret_returned: false,
        ...(typeof secret === 'string' && secret.length > 0 ? { signing_secret_hint: `…${secret.slice(-4)}` } : {}),
        signing_secret_access: 'The signing secret is not returned through MCP. An owner or admin obtains a new one with POST /v1/network/subscriptions/{id}/rotate-secret through the REST API, the SDK or the CLI.',
      });
    },
  );

  server.tool(
    'stack_delete_network_subscription',
    'Remove a subscription; nothing more is posted to its address. Operator only.',
    { subscription_id: NetworkSubscriptionIdSchema.describe('Subscription id (nsub_*)') },
    async ({ subscription_id }) =>
      toolJson(await api('DELETE', `/v1/network/subscriptions/${encodeURIComponent(subscription_id)}`)),
  );

  server.tool(
    'stack_resume_network_subscription',
    'Put a paused or failing subscription back to work; it is sent what it missed, in order. Operator only. Returns the subscription.',
    { subscription_id: NetworkSubscriptionIdSchema.describe('Subscription id (nsub_*)') },
    async ({ subscription_id }) =>
      toolJson(await api('POST', `/v1/network/subscriptions/${encodeURIComponent(subscription_id)}/resume`, {})),
  );

  server.tool(
    'stack_verify_countersignature',
    'Check a countersignature STACK made over another company\'s passport, now, with revocation: STACK\'s signature and expiry, whether the key, the install, the agent or this passport has been revoked, and, when the passport is given, that it is the passport the countersignature covers and that the install signed it. Returns valid, reasons (short codes when not valid), install, owner, passport_digest, countersignature_expires_at and revoked. A valid answer means STACK saw this install\'s key proved by its holder and this passport\'s digest; it says nothing about what the agent will do. Needs no special rights.',
    {
      countersignature: VerifyCountersignatureInput.shape.countersignature.describe('The countersignature, a compact signed token'),
      passport: VerifyCountersignatureInput.shape.passport.describe('The passport the countersignature is about, a compact signed token'),
    },
    async (input) => toolJson(await api('POST', '/v1/network/verify', input)),
  );

  server.tool(
    'stack_get_verified_status',
    'Get STACK\'s signed "STACK-verified" statement for a passport (by its digest) or for an install\'s agent: status live, expired or revoked, and the statement itself (a signed token valid for five minutes). Only a live statement earns the STACK-verified mark; show nothing older than the statement. Not found when STACK never countersigned it. Give passport_digest, or install and agent together. Needs no special rights.',
    {
      passport_digest: Base64Url256Schema.optional().describe("The passport's digest: base64url SHA-256 of the passport token"),
      install: InstallIdSchema.optional().describe('The install id (ins_*), with agent'),
      agent: z.string().min(1).max(128).optional().describe('The agent id within the install, with install'),
    },
    async ({ passport_digest, install, agent }) => {
      const params = new URLSearchParams();
      if (passport_digest) params.set('passport_digest', passport_digest);
      if (install) params.set('install', install);
      if (agent) params.set('agent', agent);
      return toolJson(await api('GET', `/v1/network/verified?${params.toString()}`));
    },
  );
}
