import { describe, it, expect } from 'vitest';
import { listIntents, INTENT_REGISTRY } from './index.js';
import { z } from 'zod';
import { defineIntent, INTENT_EFFECTS } from './types.js';
import { sampleParams } from './support/sample-params.js';
import { findFailingConstraint, isResolvablePath, normalizeRequest, resolvePath } from '../utils/constraints.js';
import { deriveRequestEmail } from '../utils/derived-email.js';
import type { ProxyRequestInput } from '../schemas/proxy.js';

// Every catalog intent declares what it can do at most: read, write, send or
// destructive. A policy rule that allows a `send` must bind the recipients
// (see utils/send-bounds.ts findUnboundSendRules), so an intent left
// unclassified, or classified as something milder than its HTTP method
// allows, would let an unbounded send through as a "write". This test is the
// gate: it fails CI on any unclassified intent and on any class that
// disagrees with the method the intent binds.

/**
 * POST (or other non-GET) endpoints that only read. Each provider exposes the
 * operation as a POST because the query does not fit in a URL (search,
 * GraphQL queries, JQL, Dropbox's RPC style, the AWS query API) or because
 * the provider is RPC-only (Telegram, Backblaze, Upstash commands).
 * Adding a name here is a claim that the call changes nothing; review it.
 */
const NON_GET_READS = new Set([
  'railway.read_project', 'monid.discover', 'monid.inspect', 'notion.query_database', 'notion.search',
  'google_sheets.get_by_data_filter', 'google_sheets.get_values_by_data_filter',
  'dropbox.list_folder', 'dropbox.list_folder_continue', 'dropbox.download_file', 'dropbox.get_metadata',
  'dropbox.search_files', 'dropbox.list_shared_links', 'dropbox.get_current_account', 'dropbox.list_team_members',
  'dropbox.list_revisions',
  'linear.read_only', 'linear.list_issue_comments', 'linear.list_teams', 'linear.list_users',
  'linear.list_workflow_states', 'linear.list_priorities', 'linear.list_integrations',
  'jira.search_issues', 'confluence.list_users', 'hubspot.search_contacts', 'hubspot.search_deals',
  'supabase.list_bucket_objects', 'outlook.search_messages', 'intercom.search_contacts',
  'telegram.get_chat', 'telegram.get_chat_member', 'telegram.get_updates', 'telegram.get_me',
  'datadog.query_logs', 'google_calendar.freebusy_query', 'google_analytics.check_compatibility',
  'mixpanel.query_jql', 'posthog.decide', 'posthog.query', 'paypal.verify_webhook_signature',
  'coinbase.preview_order', 'gumroad.verify_license', 'lemonsqueezy.validate_license',
  'tiktok.publish_status', 'tiktok.list_videos', 'tiktok.query_videos', 'tiktok.list_comments',
  'canva.export_design', 'upstash.redis_get', 'upstash.redis_scan',
  'aws.iam_list_users', 'aws.ec2_describe_instances', 'aws.dynamodb_get_item', 'aws.dynamodb_query', 'aws.dynamodb_scan',
  'backblaze.list_buckets', 'backblaze.get_upload_url', 'backblaze.list_file_names', 'backblaze.list_file_versions',
  'backblaze.download_file_by_id', 'backblaze.list_keys',
]);

/**
 * Provider-agnostic modifiers in custom.ts do not name an operation; their
 * class is the most they can admit. `custom.methods` and `custom.require_method`
 * depend on their params, so they take the worst case.
 */
const CUSTOM_EFFECTS: Record<string, string> = { 'custom.read_only': 'read' };

/** Providers whose main purpose is delivering messages to people. */
const MESSAGING = new Set(['slack', 'gmail', 'outlook', 'resend', 'agentmail', 'sendgrid', 'mailchimp', 'brevo',
  'intercom', 'zendesk', 'discord', 'twilio', 'ms_teams', 'telegram', 'whatsapp_business', 'twitter', 'linkedin',
  'reddit', 'youtube', 'instagram', 'tiktok']);
/** Action verbs that deliver content when they appear first in a messaging intent's name. */
const SEND_VERB = /^(send|post|reply|forward|publish|compose|submit|create_tweet|create_post|create_ugc_post|comment|execute_webhook|make_call)(_|$)/;
/** Messaging intents whose name starts with a send verb but deliver no content. */
const NOT_SEND = new Map([
  ['telegram.send_chat_action', 'typing indicator; carries no content'],
  ['tiktok.publish_status', 'reads the status of an earlier publish'],
]);

// A recipient path is only worth declaring if the constraint engine can read it: plain body fields, query keys, the URL
// path, array fan-out (`body.to[].email`, checked for every element) and the recipients decoded from a Gmail or
// Graph message (`derived.email.recipients`). `isResolvablePath` is the engine's own grammar, and the behavioural
// test below proves each declared path yields the value a request carries there.
const READ_METHODS = new Set(['GET', 'HEAD']);

function boundMethods(name: string): string[] | null | 'unexpandable' {
  const intent = INTENT_REGISTRY.get(name)!;
  const params = sampleParams(intent);
  if (!params) return 'unexpandable';
  const constraints = intent.expand(intent.params.parse(params));
  const method = constraints.find((c) => c.path === 'method');
  if (!method) return null;
  if (method.op === 'eq' && typeof method.value === 'string') return [method.value];
  if (method.op === 'in' && Array.isArray(method.value)) return method.value.map(String);
  return null; // not_in / matches: the set of admitted methods is open
}

describe('intent effect classification', () => {
  const intents = listIntents();

  it('classifies every catalog intent', () => {
    const unclassified = intents.filter((i) => !INTENT_EFFECTS.includes(i.effect)).map((i) => i.name);
    expect(unclassified).toEqual([]);
    expect(intents.length).toBe(INTENT_REGISTRY.size);
  });

  it('does not compile an intent without an effect', () => {
    // The `@ts-expect-error` is the check: remove `effect` from the type and the build fails here.
    // @ts-expect-error effect is required
    const unclassified = defineIntent({ name: 'x.y', description: 'd', params: z.object({}), expand: () => [] });
    expect(unclassified.name).toBe('x.y');
  });

  it('can expand every intent with sample params (add an override in support/sample-params.ts if not)', () => {
    const stuck = intents.filter((i) => boundMethods(i.name) === 'unexpandable').map((i) => i.name);
    expect(stuck).toEqual([]);
  });

  it('agrees with the HTTP methods each intent binds', () => {
    const problems: string[] = [];
    for (const intent of intents) {
      const methods = boundMethods(intent.name);
      if (methods === 'unexpandable') continue;
      const { name, effect } = intent;
      if (name.startsWith('custom.')) {
        const expected = CUSTOM_EFFECTS[name] ?? 'destructive';
        if (effect !== expected) problems.push(`${name}: custom modifier must be ${expected}, is ${effect}`);
        continue;
      }
      if (methods === null) {
        if (effect !== 'destructive' && effect !== 'send') problems.push(`${name}: any method is allowed, so it can delete; is ${effect}`);
        continue;
      }
      const onlyReads = methods.every((m) => READ_METHODS.has(m));
      if (onlyReads && effect !== 'read') problems.push(`${name}: binds only ${methods.join('/')} but is ${effect}`);
      if (!onlyReads && effect === 'read' && !NON_GET_READS.has(name)) {
        problems.push(`${name}: binds ${methods.join('/')} but is read (add to NON_GET_READS with a reason, or reclassify)`);
      }
      if (methods.length === 1 && methods[0] === 'DELETE' && effect !== 'destructive') problems.push(`${name}: DELETE must be destructive, is ${effect}`);
      if (methods.includes('DELETE') && effect !== 'destructive' && effect !== 'send') problems.push(`${name}: admits DELETE but is ${effect}`);
      if (effect === 'send' && !methods.some((m) => m === 'POST' || m === 'PUT' || m === 'PATCH')) problems.push(`${name}: send without a write method`);
    }
    expect(problems).toEqual([]);
  });

  it('classifies messaging, email, SMS and social posting as send', () => {
    const problems: string[] = [];
    for (const intent of intents) {
      const [provider, action] = intent.name.split('.') as [string, string];
      if (!MESSAGING.has(provider) || !SEND_VERB.test(action)) continue;
      if (NOT_SEND.has(intent.name)) {
        if (intent.effect === 'send') problems.push(`${intent.name}: listed as NOT_SEND but is send`);
        continue;
      }
      if (intent.effect !== 'send') problems.push(`${intent.name}: delivers content but is ${intent.effect}`);
    }
    expect(problems).toEqual([]);
  });

  it('declares recipient paths only on sends, in resolvable notation', () => {
    const problems: string[] = [];
    for (const intent of intents) {
      if (!intent.recipient_paths) continue;
      if (intent.effect !== 'send') problems.push(`${intent.name}: recipient_paths on a ${intent.effect}`);
      if (intent.recipient_paths.length === 0) problems.push(`${intent.name}: empty recipient_paths (omit it when recipients are implicit)`);
      if (new Set(intent.recipient_paths).size !== intent.recipient_paths.length) problems.push(`${intent.name}: duplicate recipient path`);
      for (const path of intent.recipient_paths) if (!isResolvablePath(path)) problems.push(`${intent.name}: bad recipient path ${path}`);
    }
    expect(problems).toEqual([]);
  });

  /** A request for a send intent that carries `value` at `path`, or null for a path that needs its own request. */
  function requestCarrying(path: string, value: string): Pick<ProxyRequestInput, 'body' | 'query' | 'url'> | null {
    const base = 'https://example.test';
    if (path === 'url.pathname') return { url: `${base}${value}`, body: undefined, query: undefined };
    if (path.startsWith('query.')) return { url: `${base}/x`, body: undefined, query: { [path.slice(6)]: value } };
    if (path.startsWith('derived.')) return null;
    const rest = path.startsWith('body[].') ? ['[]', ...path.slice(7).split('.')] : path.slice(5).split('.');
    let node: unknown = value;
    for (const segment of rest.reverse()) {
      const fan = segment.endsWith('[]');
      const key = fan ? segment.slice(0, -2) : segment;
      node = key === '' ? [node] : { [key]: fan ? [node] : node };
    }
    return { url: `${base}/x`, body: node, query: undefined };
  }

  it('declares only recipient paths the engine reads the recipient from', () => {
    const problems: string[] = [];
    for (const intent of intents) {
      for (const path of intent.recipient_paths ?? []) {
        const carried = requestCarrying(path, path === 'url.pathname' ? '/sentinel' : 'sentinel@x.test');
        if (!carried) continue; // derived: covered by the endpoint table below
        const req = normalizeRequest({ service: 'x', method: 'POST', headers: {}, ...carried } as ProxyRequestInput);
        const got = resolvePath(req, path);
        const flat = Array.isArray(got) ? got : [got];
        const want = path === 'url.pathname' ? '/sentinel' : 'sentinel@x.test';
        if (!flat.includes(want)) problems.push(`${intent.name}: ${path} does not read the recipient a request carries there`);
      }
    }
    expect(problems).toEqual([]);
  });

  // `derived.email.recipients` is read from an encoded message, so an intent may declare it only for an endpoint whose
  // request carries the message. This table is the proof: each intent maps to a request on its own bound endpoint, and
  // the engine must read the recipient out of it. An intent whose request carries no recipients (a stored draft sent by
  // id, a reply) cannot be pinned and declares none.
  const mime = (to: string) => Buffer.from(`To: ${to}\r\nSubject: s\r\n\r\nhi`, 'utf8');
  const graphMessage = { toRecipients: [{ emailAddress: { address: 'sentinel@x.test' } }] };
  const READABLE_EMAIL: Record<string, { method: string; url: string; body: unknown }> = {
    'gmail.send_email': { method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', body: { raw: mime('sentinel@x.test').toString('base64url') } },
    'gmail.send_email_to': { method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', body: { raw: mime('sentinel@x.test').toString('base64url') } },
    'outlook.send_mail': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/sendMail', body: { message: graphMessage } },
    'outlook.send_mail_to': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/sendMail', body: { message: graphMessage } },
    'outlook.send_mail_to_domain': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/sendMail', body: { message: graphMessage } },
    'outlook.forward_message': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/messages/AAA/forward', body: graphMessage },
  };
  const UNREADABLE_EMAIL: Record<string, { method: string; url: string; body: unknown }> = {
    'gmail.send_draft': { method: 'POST', url: 'https://gmail.googleapis.com/gmail/v1/users/me/drafts/send', body: { id: 'r1' } },
    'outlook.send_draft': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/messages/AAA/send', body: {} },
    'outlook.reply_message': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/messages/AAA/reply', body: { comment: 'hi' } },
    'outlook.reply_all_message': { method: 'POST', url: 'https://graph.microsoft.com/v1.0/me/messages/AAA/replyAll', body: { comment: 'hi' } },
  };

  it('declares derived.email.recipients only where the engine decodes the message', () => {
    const declaring = intents.filter((i) => i.recipient_paths?.some((p) => p.startsWith('derived.'))).map((i) => i.name).sort();
    expect(declaring).toEqual(Object.keys(READABLE_EMAIL).sort());
    for (const [name, request] of Object.entries(READABLE_EMAIL)) {
      const intent = INTENT_REGISTRY.get(name)!;
      expect(intent.recipient_paths, name).toEqual(['derived.email.recipients']);
      const req = normalizeRequest({ service: 'x', headers: {}, ...request } as ProxyRequestInput);
      expect(resolvePath(req, 'derived.email.recipients'), name).toEqual(['sentinel@x.test']);
      // The request really is on the endpoint the intent binds.
      const binding = intent.expand(intent.params.parse(sampleParams(intent))).filter((c) => c.path === 'method' || c.path === 'url.pathname');
      expect(findFailingConstraint(binding, req), name).toBeNull();
    }
  });

  it('declares no recipient path where the request carries no recipients', () => {
    for (const [name, request] of Object.entries(UNREADABLE_EMAIL)) {
      const intent = INTENT_REGISTRY.get(name)!;
      expect(intent.effect, name).toBe('send');
      expect(intent.recipient_paths, name).toBeUndefined();
      const req = normalizeRequest({ service: 'x', headers: {}, ...request } as ProxyRequestInput);
      expect(deriveRequestEmail(req), name).toBeUndefined();
      const binding = intent.expand(intent.params.parse(sampleParams(intent))).filter((c) => c.path === 'method' || c.path === 'url.pathname');
      expect(findFailingConstraint(binding, req), name).toBeNull();
    }
  });

  it('names the recipient fields of the main send intents', () => {
    const paths = (name: string) => INTENT_REGISTRY.get(name)?.recipient_paths;
    expect(paths('slack.post_to_channel')).toEqual(['body.channel']);
    expect(paths('slack.upload_file')).toEqual(['body.channel', 'body.channels']);
    expect(paths('resend.send_email')).toEqual(['body.to', 'body.cc', 'body.bcc']);
    expect(paths('twilio.send_sms')).toEqual(['body.To']);
    // Recipients inside a base64 message, or inside an array of objects, are read by the engine per element.
    expect(paths('gmail.send_email')).toEqual(['derived.email.recipients']);
    expect(paths('gmail.send_email_to')).toEqual(['derived.email.recipients']);
    expect(paths('outlook.send_mail')).toEqual(['derived.email.recipients']);
    expect(paths('outlook.create_rule')).toEqual(['body.actions.forwardTo[].emailAddress.address', 'body.actions.redirectTo[].emailAddress.address', 'body.actions.forwardAsAttachmentTo[].emailAddress.address']);
    const sendgrid = ['body.personalizations[].to[].email', 'body.personalizations[].cc[].email', 'body.personalizations[].bcc[].email', 'body.mail_settings.bcc.email'];
    for (const name of ['sendgrid.send_mail', 'sendgrid.send_mail_from', 'sendgrid.send_mail_from_domain', 'sendgrid.send_mail_to']) expect(paths(name)).toEqual(sendgrid);
    const brevo = ['body.to[].email', 'body.cc[].email', 'body.bcc[].email', 'body.messageVersions[].to[].email', 'body.messageVersions[].cc[].email', 'body.messageVersions[].bcc[].email'];
    for (const name of ['brevo.send_transactional_email', 'brevo.send_transactional_email_from', 'brevo.send_transactional_email_from_domain', 'brevo.send_transactional_email_to']) expect(paths(name)).toEqual(brevo);
    for (const name of ['google_calendar.create_event', 'google_calendar.update_event', 'google_calendar.patch_event']) expect(paths(name)).toEqual(['body.attendees[].email']);
    expect(paths('zendesk.create_side_conversation')).toEqual(['body.message.to[].email']);
    // A stored draft sent by id and a reply name no recipient in the request, so they stay review-only.
    for (const name of ['gmail.send_draft', 'outlook.send_draft', 'outlook.reply_message', 'outlook.reply_all_message']) {
      expect(paths(name)).toBeUndefined();
      expect(INTENT_REGISTRY.get(name)?.effect).toBe('send');
    }
    expect(paths('discord.send_channel_message')).toEqual(['url.pathname']);
    // Implicit recipients: a reply, a public post. These can only be reviewed.
    expect(paths('twitter.create_tweet')).toBeUndefined();
    expect(INTENT_REGISTRY.get('twitter.create_tweet')?.effect).toBe('send');
  });

  it('classifies the account Monid intents: paid runs write, catalogue and wallet reads read, none send', () => {
    const effects = Object.fromEntries(intents.filter(i => i.name.startsWith('monid.')).map(i => [i.name, i.effect]));
    expect(effects).toEqual({
      'monid.whoami': 'read',
      'monid.discover': 'read',
      'monid.inspect': 'read',
      'monid.run': 'write',
      'monid.run_endpoint': 'write',
      'monid.list_runs': 'read',
      'monid.get_run': 'read',
      'monid.stop_run': 'write',
      'monid.wallet_balance': 'read',
      'monid.wallet_activities': 'read',
    });
  });

  it('reports the classification totals', () => {
    const counts: Record<string, number> = {};
    for (const intent of intents) counts[intent.effect] = (counts[intent.effect] ?? 0) + 1;
    console.log(`[intent-effects] ${JSON.stringify(counts)}`);
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(intents.length);
  });
});
