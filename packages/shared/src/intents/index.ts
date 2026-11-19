import { ANY_OF_BUDGET_MESSAGE, ANY_OF_MAX_LEAVES, withinAnyOfBudget, type Constraint, type PlainConstraint } from '../schemas/passport.js';
import { InvalidRequestError } from '../errors/index.js';
import type { Intent, IntentRef } from './types.js';

// Seven provider files existed on disk but were never imported here, so
// every intent in them threw UnknownIntentError at expandIntents. 108
// intents across bitbucket / fly_io / gitlab / netlify / railway / render /
// vercel. The "2,199 intents" figure counted files; the registry held 2,090.
import { bitbucketIntents } from './bitbucket.js';
import { flyIoIntents } from './fly_io.js';
import { gitlabIntents } from './gitlab.js';
import { netlifyIntents } from './netlify.js';
import { railwayIntents } from './railway.js';
import { renderIntents } from './render.js';
import { vercelIntents } from './vercel.js';
import { slackIntents } from './slack.js';
import { githubIntents } from './github.js';
import { notionIntents } from './notion.js';
import { gmailIntents } from './gmail.js';
import { googleDriveIntents } from './google_drive.js';
import { googleDocsIntents } from './google_docs.js';
import { googleSheetsIntents } from './google_sheets.js';
import { dropboxIntents } from './dropbox.js';
import { boxIntents } from './box.js';
import { airtableIntents } from './airtable.js';
import { linearIntents } from './linear.js';
import { jiraIntents } from './jira.js';
import { asanaIntents } from './asana.js';
import { clickupIntents } from './clickup.js';
import { basecampIntents } from './basecamp.js';
import { trelloIntents } from './trello.js';
import { shortcutIntents } from './shortcut.js';
import { confluenceIntents } from './confluence.js';
import { hubspotIntents } from './hubspot.js';
import { salesforceIntents } from './salesforce.js';
import { gustoIntents } from './gusto.js';
import { bamboohrIntents } from './bamboohr.js';
import { stripeIntents } from './stripe.js';
import { openaiIntents } from './openai.js';
import { supabaseIntents } from './supabase.js';
import { outlookIntents } from './outlook.js';
import { resendIntents } from './resend.js';
import { agentmailIntents } from './agentmail.js';
import { monidIntents } from './monid.js';
import { sendgridIntents } from './sendgrid.js';
import { mailchimpIntents } from './mailchimp.js';
import { brevoIntents } from './brevo.js';
import { intercomIntents } from './intercom.js';
import { zendeskIntents } from './zendesk.js';
import { discordIntents } from './discord.js';
import { twilioIntents } from './twilio.js';
import { zoomIntents } from './zoom.js';
import { loomIntents } from './loom.js';
import { msTeamsIntents } from './ms_teams.js';
import { telegramIntents } from './telegram.js';
import { whatsappBusinessIntents } from './whatsapp_business.js';
import { cloudflareIntents } from './cloudflare.js';
import { digitaloceanIntents } from './digitalocean.js';
import { hetznerIntents } from './hetzner.js';
import { linodeIntents } from './linode.js';
import { sentryIntents } from './sentry.js';
import { datadogIntents } from './datadog.js';
import { newRelicIntents } from './new_relic.js';
import { pagerdutyIntents } from './pagerduty.js';
import { grafanaIntents } from './grafana.js';
import { snykIntents } from './snyk.js';
import { googleCalendarIntents } from './google_calendar.js';
import { calendlyIntents } from './calendly.js';
import { calComIntents } from './cal_com.js';
import { auth0Intents } from './auth0.js';
import { clerkIntents } from './clerk.js';
import { oktaIntents } from './okta.js';
import { twitterIntents } from './twitter.js';
import { linkedinIntents } from './linkedin.js';
import { redditIntents } from './reddit.js';
import { youtubeIntents } from './youtube.js';
import { anthropicIntents } from './anthropic.js';
import { replicateIntents } from './replicate.js';
import { huggingFaceIntents } from './hugging_face.js';
import { mistralIntents } from './mistral.js';
import { qdrantIntents } from './qdrant.js';
import { langsmithIntents } from './langsmith.js';
import { googleAnalyticsIntents } from './google_analytics.js';
import { mixpanelIntents } from './mixpanel.js';
import { amplitudeIntents } from './amplitude.js';
import { posthogIntents } from './posthog.js';
import { hotjarIntents } from './hotjar.js';
import { plausibleIntents } from './plausible.js';
import { quickbooksIntents } from './quickbooks.js';
import { xeroIntents } from './xero.js';
import { paypalIntents } from './paypal.js';
import { squareIntents } from './square.js';
import { brexIntents } from './brex.js';
import { wiseIntents } from './wise.js';
import { coinbaseIntents } from './coinbase.js';
import { shopifyIntents } from './shopify.js';
import { bigcommerceIntents } from './bigcommerce.js';
import { gumroadIntents } from './gumroad.js';
import { lemonsqueezyIntents } from './lemonsqueezy.js';
import { woocommerceIntents } from './woocommerce.js';
import { instagramIntents } from './instagram.js';
import { tiktokIntents } from './tiktok.js';
import { spotifyIntents } from './spotify.js';
import { figmaIntents } from './figma.js';
import { canvaIntents } from './canva.js';
import { contentfulIntents } from './contentful.js';
import { sanityIntents } from './sanity.js';
import { strapiIntents } from './strapi.js';
import { webflowIntents } from './webflow.js';
import { wordpressIntents } from './wordpress.js';
import { typeformIntents } from './typeform.js';
import { neonIntents } from './neon.js';
import { planetscaleIntents } from './planetscale.js';
import { upstashIntents } from './upstash.js';
import { awsS3Intents } from './aws_s3.js';
import { awsIntents } from './aws.js';
import { gcpIntents } from './gcp.js';
import { azureIntents } from './azure.js';
import { r2Intents } from './r2.js';
import { backblazeIntents } from './backblaze.js';
import { mongodbAtlasIntents } from './mongodb_atlas.js';
import { tursoIntents } from './turso.js';
import { wasabiIntents } from './wasabi.js';
import { customIntents } from './custom.js';

export * from './types.js';

// Flat registry — every intent in the v1 library, keyed by its fully
// qualified name (e.g. "slack.post_to_channel"). Order is stable so
// docs / MCP tool listings read consistently.
const ALL_INTENTS: Intent[] = [
  ...bitbucketIntents,
  ...flyIoIntents,
  ...gitlabIntents,
  ...netlifyIntents,
  ...railwayIntents,
  ...renderIntents,
  ...vercelIntents,
  ...slackIntents,
  ...githubIntents,
  ...notionIntents,
  ...gmailIntents,
  ...googleDriveIntents,
  ...googleDocsIntents,
  ...googleSheetsIntents,
  ...dropboxIntents,
  ...boxIntents,
  ...airtableIntents,
  ...linearIntents,
  ...jiraIntents,
  ...asanaIntents,
  ...clickupIntents,
  ...basecampIntents,
  ...trelloIntents,
  ...shortcutIntents,
  ...confluenceIntents,
  ...hubspotIntents,
  ...salesforceIntents,
  ...gustoIntents,
  ...bamboohrIntents,
  ...stripeIntents,
  ...openaiIntents,
  ...supabaseIntents,
  ...outlookIntents,
  ...resendIntents,
  ...agentmailIntents,
  ...monidIntents,
  ...sendgridIntents,
  ...mailchimpIntents,
  ...brevoIntents,
  ...intercomIntents,
  ...zendeskIntents,
  ...discordIntents,
  ...twilioIntents,
  ...zoomIntents,
  ...loomIntents,
  ...msTeamsIntents,
  ...telegramIntents,
  ...whatsappBusinessIntents,
  ...cloudflareIntents,
  ...digitaloceanIntents,
  ...hetznerIntents,
  ...linodeIntents,
  ...sentryIntents,
  ...datadogIntents,
  ...newRelicIntents,
  ...pagerdutyIntents,
  ...grafanaIntents,
  ...snykIntents,
  ...googleCalendarIntents,
  ...calendlyIntents,
  ...calComIntents,
  ...auth0Intents,
  ...clerkIntents,
  ...oktaIntents,
  ...twitterIntents,
  ...linkedinIntents,
  ...redditIntents,
  ...youtubeIntents,
  ...anthropicIntents,
  ...replicateIntents,
  ...huggingFaceIntents,
  ...mistralIntents,
  ...qdrantIntents,
  ...langsmithIntents,
  ...googleAnalyticsIntents,
  ...mixpanelIntents,
  ...amplitudeIntents,
  ...posthogIntents,
  ...hotjarIntents,
  ...plausibleIntents,
  ...quickbooksIntents,
  ...xeroIntents,
  ...paypalIntents,
  ...squareIntents,
  ...brexIntents,
  ...wiseIntents,
  ...coinbaseIntents,
  ...shopifyIntents,
  ...bigcommerceIntents,
  ...gumroadIntents,
  ...lemonsqueezyIntents,
  ...woocommerceIntents,
  ...instagramIntents,
  ...tiktokIntents,
  ...spotifyIntents,
  ...figmaIntents,
  ...canvaIntents,
  ...contentfulIntents,
  ...sanityIntents,
  ...strapiIntents,
  ...webflowIntents,
  ...wordpressIntents,
  ...typeformIntents,
  ...neonIntents,
  ...planetscaleIntents,
  ...upstashIntents,
  ...awsS3Intents,
  ...awsIntents,
  ...gcpIntents,
  ...azureIntents,
  ...r2Intents,
  ...backblazeIntents,
  ...mongodbAtlasIntents,
  ...tursoIntents,
  ...wasabiIntents,
  ...customIntents,
];

export const INTENT_REGISTRY: ReadonlyMap<string, Intent> = new Map(
  ALL_INTENTS.map((i) => [i.name, i] as const),
);

export function listIntents(): readonly Intent[] {
  return ALL_INTENTS;
}

export class UnknownIntentError extends Error {
  constructor(public readonly intentName: string) {
    super(`Unknown intent: ${intentName}`);
    this.name = 'UnknownIntentError';
  }
}

export class InvalidIntentParamsError extends Error {
  constructor(public readonly intentName: string, public readonly issues: unknown) {
    super(`Invalid params for intent ${intentName}: ${JSON.stringify(issues)}`);
    this.name = 'InvalidIntentParamsError';
  }
}

/**
 * Expand an agent-declared list of IntentRefs into the flat Constraint[]
 * that rides on a ServiceScope. Used at passport-issue and grant time.
 *
 * Throws on unknown names or invalid params — callers must surface these
 * as 400s rather than silently dropping the intent.
 *
 * No deduplication / merging: proxy evaluation uses AND semantics, so
 * duplicates are harmless but may bloat passport size. Callers concerned
 * about JWT size should dedupe structurally before calling.
 */
export function expandIntents(refs: readonly IntentRef[]): Constraint[] {
  const out: Constraint[] = [];
  for (const ref of refs) {
    const intent = INTENT_REGISTRY.get(ref.name);
    if (!intent) throw new UnknownIntentError(ref.name);
    const parsed = intent.params.safeParse(ref.params);
    if (!parsed.success) {
      throw new InvalidIntentParamsError(ref.name, parsed.error.issues);
    }
    out.push(...intent.expand(parsed.data));
  }
  return out;
}

/** One rule of a grant, as `GrantAgentAccessInput.alternatives` carries it. */
export interface AccessRule {
  intents?: readonly IntentRef[] | undefined;
  constraints?: readonly PlainConstraint[] | undefined;
}

/** What a grant says about what an agent may do: shared limits, and optionally several rules of which any one admits a call. */
export interface GrantRules {
  intents?: readonly IntentRef[] | undefined;
  constraints?: readonly Constraint[] | undefined;
  alternatives?: readonly AccessRule[] | undefined;
}

/**
 * The constraint list a grant stores and enforces. The grant's own intents and
 * constraints come first (they apply to every call), then, when it names
 * rules, ONE `any_of` constraint holding them: a call must fit at least one.
 * A single rule is no choice, so it is spread into the list as it is. A rule
 * that expands to nothing is refused, since it would admit every call.
 *
 * Throws on unknown intents or invalid params, as `expandIntents` does.
 */
export function expandGrantRules(rules: GrantRules): Constraint[] {
  const shared = [...(rules.intents ? expandIntents(rules.intents) : []), ...(rules.constraints ?? [])];
  const groups = (rules.alternatives ?? []).map((rule) => [
    ...(rule.intents ? expandIntents(rule.intents) : []),
    ...(rule.constraints ?? []),
  ] as Constraint[]);
  // A rule with no limits allows every call the shared constraints allow, so the choice adds nothing to them.
  if (groups.some((group) => group.length === 0)) return assertAnyOfBudget(shared);
  if (groups.length === 0) return assertAnyOfBudget(shared);
  if (groups.length === 1) return assertAnyOfBudget([...shared, ...groups[0]!]);
  const plain = groups.map((group) => group.filter((c): c is PlainConstraint => c.op !== 'any_of'));
  if (plain.some((group, i) => group.length !== groups[i]!.length)) {
    throw new InvalidRequestError('A rule cannot hold a choice of rules. List the rules side by side instead.');
  }
  if (plain.some((group) => group.length > 32) || plain.reduce((sum, group) => sum + group.length, 0) > ANY_OF_MAX_LEAVES) {
    throw new InvalidRequestError(`The rules hold more than ${ANY_OF_MAX_LEAVES} constraints in all. Shorten them.`);
  }
  return assertAnyOfBudget([...shared, { path: 'any_of', op: 'any_of', value: plain }]);
}

/** Every intent a grant names, in its own list and in each rule: the readable record of the decision. */
export function grantIntentRefs(rules: GrantRules): IntentRef[] {
  return [...(rules.intents ?? []), ...(rules.alternatives ?? []).flatMap((rule) => rule.intents ?? [])];
}

function assertAnyOfBudget(list: Constraint[]): Constraint[] {
  if (!withinAnyOfBudget(list)) throw new InvalidRequestError(ANY_OF_BUDGET_MESSAGE);
  return list;
}
