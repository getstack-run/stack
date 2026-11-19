// Known API hosts per provider — the seed for credential-to-destination
// binding (see `packages/shared/src/utils/host-binding.ts`).
//
// WHY THIS EXISTS. `POST /v1/proxy` takes `service` and `url` as independent
// inputs: `service` picks which stored credential is decrypted and injected,
// `url` is wherever the agent asked to go. Until the host binding landed,
// nothing tied the two together, so a passport granting `stripe` could send
// the live Stripe key to any public host. This map is what lets a connection
// be bound to its provider without every operator hand-typing a hostname.
//
// PROVENANCE — every entry below is transcribed from something already in
// this repo, never from recollection. Three sources, all cited inline:
//   (i)   the `Base:` declaration in the provider's own intent catalog
//         header, `packages/shared/src/intents/<provider>.ts`, authored
//         next to that provider's docs URL
//   (ii)  `verification_url` in `credential-templates.ts`
//   (iii) `OAUTH_VERIFY_ENDPOINTS` in
//         `packages/vault/src/services/connection-verifier.ts`
//
// THIS MAP IS DELIBERATELY PARTIAL. Around sixty catalog providers document
// no base host anywhere in the repo, and several more are per-tenant by
// nature (Shopify stores, Zendesk subdomains, self-hosted Grafana). Guessing
// a hostname for those would bake a wrong default into a security control,
// so they are simply absent. Absent means the operator declares
// `allowed_hosts` on the connection and the proxy denies until they do.
// Fail closed, visibly, with an actionable error — never fail open.
//
// TO ADD A PROVIDER: confirm the host against that provider's published API
// reference (not from memory), add it here, and cite the source in the
// comment. A wrong entry here is worse than a missing one: a missing entry
// asks the operator a question, a wrong entry silently permits a destination.

/**
 * provider slug → hosts its credential may be sent to.
 *
 * Entries may use the dot-led suffix form (`.amazonaws.com`) understood by
 * `isHostAllowed` when a provider is legitimately multi-host.
 */
export const PROVIDER_API_HOSTS: Record<string, readonly string[]> = {
  // ─── (i) from the `Base:` line of each intent catalog header ────────
  agentmail: ['api.agentmail.to'],
  anthropic: ['api.anthropic.com'],
  bamboohr: ['api.bamboohr.com'],
  bigcommerce: ['api.bigcommerce.com'],
  brevo: ['api.brevo.com'],
  brex: ['platform.brexapis.com'],
  cloudflare: ['api.cloudflare.com'],
  coinbase: ['api.coinbase.com'],
  datadog: ['api.datadoghq.com'],
  digitalocean: ['api.digitalocean.com'],
  discord: ['discord.com'],
  gumroad: ['api.gumroad.com'],
  gusto: ['api.gusto.com'],
  hetzner: ['api.hetzner.cloud'],
  hubspot: ['api.hubapi.com'],
  intercom: ['api.intercom.io'],
  langsmith: ['api.smith.langchain.com'],
  lemonsqueezy: ['api.lemonsqueezy.com'],
  linode: ['api.linode.com'],
  mistral: ['api.mistral.ai'],
  monid: ['api.monid.ai'],
  ms_teams: ['graph.microsoft.com'],
  neon: ['console.neon.tech'],
  new_relic: ['api.newrelic.com'],
  openai: ['api.openai.com'],
  pagerduty: ['api.pagerduty.com'],
  paypal: ['api-m.paypal.com'],
  quickbooks: ['quickbooks.api.intuit.com'],
  replicate: ['api.replicate.com'],
  resend: ['api.resend.com'],
  sendgrid: ['api.sendgrid.com'],
  sentry: ['sentry.io'],
  snyk: ['api.snyk.io'],
  square: ['connect.squareup.com'],
  stripe: ['api.stripe.com'],
  telegram: ['api.telegram.org'],
  twilio: ['api.twilio.com'],
  whatsapp_business: ['graph.facebook.com'],
  wise: ['api.wise.com'],
  xero: ['api.xero.com'],
  zoom: ['api.zoom.us'],

  // ─── (ii) from `verification_url` in credential-templates.ts ────────
  openrouter: ['openrouter.ai'],
  airtable: ['api.airtable.com'],
  vercel: ['api.vercel.com'],
  notion_api: ['api.notion.com'],
  linear_api: ['api.linear.app'],
  // The `verification_url` of RentAHuman's template: its REST API and its hosted MCP endpoint (/api/mcp) are one host.
  rentahuman: ['rentahuman.ai'],

  // ─── (iii) from OAUTH_VERIFY_ENDPOINTS in connection-verifier.ts ────
  slack: ['slack.com'],
  github: ['api.github.com'],
  google_drive: ['www.googleapis.com'],
  gmail: ['gmail.googleapis.com'],
  notion: ['api.notion.com'],
  linear: ['api.linear.app'],
  figma: ['api.figma.com'],
  dropbox: ['api.dropboxapi.com'],
  microsoft: ['graph.microsoft.com'],
  spotify: ['api.spotify.com'],
  asana: ['app.asana.com'],

  // ─── (iv) confirmed against each provider's official API reference ──
  //
  // Added so the catalogue we ship never has to ask the operator where its
  // own credential goes. Where a vendor mirrors an API across regions, BOTH
  // hosts are listed: sending a credential to the wrong regional twin is a
  // cross-jurisdiction leak, and omitting the twin would break the operator
  // who legitimately uses it.

  // Microsoft Graph
  microsoft_teams: ['graph.microsoft.com'],
  outlook: ['graph.microsoft.com'],
  microsoft_entra_app: ['graph.microsoft.com'],

  // Messaging / marketing
  klaviyo: ['a.klaviyo.com'],
  postmark: ['api.postmarkapp.com'],

  // Dev platforms
  gitlab: ['gitlab.com'], // SaaS; self-managed GitLab is per-tenant
  fly_io: ['api.machines.dev'],
  railway: ['backboard.railway.app'],
  netlify: ['api.netlify.com'],
  render: ['api.render.com'],
  bitbucket: ['api.bitbucket.org'],

  // Atlassian Cloud — OAuth 3LO goes through api.atlassian.com; API-token
  // auth goes to the per-site <site>.atlassian.net, which the operator
  // declares on the connection.
  jira: ['api.atlassian.com'],
  confluence: ['api.atlassian.com'],

  // Project / work management
  clickup: ['api.clickup.com'],
  monday: ['api.monday.com'],
  basecamp: ['3.basecampapi.com'],
  trello: ['api.trello.com'],
  shortcut: ['api.app.shortcut.com'],
  coda: ['coda.io'],

  // Google APIs
  google_docs: ['docs.googleapis.com'],
  google_sheets: ['sheets.googleapis.com'],
  google_calendar: ['www.googleapis.com'],
  google_analytics: ['analyticsdata.googleapis.com', 'analyticsadmin.googleapis.com'],
  youtube: ['www.googleapis.com'],

  // CRM / support / finance
  close: ['api.close.com'],
  attio: ['api.attio.com'],
  front: ['api2.frontapp.com'], // NOT api.frontapp.com
  plaid: ['sandbox.plaid.com', 'production.plaid.com'],
  mercury: ['api.mercury.com'],
  ramp: ['api.ramp.com'],
  rippling: ['rest.ripplingapis.com', 'api.rippling.com'],
  deel: ['api.letsdeel.com', 'api-sandbox.demo.deel.com'],

  // Analytics — regional twins listed where the vendor mirrors them
  mixpanel: [
    'api.mixpanel.com', 'mixpanel.com', 'data.mixpanel.com',
    'api-eu.mixpanel.com', 'eu.mixpanel.com', 'data-eu.mixpanel.com',
  ],
  amplitude: [
    'api2.amplitude.com', 'api.amplitude.com', 'amplitude.com',
    'api.eu.amplitude.com', 'analytics.eu.amplitude.com',
  ],
  segment: [
    'api.segment.io', 'api.segmentapis.com',
    'events.eu1.segmentapis.com', 'eu1.api.segmentapis.com',
  ],
  heap: ['heapanalytics.com', 'c.eu.heap-api.com'],
  fullstory: ['api.fullstory.com'],
  hotjar: ['insights.hotjar.com'],

  // AI / inference
  hugging_face: ['api-inference.huggingface.co', 'huggingface.co'],
  cohere: ['api.cohere.com'],
  groq: ['api.groq.com'],
  together_ai: ['api.together.ai', 'api.together.xyz'],
  fireworks: ['api.fireworks.ai'],

  // Data infrastructure — control planes are fixed hosts; the per-tenant
  // part of these products is the database connection, not the REST API.
  pinecone: ['api.pinecone.io'], // control plane; data plane is per-index
  planetscale: ['api.planetscale.com'],
  upstash: ['api.upstash.com'], // management plane; Redis REST is per-db
  mongodb_atlas: ['cloud.mongodb.com'],
  turso: ['api.turso.tech'],

  // Scheduling
  calendly: ['api.calendly.com'],
  cal_com: ['api.cal.com'],

  // Social
  twitter: ['api.x.com', 'api.twitter.com'],
  linkedin: ['api.linkedin.com'],
  reddit: ['oauth.reddit.com'],
  instagram: ['graph.facebook.com', 'graph.instagram.com'],
  tiktok: ['business-api.tiktok.com', 'open.tiktokapis.com'],

  // Automation
  zapier: ['api.zapier.com'],
  make: [
    'eu1.make.com', 'eu2.make.com', 'us1.make.com', 'us2.make.com',
    'eu1.make.celonis.com', 'us1.make.celonis.com',
  ],

  // Identity — note the auth host is separate from the API host for
  // Bitwarden (identity.*), so it is listed alongside.
  clerk: ['api.clerk.com', 'api.clerk.dev'],
  bitwarden: [
    'api.bitwarden.com', 'api.bitwarden.eu',
    'identity.bitwarden.com', 'identity.bitwarden.eu',
  ],
  onepassword: [
    'events.1password.com', 'events.ent.1password.com',
    'events.1password.ca', 'events.1password.eu',
  ],

  // Content / design
  canva: ['api.canva.com'],
  box: ['api.box.com', 'upload.box.com'],
  loom: ['www.loom.com'],
  webflow: ['api.webflow.com'],
  typeform: ['api.typeform.com'],
  tally: ['api.tally.so'],
  contentful: [
    'api.contentful.com', 'cdn.contentful.com', 'preview.contentful.com',
    'graphql.contentful.com', 'images.ctfassets.net',
    'api.eu.contentful.com', 'cdn.eu.contentful.com', 'preview.eu.contentful.com',
    'graphql.eu.contentful.com', 'images.eu.ctfassets.net',
  ],
};

/**
 * Providers whose API host is per-tenant by design, documented as templated
 * in their intent catalog header. There is no correct default for these —
 * the operator's own instance IS the host — so they are listed here purely
 * so the error message can say "this provider is per-tenant, declare your
 * instance host" rather than the generic "unknown provider".
 *
 * Source: the `Base:` line of each provider's intent catalog header.
 */
export const PER_TENANT_HOST_PROVIDERS: ReadonlySet<string> = new Set([
  'grafana', // {grafana_host}
  'mailchimp', // <dc>.api.mailchimp.com
  'shopify', // {shop}.myshopify.com
  'supabase', // {project}.supabase.co
  'woocommerce', // {site}
  'zendesk', // <subdomain>.zendesk.com
  'salesforce', // {{instance_url}} — credential-templates.ts
  'posthog', // {{host}} — credential-templates.ts
  'algolia', // {{app_id}}-dsn.algolia.net — credential-templates.ts
  'aws', // regional endpoints, no single host

  // Confirmed per-tenant against official docs. Each of these has a real
  // host, but it is the OPERATOR'S host, so there is no correct default and
  // guessing one would be worse than asking. `deriveConnectionHosts` picks
  // most of them straight out of the credential the operator pasted.
  'activecampaign', // <account>.api-us1.com — docs explicitly warn NOT to assume api-us1
  'freshdesk', // <helpdesk-domain>.freshdesk.com
  'pipedrive', // <companydomain>.pipedrive.com — routes to the right data centre
  'auth0', // {tenant}.auth0.com
  'okta', // {yourOktaDomain}
  'vault', // HashiCorp Vault, self-hosted (VAULT_ADDR)
  'n8n', // <name>.app.n8n.cloud or self-hosted
  'strapi', // self-hosted
  'wordpress', // the site itself is the host
  'sanity', // {projectId}.api.sanity.io
  'weaviate', // cloud cluster or self-hosted; docs never print a literal host
  'qdrant', // {cluster}.{region}.{cloud}.cloud.qdrant.io or self-hosted
  'aws_s3', // {bucket}.s3.{region}.amazonaws.com
  'r2', // {account-id}.r2.cloudflarestorage.com
  'backblaze', // api{NNN}.backblazeb2.com after auth redirect
  'wasabi', // s3.{region}.wasabisys.com
  'plausible', // self-hostable
  'gcp', // umbrella: {service}.googleapis.com
  'azure', // umbrella: management.azure.com + per-tenant data planes
]);

/**
 * Catalog default hosts for a provider, or null when we have no grounded
 * value. Null is not "allow anything" — callers must treat it as "the
 * operator has to declare `allowed_hosts` on the connection".
 *
 * A `custom_<name>` connection resolves against `<name>`, mirroring the
 * template lookup in `ConnectionVerifierService.verify`, so a custom
 * connection to a known provider inherits that provider's hosts.
 */
export function defaultHostsForProvider(provider: string): readonly string[] | null {
  const key = provider.replace(/^custom_/, '').toLowerCase();
  return PROVIDER_API_HOSTS[key] ?? null;
}

/** Is this provider one whose host is inherently operator-specific? */
export function isPerTenantHostProvider(provider: string): boolean {
  return PER_TENANT_HOST_PROVIDERS.has(provider.replace(/^custom_/, '').toLowerCase());
}
