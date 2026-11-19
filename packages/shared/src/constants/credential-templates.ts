// ─── Credential Templates ────────────────────────────────────────────
// Static metadata telling the dashboard + MCP what fields each service needs
// and how to verify the credentials work.

export interface CredentialField {
  key: string;
  label: string;
  type: 'text' | 'secret' | 'select';
  required: boolean;
  placeholder?: string;
  options?: string[]; // for select type
}

export interface CredentialTemplate {
  provider: string;
  fields: CredentialField[];
  help_url?: string;
  verification_url?: string;
  verification_method?: 'GET' | 'POST';
  verification_headers?: Record<string, string>;
  /**
   * The key path of a service whose connections are otherwise made through an
   * OAuth app. The template applies only to a credential that carries all of
   * its required fields; any other credential for the provider (an OAuth token
   * response, a bare legacy token) keeps its bearer header and its check.
   */
  own_fields_only?: boolean;
}

export const CREDENTIAL_TEMPLATES: Record<string, CredentialTemplate> = {
  // ─── AI / LLM ──────────────────────────────────────────────────────
  openai: {
    provider: 'openai',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'sk-...' },
      { key: 'organization', label: 'Organization ID', type: 'text', required: false, placeholder: 'org-...' },
    ],
    help_url: 'https://platform.openai.com/api-keys',
    verification_url: 'https://api.openai.com/v1/models',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },
  anthropic: {
    provider: 'anthropic',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'sk-ant-...' },
    ],
    help_url: 'https://console.anthropic.com/settings/keys',
    verification_url: 'https://api.anthropic.com/v1/models',
    verification_headers: { 'x-api-key': '{{api_key}}', 'anthropic-version': '2023-06-01' },
  },
  // RentAHuman: an agent hires people for real-world tasks. Its REST API and its hosted MCP endpoint take the account's
  // key in an `X-API-Key` header. `GET /api/keys` lists the account's keys (metadata only), so it is the probe that a
  // key is valid. Source: rentahuman.ai/docs and the published `rentahuman-mcp` 4.7.0 README.
  rentahuman: {
    provider: 'rentahuman',
    fields: [
      { key: 'api_key', label: 'API key', type: 'secret', required: true, placeholder: 'rah_...' },
    ],
    help_url: 'https://rentahuman.ai/account/api-keys',
    verification_url: 'https://rentahuman.ai/api/keys',
    verification_headers: { 'X-API-Key': '{{api_key}}' },
  },
  // openrouter has been a first-class LLM gateway provider
  // (llm-gateway-service) with a public catalog row (seed-services.mjs,
  // 2026-05-23) but no credential template, so the connect UI had no
  // field spec or key verification for it. /api/v1/key returns the key's
  // own metadata — the canonical "is this key valid" probe (verified
  // 2026-07-09: 401 unauthenticated).
  openrouter: {
    provider: 'openrouter',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'sk-or-...' },
    ],
    help_url: 'https://openrouter.ai/settings/keys',
    verification_url: 'https://openrouter.ai/api/v1/key',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },

  // ─── CRM / Sales ──────────────────────────────────────────────────
  hubspot: {
    provider: 'hubspot',
    fields: [
      { key: 'api_key', label: 'Private App Token', type: 'secret', required: true, placeholder: 'pat-na1-...' },
      { key: 'portal_id', label: 'Portal ID', type: 'text', required: false, placeholder: '12345678' },
    ],
    help_url: 'https://knowledge.hubspot.com/integrations/how-do-i-get-my-hubspot-api-key',
    verification_url: 'https://api.hubapi.com/crm/v3/objects/contacts?limit=1',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },
  salesforce: {
    provider: 'salesforce',
    fields: [
      { key: 'instance_url', label: 'Instance URL', type: 'text', required: true, placeholder: 'https://yourorg.my.salesforce.com' },
      { key: 'access_token', label: 'Access Token', type: 'secret', required: true },
    ],
    help_url: 'https://help.salesforce.com/s/articleView?id=sf.connected_app_create_api_integration.htm',
    verification_url: '{{instance_url}}/services/data/v59.0/limits',
    verification_headers: { 'Authorization': 'Bearer {{access_token}}' },
  },

  // ─── Communication ────────────────────────────────────────────────
  sendgrid: {
    provider: 'sendgrid',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'SG...' },
    ],
    help_url: 'https://docs.sendgrid.com/ui/account-and-settings/api-keys',
    verification_url: 'https://api.sendgrid.com/v3/user/profile',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },
  resend: {
    provider: 'resend',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 're_...' },
    ],
    help_url: 'https://resend.com/api-keys',
    verification_url: 'https://api.resend.com/domains',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },
  agentmail: {
    provider: 'agentmail',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'am_...' },
    ],
    help_url: 'https://docs.agentmail.to/api-reference',
    // This endpoint verifies the credential itself for organization-, pod-,
    // and inbox-scoped keys. Listing all inboxes can correctly return 403 for
    // a valid scoped key, which made STACK label a usable key as unhealthy.
    verification_url: 'https://api.agentmail.to/v0/auth/me',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },
  // ─── Paid data and tools ──────────────────────────────────────────
  monid: {
    provider: 'monid',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'monid_live_...' },
    ],
    help_url: 'https://monid.ai/docs/api/overview',
    // Identifies the key and its workspace; spends nothing.
    verification_url: 'https://api.monid.ai/v1/auth/whoami',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },
  twilio: {
    provider: 'twilio',
    fields: [
      { key: 'account_sid', label: 'Account SID', type: 'text', required: true, placeholder: 'AC...' },
      { key: 'auth_token', label: 'Auth Token', type: 'secret', required: true },
    ],
    help_url: 'https://www.twilio.com/docs/iam/keys/api-key',
    verification_url: 'https://api.twilio.com/2010-04-01/Accounts/{{account_sid}}.json',
    verification_headers: { 'Authorization': 'Basic {{__basic:account_sid:auth_token}}' },
  },

  // ─── Cloud / Infrastructure ───────────────────────────────────────
  aws: {
    provider: 'aws',
    fields: [
      { key: 'access_key_id', label: 'Access Key ID', type: 'text', required: true, placeholder: 'AKIA...' },
      { key: 'secret_access_key', label: 'Secret Access Key', type: 'secret', required: true },
      { key: 'region', label: 'Region', type: 'select', required: true, options: [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
        'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2',
      ] },
    ],
    help_url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
  },
  cloudflare: {
    provider: 'cloudflare',
    fields: [
      { key: 'api_token', label: 'API Token', type: 'secret', required: true },
    ],
    help_url: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/',
    verification_url: 'https://api.cloudflare.com/client/v4/user/tokens/verify',
    verification_headers: { 'Authorization': 'Bearer {{api_token}}' },
  },
  vercel: {
    provider: 'vercel',
    fields: [
      { key: 'api_token', label: 'API Token', type: 'secret', required: true },
      { key: 'team_id', label: 'Team ID', type: 'text', required: false, placeholder: 'team_...' },
    ],
    help_url: 'https://vercel.com/account/tokens',
    verification_url: 'https://api.vercel.com/v2/user',
    verification_headers: { 'Authorization': 'Bearer {{api_token}}' },
  },

  // ─── Payments ─────────────────────────────────────────────────────
  stripe: {
    provider: 'stripe',
    fields: [
      { key: 'secret_key', label: 'Secret Key', type: 'secret', required: true, placeholder: 'sk_live_... or sk_test_...' },
    ],
    help_url: 'https://dashboard.stripe.com/apikeys',
    verification_url: 'https://api.stripe.com/v1/balance',
    verification_headers: { 'Authorization': 'Bearer {{secret_key}}' },
  },

  // ─── Databases / Data ─────────────────────────────────────────────
  supabase: {
    provider: 'supabase',
    fields: [
      { key: 'url', label: 'Project URL', type: 'text', required: true, placeholder: 'https://xxxx.supabase.co' },
      { key: 'service_role_key', label: 'Service Role Key', type: 'secret', required: true, placeholder: 'eyJ...' },
    ],
    help_url: 'https://supabase.com/dashboard/project/_/settings/api',
    verification_url: '{{url}}/rest/v1/',
    verification_headers: { 'apikey': '{{service_role_key}}', 'Authorization': 'Bearer {{service_role_key}}' },
  },
  airtable: {
    provider: 'airtable',
    fields: [
      { key: 'api_key', label: 'Personal Access Token', type: 'secret', required: true, placeholder: 'pat...' },
    ],
    help_url: 'https://airtable.com/create/tokens',
    verification_url: 'https://api.airtable.com/v0/meta/whoami',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },

  // ─── Dev Tools ────────────────────────────────────────────────────
  sentry: {
    provider: 'sentry',
    fields: [
      { key: 'auth_token', label: 'Auth Token', type: 'secret', required: true },
      { key: 'organization', label: 'Organization Slug', type: 'text', required: true },
    ],
    help_url: 'https://docs.sentry.io/api/auth/',
    verification_url: 'https://sentry.io/api/0/organizations/{{organization}}/',
    verification_headers: { 'Authorization': 'Bearer {{auth_token}}' },
  },
  posthog: {
    provider: 'posthog',
    fields: [
      { key: 'api_key', label: 'Personal API Key', type: 'secret', required: true, placeholder: 'phx_...' },
      { key: 'host', label: 'Instance URL', type: 'text', required: false, placeholder: 'https://app.posthog.com' },
    ],
    help_url: 'https://posthog.com/docs/api',
    verification_url: '{{host}}/api/projects/',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
  },

  // ─── Project Management ───────────────────────────────────────────
  notion_api: {
    provider: 'notion_api',
    fields: [
      { key: 'api_key', label: 'Internal Integration Token', type: 'secret', required: true, placeholder: 'ntn_...' },
    ],
    help_url: 'https://www.notion.so/my-integrations',
    verification_url: 'https://api.notion.com/v1/users/me',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}', 'Notion-Version': '2022-06-28' },
  },
  linear_api: {
    provider: 'linear_api',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'lin_api_...' },
    ],
    help_url: 'https://linear.app/settings/api',
    verification_url: 'https://api.linear.app/graphql',
    verification_method: 'POST',
    verification_headers: { 'Authorization': '{{api_key}}', 'Content-Type': 'application/json' },
  },

  // ─── Keys for services that also have an OAuth app ─────────────────
  // STACK registers no OAuth app of its own at these providers, so each is
  // connected with the key or token the service itself issues (or, for a
  // company, its own OAuth app). `own_fields_only` keeps these headers off a
  // connection made through an OAuth app: that credential carries an
  // `access_token`, not these fields, and keeps its bearer header.
  github: {
    provider: 'github',
    fields: [
      { key: 'token', label: 'Personal Access Token', type: 'secret', required: true, placeholder: 'github_pat_...' },
    ],
    help_url: 'https://github.com/settings/personal-access-tokens',
    verification_url: 'https://api.github.com/user',
    verification_headers: { 'Authorization': 'Bearer {{token}}' },
    own_fields_only: true,
  },
  linear: {
    provider: 'linear',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'lin_api_...' },
    ],
    help_url: 'https://linear.app/settings/api',
    verification_url: 'https://api.linear.app/graphql',
    verification_method: 'POST',
    verification_headers: { 'Authorization': '{{api_key}}', 'Content-Type': 'application/json' },
    own_fields_only: true,
  },
  notion: {
    provider: 'notion',
    fields: [
      { key: 'api_key', label: 'Internal Integration Token', type: 'secret', required: true, placeholder: 'ntn_...' },
    ],
    help_url: 'https://www.notion.so/my-integrations',
    verification_url: 'https://api.notion.com/v1/users/me',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}', 'Notion-Version': '2022-06-28' },
    own_fields_only: true,
  },
  figma: {
    provider: 'figma',
    fields: [
      { key: 'token', label: 'Personal Access Token', type: 'secret', required: true, placeholder: 'figd_...' },
    ],
    help_url: 'https://www.figma.com/developers/api#access-tokens',
    verification_url: 'https://api.figma.com/v1/me',
    verification_headers: { 'X-Figma-Token': '{{token}}' },
    own_fields_only: true,
  },
  discord: {
    provider: 'discord',
    fields: [
      { key: 'bot_token', label: 'Bot Token', type: 'secret', required: true },
    ],
    help_url: 'https://discord.com/developers/applications',
    verification_url: 'https://discord.com/api/v10/users/@me',
    verification_headers: { 'Authorization': 'Bot {{bot_token}}' },
    own_fields_only: true,
  },
  jira: {
    provider: 'jira',
    fields: [
      { key: 'site_url', label: 'Site URL', type: 'text', required: true, placeholder: 'https://yourorg.atlassian.net' },
      { key: 'email', label: 'Account Email', type: 'text', required: true },
      { key: 'api_token', label: 'API Token', type: 'secret', required: true },
    ],
    help_url: 'https://id.atlassian.com/manage-profile/security/api-tokens',
    verification_url: '{{site_url}}/rest/api/3/myself',
    verification_headers: { 'Authorization': 'Basic {{__basic:email:api_token}}' },
    own_fields_only: true,
  },
  confluence: {
    provider: 'confluence',
    fields: [
      { key: 'site_url', label: 'Site URL', type: 'text', required: true, placeholder: 'https://yourorg.atlassian.net' },
      { key: 'email', label: 'Account Email', type: 'text', required: true },
      { key: 'api_token', label: 'API Token', type: 'secret', required: true },
    ],
    help_url: 'https://id.atlassian.com/manage-profile/security/api-tokens',
    verification_url: '{{site_url}}/wiki/rest/api/user/current',
    verification_headers: { 'Authorization': 'Basic {{__basic:email:api_token}}' },
    own_fields_only: true,
  },

  // Cal.com API v2 takes the key (`cal_live_...`) as a bearer token; `GET /v2/me` answers 401 without one. The key
  // is the only way in that STACK offers, but a customer's own OAuth app can also connect Cal.com, so the template
  // applies to a credential carrying `api_key` and leaves an OAuth token response on its bearer `access_token`.
  cal_com: {
    provider: 'cal_com',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'secret', required: true, placeholder: 'cal_live_...' },
    ],
    help_url: 'https://app.cal.com/settings/developer/api-keys',
    verification_url: 'https://api.cal.com/v2/me',
    verification_headers: { 'Authorization': 'Bearer {{api_key}}' },
    own_fields_only: true,
  },

  // ─── Search ───────────────────────────────────────────────────────
  algolia: {
    provider: 'algolia',
    fields: [
      { key: 'app_id', label: 'Application ID', type: 'text', required: true },
      { key: 'admin_api_key', label: 'Admin API Key', type: 'secret', required: true },
    ],
    help_url: 'https://www.algolia.com/doc/guides/security/api-keys/',
    verification_url: 'https://{{app_id}}-dsn.algolia.net/1/keys',
    verification_headers: { 'X-Algolia-API-Key': '{{admin_api_key}}', 'X-Algolia-Application-Id': '{{app_id}}' },
  },
};
