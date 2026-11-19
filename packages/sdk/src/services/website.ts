import type { HttpClient } from '../client.js';
import type { AccountAgentCallOptions } from './accounts.js';
import type { SiteScanFinding } from '../errors.js';

// An agent's website: one site per agent account, built and updated by the
// account's agent under its Passport, read and suspended by the customer.
//
// The agent publishes a bundle (every file, and optionally one server module)
// and the publish scan checks it first: a refusal throws
// `WebsitePublishRejectedError` with each finding, and nothing goes live.
// Publishing the same bundle again returns the live deploy and changes
// nothing. A site is suspended in one call by its owner; an agent can neither
// suspend nor resume its own site. Calls the agent makes (`publish`,
// `addHostname`, `removeHostname`, `setPrices`) require its Passport as
// `passportToken`, sent as `X-Passport-Token`; reads and `checkHostname` take
// it optionally, and the owner's calls take none.

export type SiteState = 'pending' | 'live' | 'suspended' | 'taken_down' | 'closed';
export type SiteDeployState = 'scanning' | 'live' | 'rejected' | 'failed' | 'superseded';
export type SiteHostnameKind = 'platform' | 'custom';
export type SiteHostnameState = 'pending' | 'active' | 'failed' | 'removed';
export type SiteSuspender = 'owner' | 'staff' | 'scan' | 'account_closed';
export type SiteReportCategory = 'phishing' | 'impersonation' | 'malware' | 'illegal_content' | 'copyright' | 'spam' | 'other';

/** One file of a bundle: exactly one of `content` (UTF-8 text) and `content_base64`. */
export type SiteFileInput =
  | { path: string; content: string; content_base64?: undefined }
  | { path: string; content_base64: string; content?: undefined };

export interface PublishSiteInput {
  /** One or more files. A path is absolute, such as `/index.html`. */
  files: SiteFileInput[];
  /**
   * Small server code: one JavaScript module with a default export
   * `{ fetch(request, env) }`. `env.ASSETS.fetch(request)` serves the files. It
   * runs in the site's own isolated Worker with no STACK credential.
   */
  server?: { source: string };
}

/** A file as you hold it: text as a string, anything else as bytes. */
export interface SiteFileEntry {
  path: string;
  content: string | Uint8Array;
}

export interface SiteDeployFile {
  path: string;
  sha256: string;
  bytes: number;
  content_type: string;
}

export interface SiteDeploy {
  id: string;
  state: SiteDeployState;
  bundle_sha256: string;
  server_sha256: string | null;
  file_count: number;
  total_bytes: number;
  files: SiteDeployFile[];
  findings: SiteScanFinding[];
  failure_code: string | null;
  created_at: string;
  live_at: string | null;
}

export interface SiteDnsRecord {
  type: string;
  name: string;
  value: string;
}

export interface SiteHostname {
  id: string;
  hostname: string;
  kind: SiteHostnameKind;
  state: SiteHostnameState;
  /** What the customer sets at their DNS provider. Empty for STACK's own address. */
  dns: SiteDnsRecord[];
  ssl_state: string | null;
  last_error: string | null;
  verified_at: string | null;
  created_at: string;
}

export interface AddSiteHostnameInput {
  /** A lower-case DNS name of two labels or more, such as `www.example.com`. */
  hostname: string;
}

export interface SitePriceInput {
  /** An exact path, or a prefix ending in `/*` (the prefix itself and everything under it). */
  path: string;
  /** USDC as a decimal string with up to six places and at least 0.000001, such as `0.25`. */
  price_usdc: string;
  description?: string;
}

export interface SetSitePricesInput {
  /** The whole set: it replaces what was there. Send an empty list to remove every price. */
  prices: SitePriceInput[];
}

export interface SitePrice {
  path: string;
  price_usdc: string;
  description: string | null;
}

export interface SiteLimits {
  max_total_bytes: number;
}

export interface Site {
  id: string;
  account_id: string;
  state: SiteState;
  /** The site's address on STACK's agent-sites domain. */
  url: string;
  hostnames: SiteHostname[];
  current_deploy: SiteDeploy | null;
  limits: SiteLimits;
  suspension: { by: SiteSuspender; reason: string | null; at: string } | null;
  prices: SitePrice[];
  /** Whether priced paths can be paid for, and why not when they cannot. */
  x402: { available: boolean; reason: string | null };
  created_at: string;
}

export interface ListSiteDeploysQuery {
  /** 1 to 50, default 20. */
  limit?: number;
}

const seg = encodeURIComponent;

function passport(options?: AccountAgentCallOptions): { headers: Record<string, string> } | undefined {
  return options?.passportToken ? { headers: { 'X-Passport-Token': options.passportToken } } : undefined;
}

/** The account's agent builds the site; the owner's credential alone is refused, so refuse before sending. */
function agentPassport(options: AccountAgentCallOptions | undefined): { headers: Record<string, string> } {
  if (!options?.passportToken) {
    throw new TypeError("passportToken is required: the account's agent does this, under its Passport");
  }
  return { headers: { 'X-Passport-Token': options.passportToken } };
}

function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/** The text of `bytes` when it is valid UTF-8 with no NUL, else null. Encoding the text again gives back the same bytes. */
function utf8Text(bytes: Uint8Array): string | null {
  if (bytes.includes(0)) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Build the `files` of a publish from files you hold. A string is sent as
 * `content`; bytes are sent as `content`, too, when they are UTF-8 text, and
 * as `content_base64` otherwise. Throws when the list is empty or a path repeats; the
 * API checks the rest (a site has no limit on its number of files).
 */
export function siteFiles(entries: readonly SiteFileEntry[]): SiteFileInput[] {
  if (entries.length === 0) throw new RangeError('a site needs at least one file');
  const seen = new Set<string>();
  return entries.map((entry) => {
    if (seen.has(entry.path)) throw new RangeError(`the path ${entry.path} is in the bundle twice`);
    seen.add(entry.path);
    if (typeof entry.content === 'string') return { path: entry.path, content: entry.content };
    const text = utf8Text(entry.content);
    return text !== null
      ? { path: entry.path, content: text }
      : { path: entry.path, content_base64: toBase64(entry.content) };
  });
}

export class WebsiteService {
  constructor(private readonly client: HttpClient) {}

  /** The account's site, with its addresses, live deploy, prices and limits. The empty site is created on the first read. */
  async get(accountId: string, options?: AccountAgentCallOptions): Promise<Site> {
    return this.client.get<Site>(`/v1/accounts/${seg(accountId)}/website`, undefined, passport(options));
  }

  /**
   * Publish a bundle: it becomes the live site once the scan passes. One
   * metered action, and a decision for the customer's controls. Throws
   * `WebsitePublishRejectedError` (with the findings), `WebsiteLimitExceededError`
   * or `WebsiteSuspendedError`. The same bundle again returns the live deploy.
   */
  async publish(accountId: string, input: PublishSiteInput, options: AccountAgentCallOptions): Promise<SiteDeploy> {
    return this.client.post<SiteDeploy>(`/v1/accounts/${seg(accountId)}/website/deploys`, input, agentPassport(options));
  }

  /** The recent deploys, newest first. */
  async listDeploys(
    accountId: string,
    query: ListSiteDeploysQuery = {},
    options?: AccountAgentCallOptions,
  ): Promise<{ deploys: SiteDeploy[] }> {
    return this.client.get<{ deploys: SiteDeploy[] }>(
      `/v1/accounts/${seg(accountId)}/website/deploys`,
      { limit: query.limit !== undefined ? String(query.limit) : undefined },
      passport(options),
    );
  }

  async getDeploy(accountId: string, deployId: string, options?: AccountAgentCallOptions): Promise<SiteDeploy> {
    return this.client.get<SiteDeploy>(`/v1/accounts/${seg(accountId)}/website/deploys/${seg(deployId)}`, undefined, passport(options));
  }

  /**
   * Add the customer's own domain. It starts `pending`; `dns` lists what the
   * customer sets at their DNS provider, and `checkHostname` moves it to
   * `active` once it resolves. A pending name nobody verifies for 7 days is
   * released.
   */
  async addHostname(accountId: string, input: AddSiteHostnameInput, options: AccountAgentCallOptions): Promise<SiteHostname> {
    return this.client.post<SiteHostname>(`/v1/accounts/${seg(accountId)}/website/hostnames`, input, agentPassport(options));
  }

  async listHostnames(accountId: string, options?: AccountAgentCallOptions): Promise<{ hostnames: SiteHostname[] }> {
    return this.client.get<{ hostnames: SiteHostname[] }>(`/v1/accounts/${seg(accountId)}/website/hostnames`, undefined, passport(options));
  }

  /** Check the domain's DNS and certificate now. The owner or the agent. */
  async checkHostname(accountId: string, hostnameId: string, options?: AccountAgentCallOptions): Promise<SiteHostname> {
    return this.client.post<SiteHostname>(
      `/v1/accounts/${seg(accountId)}/website/hostnames/${seg(hostnameId)}/check`,
      undefined,
      passport(options),
    );
  }

  /** Stop serving the site on a domain and release the name. */
  async removeHostname(accountId: string, hostnameId: string, options: AccountAgentCallOptions): Promise<void> {
    await this.client.delete<void>(`/v1/accounts/${seg(accountId)}/website/hostnames/${seg(hostnameId)}`, agentPassport(options));
  }

  /**
   * Set the paths that cost USDC to read. The list replaces the set. A visitor
   * pays the agent's own wallet before the page is served; with no wallet or
   * no payment service the price path answers 503 and never serves free.
   */
  async setPrices(accountId: string, input: SetSitePricesInput, options: AccountAgentCallOptions): Promise<{ prices: SitePrice[] }> {
    return this.client.put<{ prices: SitePrice[] }>(`/v1/accounts/${seg(accountId)}/website/prices`, input, agentPassport(options));
  }

  async getPrices(accountId: string, options?: AccountAgentCallOptions): Promise<{ prices: SitePrice[] }> {
    return this.client.get<{ prices: SitePrice[] }>(`/v1/accounts/${seg(accountId)}/website/prices`, undefined, passport(options));
  }

  /** Take the site offline now. Owner or admin only; an agent is refused. `reason` is 3 to 500 characters. */
  async suspend(accountId: string, reason: string): Promise<Site> {
    return this.client.post<Site>(`/v1/accounts/${seg(accountId)}/website/suspension`, { reason });
  }

  /** Bring the site back after your own suspension. A suspension by STACK is not lifted this way. */
  async resume(accountId: string): Promise<Site> {
    return this.client.delete<Site>(`/v1/accounts/${seg(accountId)}/website/suspension`);
  }

  /** Suspend every site of your account at once. Returns how many were suspended. */
  async suspendAll(reason: string): Promise<{ suspended: number }> {
    return this.client.post<{ suspended: number }>('/v1/websites/suspend-all', { reason });
  }

  /**
   * Report a page on a STACK-hosted site. Anyone may: it needs no account and
   * sends no credential. The answer is the same whether or not the address is
   * one STACK hosts. `description` is 10 to 2000 characters.
   */
  async report(
    url: string,
    category: SiteReportCategory,
    description: string,
    reporterEmail?: string,
  ): Promise<{ accepted: true }> {
    return this.client.postPublic<{ accepted: true }>('/v1/public/site-reports', {
      url,
      category,
      description,
      ...(reporterEmail !== undefined ? { reporter_email: reporterEmail } : {}),
    });
  }
}
