import { canonicalize, publicFetch, sha256 } from '@stack/shared';

const STRIPE_REFUNDS_URL = 'https://api.stripe.com/v1/refunds';
const STRIPE_API_VERSION = '2024-06-20';
const PAGE_SIZE = 100;
const MAX_PAGES = 100;
type StripeRefundStatus = 'pending' | 'requires_action' | 'succeeded' | 'failed' | 'canceled';

export type StripeReconciliationResult = {
  state: 'confirmed' | 'not_found' | 'contradictory';
  evidenceHash: `sha256:${string}`;
  resourceHash?: `sha256:${string}`;
  providerStatus?: StripeRefundStatus;
  observedCount: number;
};

export class StripeReconciliationUnavailableError extends Error {
  constructor(message = 'Stripe reconciliation is temporarily unavailable') {
    super(message);
    this.name = 'StripeReconciliationUnavailableError';
  }
}

type Fetcher = typeof publicFetch;

/**
 * Read-only, fixed-destination Stripe reconciliation. The browser supplies no
 * provider URL, outcome, resource ID or evidence. We query only refunds made
 * after the durable dispatch window and match the STACK-reserved metadata
 * marker that was injected into the exact outbound request.
 */
export async function reconcileStripeRefund(input: {
  credential: string | Record<string, string>;
  stripeAccount: string | null;
  providerMarker: string;
  firstDispatchedAt: Date;
  fetcher?: Fetcher;
}): Promise<StripeReconciliationResult> {
  const token = stripeCredentialToken(input.credential);
  if (!token) throw new StripeReconciliationUnavailableError('Pinned Stripe credential is unavailable');
  if (!/^stack_[0-9a-f]{64}$/.test(input.providerMarker)) {
    throw new StripeReconciliationUnavailableError('Stripe reconciliation marker is invalid');
  }
  if (input.stripeAccount !== null && !/^acct_[A-Za-z0-9]+$/.test(input.stripeAccount)) {
    throw new StripeReconciliationUnavailableError('Pinned Stripe account is invalid');
  }

  const fetcher = input.fetcher ?? publicFetch;
  const createdGte = Math.max(0, Math.floor(input.firstDispatchedAt.getTime() / 1_000) - 300);
  let startingAfter: string | null = null;
  let pages = 0;
  let completed = false;
  const matches: Array<{ id: string; status: StripeRefundStatus | null; created: number | null }> = [];

  while (pages < MAX_PAGES) {
    const url = new URL(STRIPE_REFUNDS_URL);
    url.searchParams.set('limit', String(PAGE_SIZE));
    url.searchParams.set('created[gte]', String(createdGte));
    if (startingAfter) url.searchParams.set('starting_after', startingAfter);
    const response = await fetcher(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Stripe-Version': STRIPE_API_VERSION,
        ...(input.stripeAccount ? { 'Stripe-Account': input.stripeAccount } : {}),
      },
      redirect: 'manual',
    }, {
      timeoutMs: 10_000,
      maxResponseBytes: 2 * 1024 * 1024,
      maxRequestBytes: 1,
    });
    if (!response.ok) {
      throw new StripeReconciliationUnavailableError(`Stripe reconciliation returned HTTP ${response.status}`);
    }
    const page = await parseStripeRefundPage(response);
    pages += 1;
    for (const refund of page.data) {
      if (refund.metadata?.stack_operation === input.providerMarker) {
        matches.push({ id: refund.id, status: refund.status, created: refund.created });
      }
    }
    if (!page.has_more) {
      completed = true;
      break;
    }
    const lastId = page.data.at(-1)?.id;
    if (!lastId || lastId === startingAfter) {
      throw new StripeReconciliationUnavailableError('Stripe reconciliation pagination is invalid');
    }
    startingAfter = lastId;
  }
  if (!completed) {
    throw new StripeReconciliationUnavailableError('Stripe reconciliation exceeded its safe read bound');
  }

  const observed = {
    version: 1,
    provider: 'stripe',
    resource: 'refund',
    account: input.stripeAccount ?? 'credential-owner',
    marker: input.providerMarker,
    created_gte: createdGte,
    pages,
    matches: matches.map(({ id, status, created }) => ({ id_hash: sha256(id), status, created })),
  };
  const evidenceHash = `sha256:${sha256(canonicalize(observed))}` as const;
  if (matches.length === 0) return { state: 'not_found', evidenceHash, observedCount: 0 };
  if (matches.length === 1) {
    if (!matches[0]!.status) {
      throw new StripeReconciliationUnavailableError('Stripe refund status is unavailable');
    }
    return {
      state: 'confirmed',
      evidenceHash,
      resourceHash: `sha256:${sha256(matches[0]!.id)}`,
      providerStatus: matches[0]!.status,
      observedCount: 1,
    };
  }
  return { state: 'contradictory', evidenceHash, observedCount: matches.length };
}

function stripeCredentialToken(credential: string | Record<string, string>): string | null {
  if (typeof credential === 'string') return credential.trim() || null;
  for (const key of ['api_key', 'access_token', 'token', 'secret_key']) {
    const value = credential[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

async function parseStripeRefundPage(response: Response): Promise<{
  data: Array<{
    id: string;
    status: StripeRefundStatus | null;
    created: number | null;
    metadata: Record<string, string> | null;
  }>;
  has_more: boolean;
}> {
  let value: unknown;
  try { value = await response.json(); } catch {
    throw new StripeReconciliationUnavailableError('Stripe reconciliation response is invalid');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new StripeReconciliationUnavailableError('Stripe reconciliation response is invalid');
  }
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record['data']) || typeof record['has_more'] !== 'boolean') {
    throw new StripeReconciliationUnavailableError('Stripe reconciliation response is invalid');
  }
  const data = record['data'].map((candidate) => {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      throw new StripeReconciliationUnavailableError('Stripe refund record is invalid');
    }
    const refund = candidate as Record<string, unknown>;
    if (typeof refund['id'] !== 'string' || !/^re_[A-Za-z0-9]+$/.test(refund['id'])) {
      throw new StripeReconciliationUnavailableError('Stripe refund record is invalid');
    }
    const metadata = refund['metadata'];
    return {
      id: refund['id'],
      status: isStripeRefundStatus(refund['status']) ? refund['status'] : null,
      created: typeof refund['created'] === 'number' && Number.isSafeInteger(refund['created'])
        ? refund['created']
        : null,
      metadata: metadata && typeof metadata === 'object' && !Array.isArray(metadata)
        ? Object.fromEntries(Object.entries(metadata as Record<string, unknown>)
          .filter((entry): entry is [string, string] => typeof entry[1] === 'string'))
        : null,
    };
  });
  return { data, has_more: record['has_more'] };
}

function isStripeRefundStatus(
  value: unknown,
): value is StripeRefundStatus {
  return typeof value === 'string'
    && ['pending', 'requires_action', 'succeeded', 'failed', 'canceled'].includes(value);
}
