import { describe, expect, it, vi } from 'vitest';
import { NotFoundError } from '@stack/shared';
import { registerOperatorReviewRoutes } from './operator-reviews.js';

function fixture(download: (...args: never[]) => unknown) {
  const routes = new Map<string, (...args: never[]) => unknown>();
  const app = {
    get(path: string, _options: unknown, handler: (...args: never[]) => unknown) {
      routes.set(`GET ${path}`, handler);
    },
    post(path: string, _options: unknown, handler: (...args: never[]) => unknown) {
      routes.set(`POST ${path}`, handler);
    },
  };
  registerOperatorReviewRoutes(app as never, { operatorReview: { download } } as never);
  return routes.get('GET /v1/missions/:id/operator-reviews/:claim_id/download')!;
}

function replyFixture() {
  const headers = new Map<string, string>();
  let sent: unknown;
  const reply = {
    header(name: string, value: string) {
      headers.set(name, value);
      return reply;
    },
    send(value: unknown) {
      sent = value;
      return value;
    },
  };
  return { reply, headers, sent: () => sent };
}

describe('Operator review COSE download', () => {
  it('returns the exact bytes and stable integrity headers', async () => {
    const bytes = Buffer.from([0xd2, 0x84, 0x43, 0xa1]);
    const download = vi.fn(async () => ({ bytes, digest_sha256_base64: 'YWJjZA==' }));
    const handler = fixture(download as never);
    const response = replyFixture();
    await handler({
      params: { id: 'ms_one', claim_id: 'pc_review_one' },
      operatorId: 'op_one',
    } as never, response.reply as never);

    expect(response.sent()).toBe(bytes);
    expect(download).toHaveBeenCalledWith('ms_one', 'pc_review_one', 'op_one');
    expect(response.headers.get('Content-Type')).toBe('application/cose');
    expect(response.headers.get('Content-Disposition')).toBe(
      'attachment; filename="operator-review-ms_one-pc_review_one.cose"',
    );
    expect(response.headers.get('Digest')).toBe('sha-256=YWJjZA==');
    expect(response.headers.get('Content-Length')).toBe(String(bytes.length));
  });

  it.each(['unknown', 'foreign', 'wrong mission', 'wrong type'])('keeps %s lookups as not found', async () => {
    const handler = fixture(vi.fn(async () => { throw new NotFoundError('operator review', 'pc_review_one'); }) as never);
    await expect(handler({
      params: { id: 'ms_one', claim_id: 'pc_review_one' },
      operatorId: 'op_one',
    } as never, replyFixture().reply as never)).rejects.toBeInstanceOf(NotFoundError);
  });
});
