import { StackError, sha256 } from '@stack/shared';

export interface ProxyOperationRatePipeline {
  incr(key: string): ProxyOperationRatePipeline;
  expire(key: string, seconds: number): ProxyOperationRatePipeline;
  exec(): Promise<Array<[Error | null, unknown]> | null>;
}

export interface ProxyOperationRateStore {
  multi(): ProxyOperationRatePipeline;
}

export async function enforceProxyOperationReadRate(input: {
  redis: ProxyOperationRateStore;
  operatorId: string;
  principalId: string;
  includeResponse: boolean;
  now?: Date;
}): Promise<void> {
  const limit = input.includeResponse ? 10 : 60;
  const now = input.now ?? new Date();
  const minute = Math.floor(now.getTime() / 60_000);
  const principalHash = sha256(`${input.operatorId}\0${input.principalId}`);
  const key = `proxy_operation_read:${input.includeResponse ? 'replay' : 'status'}:${principalHash}:${minute}`;
  let result: Array<[Error | null, unknown]> | null;
  try {
    result = await input.redis.multi().incr(key).expire(key, 120).exec();
  } catch {
    throw new StackError('Proxy operation read limit is unavailable', 'SERVICE_UNAVAILABLE', 503);
  }
  const count = Number(result?.[0]?.[1]);
  if (!Number.isFinite(count)) {
    throw new StackError('Proxy operation read limit is unavailable', 'SERVICE_UNAVAILABLE', 503);
  }
  if (count > limit) {
    throw new StackError(
      `Proxy operation ${input.includeResponse ? 'replay' : 'status'} limit exceeded`,
      'RATE_LIMITED',
      429,
    );
  }
}
