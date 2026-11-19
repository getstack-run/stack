import { Resolver } from 'node:dns/promises';
import { SSO_DOMAIN_LOOKUP_TIMEOUT_SECONDS } from '@stack/shared';

/**
 * Reads the TXT records at a DNS name. It answers with the records (each one the strings the name server split it into),
 * or throws `DnsNameAbsentError` when the name server said there is no such name or no such record, and throws anything
 * else (a timeout, a refused or failed query, an unreachable server) as an ordinary error. The caller must treat the
 * first as "the record is not there" and the second as "no answer", never the other way round: a lookup that fails is
 * not evidence that a record is gone, and is never evidence that it is there.
 */
export interface DnsTxtResolver {
  resolveTxt(name: string): Promise<string[][]>;
}

/** The name server answered that the name, or a TXT record at it, does not exist. */
export class DnsNameAbsentError extends Error {
  constructor(name: string) {
    super(`no TXT record at ${name}`);
    this.name = 'DnsNameAbsentError';
  }
}

// Node reports NXDOMAIN as ENOTFOUND and an empty answer as ENODATA; every other code is a failure to get an answer.
const ABSENT_CODES = new Set(['ENOTFOUND', 'ENODATA']);

export interface SystemDnsTxtResolverOptions {
  /** Name servers to ask (addresses), in place of the machine's own resolver. Empty or unset: the machine's. */
  servers?: readonly string[];
  /** The longest the lookup may take, in milliseconds. */
  timeoutMs?: number;
}

/**
 * The machine's own resolver (or the servers an install names). A lookup is one query with a hard time limit, so a
 * name server that does not answer cannot hold a sign-in or an upkeep pass.
 */
export function systemDnsTxtResolver(options: SystemDnsTxtResolverOptions = {}): DnsTxtResolver {
  const timeoutMs = options.timeoutMs ?? SSO_DOMAIN_LOOKUP_TIMEOUT_SECONDS * 1000;
  return {
    async resolveTxt(name: string): Promise<string[][]> {
      const resolver = new Resolver({ timeout: Math.max(1, Math.floor(timeoutMs / 2)), tries: 2 });
      if (options.servers && options.servers.length > 0) resolver.setServers([...options.servers]);
      let timer: NodeJS.Timeout | undefined;
      const limit = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          resolver.cancel();
          reject(new Error(`the lookup of ${name} timed out`));
        }, timeoutMs);
      });
      try {
        return await Promise.race([resolver.resolveTxt(name), limit]);
      } catch (error) {
        const code = (error as { code?: unknown } | null)?.code;
        if (typeof code === 'string' && ABSENT_CODES.has(code)) throw new DnsNameAbsentError(name);
        throw error;
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
  };
}
