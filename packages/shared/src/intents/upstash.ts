import { z } from 'zod';
import type { Constraint } from '../schemas/passport.js';
import { defineIntent } from './types.js';

// Upstash — two distinct planes.
//   Data plane (Redis REST): https://{endpoint}.upstash.io/{cmd}/{key}/…
//     Commands are encoded as the first path segment (GET, SET, DEL,
//     EXPIRE, INCR, SADD, HSET, LPUSH, XADD, …). Upstash accepts either
//     GET (readonly) or POST — intents bind on pathname only.
//   Management plane: https://api.upstash.com/v2/…
//     (databases, kafka topics, teams). Intents bind on path + method.

const keyPrefix = z.string().min(1).max(256);
const prefixList = z.union([keyPrefix, z.array(keyPrefix).min(1)]);
type PrefixList = z.infer<typeof prefixList>;
const toList = (v: PrefixList): string[] => (Array.isArray(v) ? v : [v]);

function cmdConstraint(cmds: string[], prefix?: PrefixList): Constraint {
  const cmdAlt = cmds.join('|');
  if (!prefix) {
    return { path: 'url.pathname', op: 'matches', value: `^/(${cmdAlt})(/.+)?$` };
  }
  const list = toList(prefix);
  const esc = list.map((t) => t.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'));
  const alt = list.length === 1 ? esc[0]! : `(${esc.join('|')})`;
  return { path: 'url.pathname', op: 'matches', value: `^/(${cmdAlt})/${alt}[^/]*(/.+)?$` };
}

export const upstashIntents = [
  defineIntent({
    name: 'upstash.redis_get',
    effect: 'read',
    description:
      'Read a value by key via Upstash Redis REST. Binds GET /GET/{key} optionally restricted to a key prefix.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['GET', 'MGET', 'GETRANGE', 'GETSET', 'STRLEN'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_set',
    effect: 'write',
    description:
      'Write a value by key via Upstash Redis REST. Binds POST /SET/{key}/{value} optionally restricted to a key prefix.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['SET', 'MSET', 'SETEX', 'PSETEX', 'SETNX', 'SETRANGE', 'APPEND'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_del',
    effect: 'destructive',
    description:
      'Delete a key via Upstash Redis REST. Binds POST /DEL/{key} optionally restricted to a key prefix. Destructive.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['DEL', 'UNLINK'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_expire',
    effect: 'write',
    description:
      'Set a TTL on a Redis key. Binds POST /EXPIRE/{key}/{seconds} optionally restricted to a key prefix.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['EXPIRE', 'PEXPIRE', 'EXPIREAT', 'PEXPIREAT', 'PERSIST'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_incr',
    effect: 'write',
    description:
      'Atomically increment a numeric value. Binds POST /INCR/{key} and related counters.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['INCR', 'DECR', 'INCRBY', 'DECRBY', 'INCRBYFLOAT'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_set_ops',
    effect: 'write',
    description:
      'Add, remove, or query Redis set members. Binds SADD/SREM/SMEMBERS/SISMEMBER/SCARD.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['SADD', 'SREM', 'SMEMBERS', 'SISMEMBER', 'SCARD', 'SPOP', 'SRANDMEMBER'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_hash_ops',
    effect: 'write',
    description:
      'Read and write Redis hash fields. Binds HGET/HSET/HDEL/HGETALL/HINCRBY.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['HGET', 'HSET', 'HMSET', 'HMGET', 'HDEL', 'HGETALL', 'HKEYS', 'HVALS', 'HINCRBY', 'HEXISTS', 'HLEN'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_list_ops',
    effect: 'write',
    description:
      'Push, pop, and query Redis lists. Binds LPUSH/RPUSH/LPOP/RPOP/LRANGE/LLEN.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['LPUSH', 'RPUSH', 'LPOP', 'RPOP', 'LRANGE', 'LLEN', 'LINDEX', 'LREM', 'LTRIM'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_stream_ops',
    effect: 'write',
    description:
      'Append to and read from Redis streams. Binds XADD/XREAD/XRANGE/XLEN/XDEL.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['XADD', 'XREAD', 'XRANGE', 'XREVRANGE', 'XLEN', 'XDEL', 'XTRIM', 'XACK', 'XGROUP'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_pubsub',
    effect: 'write',
    description:
      'Publish to Redis pub/sub channels. Binds POST /PUBLISH/{channel}.',
    params: z.object({ prefix: prefixList.optional() }),
    expand: ({ prefix }) => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      cmdConstraint(['PUBLISH', 'PUBSUB'], prefix),
    ],
  }),

  defineIntent({
    name: 'upstash.redis_pipeline',
    effect: 'write',
    description:
      'Execute a pipelined batch of Redis commands. Binds POST /pipeline and /multi-exec.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/(pipeline|multi-exec)$' },
    ],
  }),

  defineIntent({
    name: 'upstash.redis_scan',
    effect: 'read',
    description:
      'Iterate Redis keys with SCAN or KEYS. Binds SCAN, HSCAN, SSCAN, KEYS.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'in', value: ['GET', 'POST'] },
      { path: 'url.pathname', op: 'matches', value: '^/(SCAN|HSCAN|SSCAN|ZSCAN|KEYS)(/.+)?$' },
    ],
  }),

  defineIntent({
    name: 'upstash.mgmt_list_databases',
    effect: 'read',
    description:
      'List Upstash Redis databases on the account via the management API. Binds GET /v2/redis/databases.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/redis/databases' },
    ],
  }),

  defineIntent({
    name: 'upstash.mgmt_create_database',
    effect: 'write',
    description:
      'Create a new Upstash Redis database. Binds POST /v2/redis/database.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/redis/database' },
    ],
  }),

  defineIntent({
    name: 'upstash.mgmt_delete_database',
    effect: 'destructive',
    description:
      'Delete an Upstash Redis database by id. Binds DELETE /v2/redis/database/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/redis/database/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'upstash.mgmt_reset_password',
    effect: 'write',
    description:
      'Reset the password for an Upstash Redis database. Binds POST /v2/redis/reset-password/{id}. Sensitive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/redis/reset-password/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'upstash.kafka_list_topics',
    effect: 'read',
    description:
      'List Kafka topics on the account. Binds GET /v2/kafka/topics.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/kafka/topics' },
    ],
  }),

  defineIntent({
    name: 'upstash.kafka_create_topic',
    effect: 'write',
    description:
      'Create a new Kafka topic. Binds POST /v2/kafka/topic.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'POST' },
      { path: 'url.pathname', op: 'eq', value: '/v2/kafka/topic' },
    ],
  }),

  defineIntent({
    name: 'upstash.kafka_delete_topic',
    effect: 'destructive',
    description:
      'Delete a Kafka topic by id. Binds DELETE /v2/kafka/topic/{id}. Destructive.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'DELETE' },
      { path: 'url.pathname', op: 'matches', value: '^/v2/kafka/topic/[^/]+$' },
    ],
  }),

  defineIntent({
    name: 'upstash.mgmt_list_teams',
    effect: 'read',
    description:
      'List teams on the Upstash account. Binds GET /v2/teams.',
    params: z.object({}),
    expand: () => [
      { path: 'method', op: 'eq', value: 'GET' },
      { path: 'url.pathname', op: 'eq', value: '/v2/teams' },
    ],
  }),
];
