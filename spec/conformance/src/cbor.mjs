// A small CBOR (RFC 8949) encoder and decoder, enough for COSE_Sign1 messages and the claim envelopes of the
// Record Format: unsigned and negative integers, byte and text strings, arrays, maps, tags, booleans, null.
// The kit judges implementations with nothing but node:crypto, so it carries its own.
//
// Decoded values: integers are numbers (or BigInt past 2^53), byte strings are Buffers, text strings are
// strings, arrays are arrays, maps are `Map`s (keys may be integers), a tag is `{ tag, value }`.

export class Tagged {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

/** A number to be written as an IEEE 754 double (as the reference producer writes millisecond timestamps). */
export class Float64 {
  constructor(value) {
    this.value = value;
  }
}

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  if (n < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = (major << 5) | 27;
  b.writeBigUInt64BE(BigInt(n), 1);
  return b;
}

/** Encode a value. Plain objects are encoded as maps with text keys in insertion order. */
export function encode(value) {
  if (value === null || value === undefined) return Buffer.from([0xf6]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('the kit encodes integers only');
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === 'bigint') return value >= 0n ? head(0, Number(value)) : head(1, Number(-1n - value));
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(2, bytes.length), bytes]);
  }
  if (value instanceof Float64) {
    const b = Buffer.alloc(9);
    b[0] = 0xfb;
    b.writeDoubleBE(value.value, 1);
    return b;
  }
  if (value instanceof Tagged) return Buffer.concat([head(6, value.tag), encode(value.value)]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value instanceof Map) {
    return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encode(k), encode(v)])]);
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined);
    return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [encode(k), encode(v)])]);
  }
  throw new Error(`cannot encode ${typeof value}`);
}

/** Decode one value from the start of `bytes`; the whole input must be consumed. */
export function decode(bytes) {
  const buffer = Buffer.from(bytes);
  const state = { offset: 0 };
  const value = read(buffer, state);
  if (state.offset !== buffer.length) throw new Error('trailing bytes after the CBOR value');
  return value;
}

function readArgument(buffer, state, info) {
  if (info < 24) return info;
  const need = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
  if (!need) throw new Error('unsupported CBOR length');
  if (state.offset + need > buffer.length) throw new Error('truncated CBOR');
  let n;
  if (need === 1) n = buffer[state.offset];
  else if (need === 2) n = buffer.readUInt16BE(state.offset);
  else if (need === 4) n = buffer.readUInt32BE(state.offset);
  else {
    const big = buffer.readBigUInt64BE(state.offset);
    n = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
  }
  state.offset += need;
  return n;
}

function read(buffer, state) {
  if (state.offset >= buffer.length) throw new Error('truncated CBOR');
  const initial = buffer[state.offset++];
  const major = initial >> 5;
  const info = initial & 0x1f;
  if (major === 7) {
    if (info === 20) return false;
    if (info === 21) return true;
    if (info === 22 || info === 23) return null;
    if (info === 25 || info === 26 || info === 27) {
      const size = { 25: 2, 26: 4, 27: 8 }[info];
      if (state.offset + size > buffer.length) throw new Error('truncated CBOR');
      let value;
      if (info === 25) {
        const half = buffer.readUInt16BE(state.offset);
        const exponent = (half >> 10) & 0x1f;
        const fraction = half & 0x3ff;
        value = exponent === 0 ? fraction * 2 ** -24 : exponent === 31 ? (fraction ? NaN : Infinity) : (fraction + 1024) * 2 ** (exponent - 25);
        if (half & 0x8000) value = -value;
      } else if (info === 26) value = buffer.readFloatBE(state.offset);
      else value = buffer.readDoubleBE(state.offset);
      state.offset += size;
      return value;
    }
    throw new Error('unsupported CBOR simple value');
  }
  if (info === 31) throw new Error('indefinite-length CBOR is not supported');
  const n = readArgument(buffer, state, info);
  switch (major) {
    case 0:
      return n;
    case 1:
      return typeof n === 'bigint' ? -1n - n : -1 - n;
    case 2:
    case 3: {
      if (typeof n === 'bigint' || state.offset + n > buffer.length) throw new Error('truncated CBOR');
      const slice = buffer.subarray(state.offset, state.offset + n);
      state.offset += n;
      return major === 2 ? Buffer.from(slice) : slice.toString('utf8');
    }
    case 4: {
      const out = [];
      for (let i = 0; i < n; i++) out.push(read(buffer, state));
      return out;
    }
    case 5: {
      const out = new Map();
      for (let i = 0; i < n; i++) {
        const k = read(buffer, state);
        out.set(k, read(buffer, state));
      }
      return out;
    }
    case 6:
      return new Tagged(n, read(buffer, state));
    default:
      throw new Error('unsupported CBOR type');
  }
}

/** Strip a tag, if the value has one. */
export function untag(value) {
  return value instanceof Tagged ? value.value : value;
}
