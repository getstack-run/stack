// Keccak-256 (the original Keccak padding that Ethereum uses, not NIST SHA3-256)
// and the EIP-712 digest of an EIP-3009 TransferWithAuthorization, so the kit
// can check a payload hash without a library of its own.

const MASK = (1n << 64n) - 1n;
const ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROTATIONS = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
];
const rotl = (value, bits) => (bits === 0 ? value : ((value << BigInt(bits)) | (value >> BigInt(64 - bits))) & MASK);

function permute(state) {
  for (let round = 0; round < 24; round += 1) {
    const c = [];
    for (let x = 0; x < 5; x += 1) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y += 1) state[x + 5 * y] ^= d;
    }
    const b = new Array(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROTATIONS[x][y]);
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & MASK & b[((x + 2) % 5) + 5 * y]);
    }
    state[0] ^= ROUND_CONSTANTS[round];
  }
}

/** Keccak-256 of bytes, as a Buffer of 32 bytes. */
export function keccak256(input) {
  const rate = 136;
  const message = Buffer.from(input);
  const padded = Buffer.alloc(Math.ceil((message.length + 1) / rate) * rate);
  message.copy(padded);
  padded[message.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const state = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let lane = 0; lane < rate / 8; lane += 1) state[lane] ^= padded.readBigUInt64LE(offset + lane * 8);
    permute(state);
  }
  const out = Buffer.alloc(32);
  for (let lane = 0; lane < 4; lane += 1) out.writeBigUInt64LE(state[lane], lane * 8);
  return out;
}

const word = (value) => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
const addressWord = (value) => Buffer.from(value.slice(2).toLowerCase().padStart(64, '0'), 'hex');
const utf8 = (text) => Buffer.from(text, 'utf8');

/** The EIP-712 digest of a TransferWithAuthorization in the given domain, as `0x` and 64 hexadecimal digits. */
export function transferAuthorizationDigest(domain, message) {
  const domainSeparator = keccak256(Buffer.concat([
    keccak256(utf8('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
    keccak256(utf8(domain.name)),
    keccak256(utf8(domain.version)),
    word(domain.chainId),
    addressWord(domain.verifyingContract),
  ]));
  const structHash = keccak256(Buffer.concat([
    keccak256(utf8('TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)')),
    addressWord(message.from),
    addressWord(message.to),
    word(message.value),
    word(message.validAfter),
    word(message.validBefore),
    Buffer.from(message.nonce.slice(2), 'hex'),
  ]));
  return `0x${keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), domainSeparator, structHash])).toString('hex')}`;
}
