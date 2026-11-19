// A network implementation as a program: one JSON object on stdin, one on stdout
// (the command interface of the `network-verifier` suite). This one is the SDK
// behind that interface; a program in any language does the same.

import * as sdk from '@getstackrun/sdk';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const message = JSON.parse(Buffer.concat(chunks).toString('utf8'));

async function main() {
  if (message.op === 'verify') {
    const options = { jwks: message.jwks, now: new Date(message.now * 1000) };
    try {
      if (message.kind === 'countersignature') await sdk.verifyCountersignedPassport({ countersignature: message.token, passport: message.passport, ...options });
      else if (message.kind === 'revocation_list') await sdk.verifyRevocationList(message.token, options);
      else if (message.kind === 'verified') await sdk.verifyVerifiedStatement(message.token, options);
      else await sdk.verifyDetectionRules(message.token, { ...options, ...(message.held_revision !== undefined ? { heldRevision: message.held_revision } : {}) });
      return { valid: true };
    } catch {
      return { valid: false };
    }
  }
  if (message.op === 'revoked') {
    try {
      const list = await sdk.verifyRevocationList(message.token, { jwks: message.jwks, now: new Date(message.now * 1000) });
      const held = message.held;
      return { revoked: sdk.revocationCovers(list.entries, { install: held.install, keyId: held.key_id, passportDigest: held.passport_digest, agent: held.agent }) !== undefined };
    } catch {
      return { revoked: false };
    }
  }
  const key = await sdk.InstallKey.fromPem(message.private_key_pem);
  const now = new Date(message.now * 1000);
  if (message.op === 'key_proof') return { token: await key.signKeyProof(message.install_id, message.nonce, { now }) };
  if (message.op === 'proof') return { token: await key.signProof(message.install_id, message.claims, { now }) };
  return { unsupported: true };
}

process.stdout.write(JSON.stringify(await main()));
