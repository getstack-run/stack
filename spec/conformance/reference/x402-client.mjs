// A reference x402 buyer: reads the requirements of a 402 and builds the
// PAYMENT-SIGNATURE value of spec/agent-site-payments/SPEC.md section 4.
// `pay` is what the `x402` suite takes (`stack-conformance x402 --module`).
// `sign(typedData)` is the wallet: it returns the 0x signature of the
// authorisation in the asset's EIP-712 domain.

import { randomBytes } from 'node:crypto';

export async function pay({ paymentRequired, payer, sign, now, maxAmount }) {
  const entry = paymentRequired.accepts.find((candidate) => candidate.scheme === 'exact' && /^eip155:[0-9]+$/.test(candidate.network));
  if (!entry) throw new Error('no entry of accepts can be paid with the exact scheme');
  if (maxAmount !== undefined && BigInt(entry.amount) > BigInt(maxAmount)) throw new Error(`the price ${entry.amount} is over the maximum ${maxAmount}`);
  const authorization = {
    from: payer,
    to: entry.payTo,
    value: entry.amount,
    validAfter: '0',
    validBefore: String(now + entry.maxTimeoutSeconds),
    nonce: `0x${randomBytes(32).toString('hex')}`,
  };
  const signature = await sign({
    domain: { name: entry.extra.name, version: entry.extra.version, chainId: Number(entry.network.split(':')[1]), verifyingContract: entry.asset },
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
      ],
    },
    primaryType: 'TransferWithAuthorization',
    message: authorization,
  });
  return Buffer.from(JSON.stringify({ x402Version: 2, accepted: entry, payload: { signature, authorization } }), 'utf8').toString('base64');
}

export default pay;
