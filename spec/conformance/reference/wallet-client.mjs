// A reference wallet client: builds the typed data of spec/wallet-relay/SPEC.md
// section 5.1 and has the signing string of section 4 signed, with the one
// helper the SDK publishes for the string (`walletPaymentAuthorizationPayload`).
// `build` is what the `wallet` suite takes (`stack-conformance wallet --module`).

import { walletPaymentAuthorizationPayload } from '@getstackrun/sdk';

const MAX_AUTHORIZATION_SECONDS = 600;

export function build({ appId, walletId, from, to, valueAtomic, validAfter, validBefore, nonce, sign }) {
  if (Number(validBefore) > Math.floor(Date.now() / 1000) + MAX_AUTHORIZATION_SECONDS) {
    throw new Error(`an authorisation must expire within ${MAX_AUTHORIZATION_SECONDS} seconds: the relay refuses a longer one`);
  }
  const typedData = {
    domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
      ],
    },
    primary_type: 'TransferWithAuthorization',
    message: { from, to, value: String(valueAtomic), validAfter: String(validAfter), validBefore: String(validBefore), nonce },
  };
  return { typed_data: typedData, agent_signature: sign(walletPaymentAuthorizationPayload({ appId, walletId, typedData })) };
}

export default build;
