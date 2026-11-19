// The SDK's x402 buyer (`payX402` and the pieces it is made of) against the kit: it passes the x402 buyer checks, and
// it buys from the reference site in one call with the payment STACK would hand back.

import { afterAll, describe, expect, it } from 'vitest';
import { generateAgentWalletKey, payX402, readX402Ask, x402PaymentHeader, x402TransferTypedData } from '@getstackrun/sdk';
import { formatReport, runX402Suite } from '../src/index.mjs';
import { serveX402Site } from './x402-site-server.mjs';

/** The SDK's builder as the suite takes a buyer: it signs with the kit's wallet. */
async function sdkBuyer({ paymentRequiredHeader, payer, sign, now, maxAmount }) {
  const ask = readX402Ask({ paymentRequiredHeader });
  if (maxAmount !== undefined && BigInt(ask.requirement.amount) > BigInt(maxAmount)) throw new Error('over the maximum');
  const typedData = x402TransferTypedData({ requirement: ask.requirement, from: payer, nowSeconds: now });
  const signature = await sign({ domain: typedData.domain, types: typedData.types, primaryType: typedData.primary_type, message: typedData.message });
  return x402PaymentHeader({ ask, typedData, signature }).value;
}

describe('the SDK x402 buyer', () => {
  const closers = [];
  afterAll(() => Promise.all(closers.map((close) => close())));

  it('passes the x402 buyer checks, apart from paying on the Base test network, which the wallet never does', async () => {
    const report = await runX402Suite({ pay: sdkBuyer });
    // XC05 asks a buyer to sign for the USDC of Base Sepolia (eip155:84532). The agent wallet pays USDC on Base only,
    // and STACK refuses anything else, so the SDK refuses the entry before anything is signed; the domain it signs for
    // Base itself is checked by the other checks and by the SDK's own tests.
    expect(report.results.filter((r) => r.status === 'fail').map((r) => r.id), formatReport(report)).toEqual(['XC05']);
    expect(report.passed).toBeGreaterThanOrEqual(6);
    const sepolia = Buffer.from(JSON.stringify({ x402Version: 2, accepts: [{
      scheme: 'exact', network: 'eip155:84532', amount: '1', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
      payTo: '0x5555555555555555555555555555555555555555', extra: { name: 'USDC', version: '2' },
    }] })).toString('base64');
    expect(() => readX402Ask({ paymentRequiredHeader: sepolia })).toThrow(/only USDC on Base/);
  });

  it('buys from the reference site in one call', async () => {
    const site = await serveX402Site({});
    closers.push(site.close);
    const payments = [];
    const result = await payX402(site.url, {
      key: generateAgentWalletKey(),
      wallet: { address: '0x1111111111111111111111111111111111111111', walletId: 'wal_1', appId: 'app_1' },
      // What STACK hands back once the wallet signed: the reference site's facilitator accepts any well-formed signature.
      pay: async (input) => {
        payments.push(input);
        return { payment_id: 'wpay_1', signature: `0x${'ab'.repeat(65)}`, amount_atomic: '250000', amount_cents: 25 };
      },
    });
    expect(result.paid).toBe(true);
    expect(result.response.status).toBe(200);
    expect(result.settlement).toMatchObject({ success: true });
    expect(payments).toHaveLength(1);
    expect(payments[0].typed_data.message).toMatchObject({ to: '0x5555555555555555555555555555555555555555', value: '250000' });
  });
});
