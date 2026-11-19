// The reference receiver in reference/authority-receiver.mjs must pass the
// authority suite, as a library and behind a delivery endpoint, and the suite
// must fail receivers that each have one deliberate defect.

import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { commandReceiver, formatReport, runAuthorityReceiverSuite } from '../src/index.mjs';
import { createReceiver } from './authority-receiver.mjs';
import { decodeJws, digest } from '../src/authority-jose.mjs';
import { canonicalize } from '../src/canonical.mjs';
import { listen } from './support.mjs';

const mustFailedIds = (report) => report.results.filter((r) => r.status === 'fail' && r.level === 'MUST').map((r) => r.id);
const failedIds = (report) => report.results.filter((r) => r.status === 'fail').map((r) => r.id);

/** The reference receiver with some of its functions replaced. */
const defective = (replace) => (config) => ({ ...createReceiver(config), ...replace(config, createReceiver(config)) });

describe('authority receiver suite', () => {
  it('passes the reference receiver as a library', async () => {
    const report = await runAuthorityReceiverSuite({ create: createReceiver });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.warnings, formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
    expect(report.passed).toBe(report.results.length);
    expect(report.results.length).toBe(38);
  });

  it('passes the reference receiver with an ES256 request key', async () => {
    const report = await runAuthorityReceiverSuite({ create: createReceiver, requestAlg: 'ES256' });
    expect(report.failed, formatReport(report)).toBe(0);
    expect(report.passed).toBe(report.results.length);
  });

  it('passes the reference receiver run as a program', async () => {
    const program = fileURLToPath(new URL('./authority-receiver-command.mjs', import.meta.url));
    const report = await runAuthorityReceiverSuite({ create: commandReceiver(process.execPath, [program]) });
    expect(report.failed, formatReport(report)).toBe(0);
    // A program has no memory between calls: the one SHOULD about a repeated presentation is a warning.
    expect(failedIds(report)).toEqual(['A48']);
  });

  describe('behind a delivery endpoint', () => {
    let instance;
    let deliveryKey;
    beforeAll(async () => {
      const { fixtureKeys, FIXTURE } = await import('../src/authority-fixtures.mjs');
      const { receiverConfig } = await import('../src/authority-receiver.mjs');
      const keys = fixtureKeys();
      deliveryKey = { kid: keys.encryption.kid, publicJwk: keys.encryption.publicJwk };
      const receiver = createReceiver(receiverConfig(keys));
      const server = createServer((req, res) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', async () => {
          try {
            if (!String(req.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded')) return res.writeHead(415).end();
            const response = new URLSearchParams(Buffer.concat(chunks).toString('utf8')).get('response');
            if (!response) return res.writeHead(400).end();
            const { presentationPayload, requestHashOf, NORMALIZED_REQUEST } = await import('../src/authority-fixtures.mjs');
            await receiver.openPresentation(response, {
              now: Math.floor(Date.now() / 1000),
              expected: { nonce: FIXTURE.nonce, requestHash: requestHashOf(FIXTURE.receiverRequestId, NORMALIZED_REQUEST) },
            });
            void presentationPayload;
            return res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
          } catch {
            return res.writeHead(400).end();
          }
        });
      });
      instance = await listen(server);
    });
    afterAll(() => instance?.close());

    it('passes the reference receiver served over HTTP', async () => {
      const report = await runAuthorityReceiverSuite({ deliveryUrl: `${instance.url}/direct-post`, deliveryKey, timeoutMs: 3000 });
      expect(report.failed, formatReport(report)).toBe(0);
      // The checks that need a function are skipped, never passed.
      expect(report.results.filter((r) => r.status === 'pass').every((r) => r.id.startsWith('U'))).toBe(true);
      expect(report.results.filter((r) => r.status === 'skip').every((r) => r.id.startsWith('A'))).toBe(true);
      expect(report.passed).toBe(20);
    });
  });

  describe('fails a receiver with one defect', () => {
    const run = (create) => runAuthorityReceiverSuite({ create });

    it('one whose assertion is not bound to the body', async () => {
      const ids = mustFailedIds(await run(defective((config, base) => ({
        authorization: (input) => base.authorization({ ...input, body: undefined }),
      }))));
      expect(ids).toEqual(['A04', 'A08']);
    });

    it('one that reuses the jti of the call in the signed request', async () => {
      let last;
      const ids = mustFailedIds(await run(defective((config, base) => ({
        authorization: (input) => {
          const header = base.authorization(input);
          last = decodeJws(header.slice('STACK-Receiver '.length)).payload.jti;
          return header;
        },
        signPresentationRequest: (fields, options) => {
          const compact = base.signPresentationRequest(fields, options);
          return compact && last ? swapJti(compact, last, config) : compact;
        },
      }))));
      expect(ids).toContain('A13');
    });

    it('one that commits the result with a fixed nonce', async () => {
      const fixed = 'AAAAAAAAAAAAAAAAAAAAAA';
      const ids = mustFailedIds(await run(defective((config, base) => ({
        signReceipt: (input) => resign(base.signReceipt(input), config, { result_commitment_nonce: fixed, result_hash: digest(canonicalize({ value: input.result, commitment_nonce: fixed })) }),
      }))));
      expect(ids).toEqual(['A24']);
    });

    it('one that does not hash the presentation it received', async () => {
      const ids = mustFailedIds(await run(defective((config, base) => ({
        signReceipt: (input) => resign(base.signReceipt(input), config, { presentation_payload_hash: digest('nothing') }),
      }))));
      expect(ids).toEqual(['A21']);
    });

    it('one that checks nothing when it opens a presentation', async () => {
      const ids = mustFailedIds(await run(defective((config) => ({
        openPresentation: async (jwe) => {
          const { decryptJwe, privateKeyFromJwk } = await import('../src/authority-jose.mjs');
          try {
            return decodeJws(decryptJwe(jwe, privateKeyFromJwk(config.encryptionKey.privateJwk)).plaintext).payload;
          } catch {
            return decodeJws(jwe.split('.').slice(0, 3).join('.'))?.payload ?? null;
          }
        },
      }))));
      expect(ids).toEqual(expect.arrayContaining(['A36', 'A37', 'A38', 'A40', 'A41', 'A42', 'A43', 'A44', 'A45', 'A46', 'A47']));
    });

    it('one that accepts the unsigned presentation (alg none)', async () => {
      const ids = mustFailedIds(await run(defective((config, base) => ({
        openPresentation: async (jwe, options) => {
          try {
            return await base.openPresentation(jwe, options);
          } catch (error) {
            const { decryptJwe, privateKeyFromJwk } = await import('../src/authority-jose.mjs');
            const plain = decryptJwe(jwe, privateKeyFromJwk(config.encryptionKey.privateJwk)).plaintext;
            const decoded = decodeJws(plain);
            if (decoded?.header.alg === 'none') return decoded.payload;
            throw error;
          }
        },
      }))));
      expect(ids).toEqual(['A38']);
    });

    it('one that does not remember a presentation (a SHOULD)', async () => {
      const report = await run(defective((config) => ({
        openPresentation: async (jwe, options) => {
          const fresh = createReceiver(config);
          return fresh.openPresentation(jwe, options);
        },
      })));
      expect(report.conforms, formatReport(report)).toBe(true);
      expect(failedIds(report)).toEqual(['A48']);
    });
  });
});

function swapJti(compact, jti, config) {
  return resign(compact, config, { jti }, 'request');
}

/** Re-sign a compact JWS from the reference with changed claims, as a defective receiver would have produced it. */
function resign(compact, config, changes, which = 'receipt') {
  const decoded = decodeJws(compact);
  const material = which === 'request' ? config.requestKey : config.receiptKey;
  return signWith(material, { ...decoded.payload, ...changes });
}

import { privateKeyFromJwk, signJws } from '../src/authority-jose.mjs';
function signWith(material, payload) {
  return signJws({ alg: material.alg, kid: material.kid, typ: 'JWT' }, payload, privateKeyFromJwk(material.privateJwk), material.alg);
}
