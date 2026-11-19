import type { KmsService } from '@stack/vault';

/**
 * Dev-only mock KMS: base64, no encryption. It stands in for the real
 * `KmsService` in two places:
 *
 *   - the drop-off, skill-invocation and skill-review services, which only ever
 *     delete the ciphertext they hold and never surface it;
 *   - the mission claim signer bootstrap, which needs a `KmsService` shape even
 *     when `AWS_KMS_KEY_ID` is not set. Production refuses to boot without a
 *     signing key (`boot/signing.ts`), so the mock never signs anything real.
 *
 * Anything that re-encrypts or persists customer data must use the real
 * `KmsService` instead (see `boot/cmek.ts`). This mirrors the API's private
 * `createDevKms` in `apps/api/src/config/wiring/infra.ts`; `@stack/vault` does not
 * export one, so there is nothing shared to import.
 */
export function createDevKms(): KmsService {
  return {
    async encrypt(plaintext: string) {
      return { ciphertext: Buffer.from(plaintext).toString('base64'), keyRef: 'dev-key' };
    },
    async decrypt(ciphertext: string) {
      return Buffer.from(ciphertext, 'base64').toString('utf8');
    },
    async encryptDirect(plaintext: Buffer) {
      return plaintext;
    },
    async decryptDirect(ciphertext: Buffer) {
      return ciphertext;
    },
    async smokeTestCustomerKey() {},
    setOperatorKeyHandlers() {},
  } as unknown as KmsService;
}
