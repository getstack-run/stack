import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
// The kit is plain JavaScript with no declarations.
// @ts-expect-error TS7016
import * as conformanceKit from '../../../../spec/conformance/src/index.mjs';
import { isClientMetadataUrl, validateClientMetadataDocument } from './oauth-cimd.js';

/**
 * The engine's check of a client metadata document against the conformance kit's `oauth-client-metadata` suite
 * (spec/oauth-profile, sections 4.1 and 4.3).
 */

type Report = { conforms: boolean; failed: number; warnings: number; skipped: number };
type Kit = {
  runClientMetadataSuite(options: { validate: (clientId: string, document: unknown) => unknown; isMetadataClientId: (clientId: string) => boolean }): Promise<Report>;
  formatReport(report: Report): string;
};

describe('the engine\'s client metadata document check', () => {
  it('passes the oauth-client-metadata suite', async () => {
    const kit = conformanceKit as unknown as Kit;
    const report = await kit.runClientMetadataSuite({
      validate: (clientId, document) => validateClientMetadataDocument(clientId, document),
      isMetadataClientId: isClientMetadataUrl,
    });
    expect(report.failed, kit.formatReport(report)).toBe(0);
    expect(report.warnings, kit.formatReport(report)).toBe(0);
    expect(report.skipped).toBe(0);
  });

  it('gives the verdict of every test vector', () => {
    const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../../../../spec/conformance/fixtures/identity/vectors.json', import.meta.url)), 'utf8')) as {
      client_metadata: {
        cases: Array<{ name: string; valid: boolean; client_id: string; document: unknown }>;
        client_ids: Array<{ client_id: string; metadata_document_url: boolean }>;
      };
    };
    for (const c of vectors.client_metadata.cases) {
      let valid = true;
      try {
        validateClientMetadataDocument(c.client_id, c.document);
      } catch {
        valid = false;
      }
      expect(valid, c.name).toBe(c.valid);
    }
    for (const c of vectors.client_metadata.client_ids) expect(isClientMetadataUrl(c.client_id), c.client_id).toBe(c.metadata_document_url);
  });
});
