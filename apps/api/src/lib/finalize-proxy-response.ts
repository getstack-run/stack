import { CREDENTIAL_TEMPLATES } from '@stack/shared';
import type { ProxyResult } from '@stack/vault';
import type { DetectorService, ScanOutputResult } from '@stack/vault';

const REDACTION = '[REDACTED BY STACK]';
const SECRET_KEY = /(api[_-]?key|authorization|credential|password|private[_-]?key|refresh[_-]?token|secret|token)/i;

function credentialSecrets(
  service: string,
  rawCredential: string,
  injectedAuthHeaders: Record<string, string>,
): string[] {
  const values = new Set<string>();
  try {
    const parsed = JSON.parse(rawCredential);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      const template = CREDENTIAL_TEMPLATES[service.replace(/^custom_/, '')];
      const declaredSecretKeys = new Set(
        template?.fields.filter((field) => field.type === 'secret').map((field) => field.key) ?? [],
      );
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value === 'string' && value.length > 0 && (declaredSecretKeys.has(key) || SECRET_KEY.test(key))) {
          values.add(value);
        }
      }
    } else if (typeof parsed === 'string' && parsed.length > 0) {
      values.add(parsed);
    }
  } catch {
    if (rawCredential.length > 0) values.add(rawCredential);
  }
  for (const value of Object.values(injectedAuthHeaders)) {
    if (!value) continue;
    values.add(value);
    const credentialPart = /^(?:basic|bearer)\s+(.+)$/iu.exec(value)?.[1];
    if (credentialPart) values.add(credentialPart);
  }
  return [...values].sort((left, right) => right.length - left.length);
}

function scrubString(value: string, secrets: readonly string[]): string {
  let scrubbed = value;
  for (const secret of secrets) scrubbed = scrubbed.split(secret).join(REDACTION);
  return scrubbed;
}

function scrubValue(value: unknown, secrets: readonly string[]): unknown {
  if (typeof value === 'string') return scrubString(value, secrets);
  if (Array.isArray(value)) return value.map((entry) => scrubValue(entry, secrets));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
        scrubString(key, secrets),
        scrubValue(entry, secrets),
      ]),
    );
  }
  return value;
}

export interface FinalizeProxyResponseInput {
  detector: Pick<DetectorService, 'scanOutput'>;
  detectorContext: Parameters<DetectorService['scanOutput']>[0]['ctx'];
  response: ProxyResult;
  rawCredential: string;
  injectedAuthHeaders?: Record<string, string>;
  service: string;
  method: string;
}

export interface FinalizedProxyResponse {
  response: ProxyResult;
  scan: ScanOutputResult;
}

/**
 * Produce the only response shape that may be returned or encrypted. Exact
 * injected credential values are removed in every accountability mode. The
 * configured detector policy may additionally replace the response body, and
 * a matched header is omitted rather than retained with suspicious content.
 */
export async function finalizeProxyResponse(input: FinalizeProxyResponseInput): Promise<FinalizedProxyResponse> {
  const bodyText = typeof input.response.body === 'string'
    ? input.response.body
    : JSON.stringify(input.response.body ?? '');
  const scan = await input.detector.scanOutput({
    ctx: input.detectorContext,
    body: bodyText,
    headers: input.response.headers,
    metadata: {
      response_status: input.response.status,
      request_service: input.service,
      request_method: input.method,
    },
  });

  const secrets = credentialSecrets(input.service, input.rawCredential, input.injectedAuthHeaders ?? {});
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input.response.headers)) {
    if (scan.match?.field_path.toLowerCase() === `headers.${name}`.toLowerCase()) continue;
    const scrubbed = scrubString(value, secrets);
    if (scrubbed !== value) continue;
    headers[name.toLowerCase()] = value;
  }

  const body = scrubValue(
    scan.redactedBody !== null ? scan.redactedBody : input.response.body,
    secrets,
  );

  return {
    response: { status: input.response.status, headers, body },
    scan,
  };
}
