import { readFileSync } from 'node:fs';

/**
 * The settings that carry a secret and may be given as a file instead of a
 * value: `NAME_FILE=/run/secrets/name` fills `NAME` with the file's content.
 * This is how a Docker or Kubernetes secret reaches a process without the
 * secret appearing in its environment listing or in the orchestrator's config.
 * Only these names are read this way; nothing else in the environment can be
 * redirected to a file.
 */
export const SECRET_FILE_SETTINGS = [
  'API_KEY_PEPPER',
  'DATABASE_URL',
  'REDIS_URL',
  'SESSION_SIGNING_KEY',
  'STACK_KEY_ENCRYPTION_KEY',
  'STACK_LICENCE_KEY',
  'STACK_NETWORK_KEY',
  'STACK_INTENT_MODEL_KEY',
  'STACK_SIEM_HTTP_TOKEN',
  'MCP_ELICITATION_ATTESTATION_KEY',
  'SMTP_PASSWORD',
  'SMTP_URL',
  'RESEND_API_KEY',
  'OPENROUTER_API_KEY',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
] as const;

/**
 * Read each `NAME_FILE` that is set and put its content in `NAME`. A setting
 * given both ways is refused (which one wins must not depend on read order),
 * and an unreadable file stops the boot with the setting named, never the path
 * of a secret's content. A trailing newline is dropped.
 */
export function loadSecretFiles(
  env: Record<string, string | undefined> = process.env,
  names: readonly string[] = SECRET_FILE_SETTINGS,
): string[] {
  const loaded: string[] = [];
  for (const name of names) {
    const file = env[`${name}_FILE`]?.trim();
    if (!file) continue;
    if (env[name]) throw new Error(`[BOOT] Set ${name} or ${name}_FILE, not both`);
    let content: string;
    try {
      content = readFileSync(file, 'utf8');
    } catch {
      throw new Error(`[BOOT] ${name}_FILE cannot be read`);
    }
    env[name] = content.replace(/\r?\n$/, '');
    loaded.push(name);
  }
  return loaded;
}
