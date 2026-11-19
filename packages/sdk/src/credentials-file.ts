// Shared read/write helpers for ~/.stack/credentials.json.
//
// Same file the CLI's `auth login` writes; same file the SDK's
// browser-bootstrap writes. Read by client.ts on every static-bearer
// resolve. Centralized here so the on-disk shape stays consistent
// across all three writers.

export interface StoredCredentials {
  client_id: string;
  refresh_token: string;
  issued_at: number;
  refresh_expires_at: number;
  operator_email?: string;
  scope: string;
}

export async function credentialsFilePath(): Promise<string> {
  const { homedir } = await import('node:os');
  const { join } = await import('node:path');
  return join(homedir(), '.stack', 'credentials.json');
}

export async function readCredentialsFile(): Promise<StoredCredentials | null> {
  try {
    const { readFile } = await import('node:fs/promises');
    const path = await credentialsFilePath();
    const raw = await readFile(path, 'utf8');
    const parsed: unknown = JSON.parse(raw);
    // A file that cannot sign anyone in is no sign-in at all (spec/credentials-files).
    if (parsed === null || typeof parsed !== 'object') return null;
    const { client_id: clientId, refresh_token: refreshToken } = parsed as Record<string, unknown>;
    if (typeof clientId !== 'string' || clientId === '' || typeof refreshToken !== 'string' || refreshToken === '') return null;
    return parsed as StoredCredentials;
  } catch {
    return null;
  }
}

export async function writeCredentialsFile(creds: StoredCredentials): Promise<void> {
  const { mkdir, writeFile, chmod } = await import('node:fs/promises');
  const { join, dirname } = await import('node:path');
  const { homedir } = await import('node:os');
  const path = join(homedir(), '.stack', 'credentials.json');
  await mkdir(dirname(path), { recursive: true });
  // Created readable by the owner only: the refresh token is a bearer secret, and a file made with the default mode is
  // readable by others until the chmod below runs.
  await writeFile(path, JSON.stringify(creds, null, 2), { encoding: 'utf8', mode: 0o600 });
  try {
    await chmod(path, 0o600);
  } catch {
    /* Windows / unsupported FS — default ACL on %USERPROFILE%\.stack is user-scoped */
  }
}

const LOCK_ACQUIRE_TIMEOUT_MS = 5_000;
const LOCK_RETRY_INTERVAL_MS = 50;
const LOCK_STALE_MS = 30_000;

/**
 * Run `work` holding `~/.stack/credentials.lock` (spec/credentials-files, section 5), so that two processes do not post the
 * same refresh token and have the server end the whole family. The lock is an exclusive create; a lock older than 30 seconds
 * is a dead holder's; a client that cannot take it (a permission, the wait of 5 seconds) goes on without it. `work` must
 * read the credentials file again itself: the holder before it may have rotated the token.
 */
export async function withCredentialsLock<T>(work: () => Promise<T>): Promise<T> {
  const { mkdir, writeFile, stat, unlink } = await import('node:fs/promises');
  const { dirname, join } = await import('node:path');
  const path = await credentialsFilePath();
  const lockPath = join(dirname(path), 'credentials.lock');
  await mkdir(dirname(path), { recursive: true });
  const deadline = Date.now() + LOCK_ACQUIRE_TIMEOUT_MS;
  let held = false;
  while (Date.now() < deadline) {
    try {
      await writeFile(lockPath, String(process.pid), { flag: 'wx', mode: 0o600 });
      held = true;
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') break;
      try {
        if (Date.now() - (await stat(lockPath)).mtimeMs > LOCK_STALE_MS) {
          await unlink(lockPath).catch(() => undefined);
          continue;
        }
      } catch {
        continue; // the lock went away between the failed create and the look: take it
      }
      await new Promise((resolve) => setTimeout(resolve, LOCK_RETRY_INTERVAL_MS));
    }
  }
  try {
    return await work();
  } finally {
    if (held) await unlink(lockPath).catch(() => undefined);
  }
}
