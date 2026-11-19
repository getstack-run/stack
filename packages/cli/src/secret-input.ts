import { stdin, stderr } from 'node:process';

/** Read one secret without placing it in argv or echoing it to the terminal. */
export async function readSecretFromStdin(promptText: string): Promise<string> {
  if (!stdin.isTTY) {
    const chunks: Buffer[] = [];
    return new Promise<string>((resolve, reject) => {
      stdin.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      stdin.once('end', () => resolve(Buffer.concat(chunks).toString('utf8').trim()));
      stdin.once('error', reject);
    });
  }

  stderr.write(promptText);
  const wasRaw = stdin.isRaw === true;
  stdin.setRawMode?.(true);
  stdin.resume();
  stdin.setEncoding('utf8');
  return new Promise<string>((resolve, reject) => {
    let value = '';
    const finish = (fn: () => void) => {
      stdin.removeListener('data', onData);
      stdin.setRawMode?.(wasRaw);
      stdin.pause();
      stderr.write('\n');
      fn();
    };
    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === '\r' || char === '\n') return finish(() => resolve(value.trim()));
        if (char === '\u0003' || char === '\u0004') return finish(() => reject(new Error('cancelled')));
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else value += char;
      }
    };
    stdin.on('data', onData);
  });
}
