import { stderr } from 'node:process';
import type { DriveUploadProgress } from '@getstackrun/sdk';

// `drive upload` sends the file as one request, streamed from disk by the SDK. This file holds what the command shows and checks around that.

/** What a text file may be (10 MiB) and what any file may be (1 GiB): the API's own numbers, copied because the CLI depends on nothing of the API's. */
export const BUFFERED_MAX_BYTES = 10 * 1024 * 1024;
export const MAX_FILE_BYTES = 1024 * 1024 * 1024;

const MIB = 1024 * 1024;

/** Progress on stderr: a line that rewrites itself on a terminal, a line per tenth otherwise. */
export function progressWriter(): (progress: DriveUploadProgress) => void {
  let lastTenth = -1;
  return ({ uploaded_bytes, total_bytes }) => {
    if (total_bytes === null || total_bytes === 0) return;
    const percent = Math.floor((uploaded_bytes / total_bytes) * 100);
    const text = `uploaded ${Math.floor(uploaded_bytes / MIB)} of ${Math.ceil(total_bytes / MIB)} MiB (${percent}%)`;
    if (stderr.isTTY) {
      stderr.write(`\r${text}${percent === 100 ? '\n' : ''}`);
    } else if (Math.floor(percent / 10) !== lastTenth) {
      lastTenth = Math.floor(percent / 10);
      stderr.write(`${text}\n`);
    }
  };
}
