// The files a model or a tool made, as the caller receives them: saved to the
// agent's drive when the deployment has one, and otherwise returned (the bytes
// when they are small, or the provider's link). The image gateway on a
// customer's own key uses this, and so does an account's tool run, so a file is
// never lost for want of a place to put it.

import { publicFetch, type GeneratedFile } from '@stack/shared';

/** Where a made file goes: the agent's drive, when the deployment has one. */
export interface GeneratedFileSink {
  save(input: {
    operatorId: string;
    agentId: string;
    missionId: string | null;
    name: string;
    contentType: string;
    bytes: Buffer;
    /** The model or tool run that made it, for the drive's record. */
    origin: { tool: string; toolRunId: string };
  }): Promise<{ id: string }>;
}

/** Bytes returned inline when there is no drive to save a file to. */
export const INLINE_FILE_MAX_BYTES = 8 * 1024 * 1024;
/** The most STACK downloads from a provider link to save it. */
const DOWNLOAD_MAX_BYTES = 200 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 120_000;

export type FileDownload = (url: string) => Promise<{ bytes: Buffer; contentType: string | null }>;

/** The SSRF-guarded fetch of a provider's file link: https only, no redirects, a size cap. */
export const guardedDownload: FileDownload = async (url) => {
  const response = await publicFetch(url, { method: 'GET', redirect: 'manual' }, {
    allowedProtocols: ['https:'], timeoutMs: DOWNLOAD_TIMEOUT_MS, maxResponseBytes: DOWNLOAD_MAX_BYTES,
  });
  if (!response.ok) throw new Error(`The file link answered ${response.status}`);
  return { bytes: Buffer.from(await response.arrayBuffer()), contentType: response.headers.get('content-type') };
};

export interface FileOwner {
  operatorId: string;
  agentId: string;
  missionId: string | null;
}

/**
 * One file as the caller sees it: saved to the drive when there is one, else
 * the bytes (small) or the provider's link. A drive that refuses the file does
 * not fail the call.
 */
export async function presentGeneratedFile(
  sink: GeneratedFileSink | null,
  owner: FileOwner,
  origin: { tool: string; toolRunId: string },
  file: { name: string; contentType: string; bytes: Buffer | null; sourceUrl: string | null },
): Promise<GeneratedFile> {
  let driveFileId: string | null = null;
  if (file.bytes && sink) {
    try {
      driveFileId = (await sink.save({
        operatorId: owner.operatorId, agentId: owner.agentId, missionId: owner.missionId,
        name: file.name, contentType: file.contentType, bytes: file.bytes, origin,
      })).id;
    } catch (error) {
      console.error('[tool files] saving a file to the drive failed:', error instanceof Error ? error.name : 'error');
    }
  }
  const inline = driveFileId === null && file.bytes !== null && file.bytes.length <= INLINE_FILE_MAX_BYTES;
  return {
    name: file.name,
    content_type: file.contentType,
    size_bytes: file.bytes ? file.bytes.length : null,
    drive_file_id: driveFileId,
    source_url: file.sourceUrl,
    data_base64: inline ? file.bytes!.toString('base64') : null,
  };
}
