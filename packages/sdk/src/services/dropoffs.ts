import type { HttpClient } from '../client.js';
import type { Dropoff, DropoffStatus, CreateDropoffInput } from '../types.js';
import type { DriveFile } from './drive.js';

/** Drop-off create, deposit and collect read the Mission Passport from X-Passport-Token. */
function passportHeaders(passportToken?: string): { headers: Record<string, string> } | undefined {
  return passportToken ? { headers: { 'X-Passport-Token': passportToken } } : undefined;
}

export class DropoffService {
  constructor(private client: HttpClient) {}

  /** An agent caller passes the producer's Mission Passport as `passportToken`. */
  async create(input: CreateDropoffInput, options?: { passportToken?: string }): Promise<Dropoff> {
    return this.client.post<Dropoff>('/v1/dropoffs', input, passportHeaders(options?.passportToken));
  }

  /** `driveFiles` are drive file ids the drop-off hands over: they open to the collector when it collects. */
  async deposit(
    id: string,
    agentId: string,
    payload: Record<string, unknown>,
    attribution?: { passportToken?: string; passportJti?: string; missionId?: string; driveFiles?: string[] },
  ): Promise<Dropoff> {
    return this.client.post<Dropoff>(`/v1/dropoffs/${id}/deposit`, {
      agent_id: agentId,
      payload,
      ...(attribution?.passportJti ? { passport_jti: attribution.passportJti } : {}),
      ...(attribution?.missionId ? { mission_id: attribution.missionId } : {}),
      ...(attribution?.driveFiles ? { drive_files: attribution.driveFiles } : {}),
    }, passportHeaders(attribution?.passportToken));
  }

  /** An agent caller passes its Mission Passport as `passportToken`. `drive_files` are the files the depositor handed over, now open to the collector; their content is untrusted. */
  async collect(id: string, agentId: string, options?: { passportToken?: string }): Promise<{ payload: unknown; drive_files?: DriveFile[] }> {
    return this.client.post(`/v1/dropoffs/${id}/collect`, { agent_id: agentId }, passportHeaders(options?.passportToken));
  }

  async get(id: string): Promise<DropoffStatus> {
    return this.client.get<DropoffStatus>(`/v1/dropoffs/${id}`);
  }

  async list(): Promise<Dropoff[]> {
    return this.client.get<Dropoff[]>('/v1/dropoffs');
  }

  async expire(id: string): Promise<Dropoff> {
    return this.client.post<Dropoff>(`/v1/dropoffs/${id}/expire`);
  }
}
