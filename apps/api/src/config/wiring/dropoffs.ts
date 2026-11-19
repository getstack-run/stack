import type { Database } from '@stack/shared';
import { DropoffRepository, DropoffService } from '@stack/dropoff';
import type { KmsService } from '@stack/vault';

export interface DropoffServices {
  dropoff: DropoffService;
}

/** Encrypted file and message drop-offs between agents and humans. */
export function createDropoffServices(db: Database, kms: KmsService): DropoffServices {
  return { dropoff: new DropoffService(new DropoffRepository(db), kms) };
}
