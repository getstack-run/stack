/** Immutable proof, domain and receiver profile versions. */
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  canonicalize,
  generateId,
  type CreateAuthorityProfileVersionInput,
} from '@stack/shared';
import { AuthorityCore } from './core.js';
import { assertStackInternalProfile, assertStackProxyBridgeProfile } from './profile-validators.js';
import { compileDomainSchema } from './domain-schema.js';
import { sha256 } from './digest.js';
import { validatePublicHttpsEndpoint } from './receiver-validation.js';

export class ProfileVersionService {
  private readonly now: () => Date;

  constructor(private readonly core: AuthorityCore) {
    this.now = core.now;
  }

  async createProfileVersion(
    operatorId: string,
    input: CreateAuthorityProfileVersionInput,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `profile.create:${input.profile_kind}:${input.profile_key}`,
      idempotencyKey,
      input,
      async (repo) => {
        let config = input.config_json as Record<string, unknown>;
        let receiverId: string | null = null;
        if (input.profile_kind === 'receiver') {
          receiverId = input.receiver_id;
          const receiver = await repo.findReceiver(operatorId, receiverId);
          if (!receiver || receiver.status === 'revoked')
            throw new NotFoundError('AuthorityReceiver', receiverId);
          if (receiver.mode === 'internal') {
            if (
              !(await repo.isOwnedInternalReceiver(operatorId, receiver.canonical_identifier ?? ''))
            )
              throw new ForbiddenError();
            assertStackInternalProfile(config, receiver);
          } else if (receiver.mode === 'proxy_bridge') {
            assertStackProxyBridgeProfile(config, receiver);
          } else {
            const delivery = config.delivery as Record<string, unknown>;
            this.core.presentationProtocolForConfig(config).validateProfile(config);
            const checked = await validatePublicHttpsEndpoint(String(delivery.endpoint));
            config = { ...config, delivery: { ...delivery, endpoint: checked.normalized } };
          }
        } else if (input.profile_kind === 'domain') {
          for (const action of input.config_json.actions)
            compileDomainSchema(action.normalized_request_schema);
        }
        const contentHash = sha256(
          canonicalize({
            profile_kind: input.profile_kind,
            profile_key: input.profile_key,
            version: input.version,
            schema_uri: input.schema_uri,
            schema_version: input.schema_version,
            adapter_key: input.adapter_key,
            adapter_version: input.adapter_version,
            config_json: config,
          }),
        );
        return repo.insertProfileVersion({
          id: generateId('apv'),
          owner_operator_id: operatorId,
          profile_kind: input.profile_kind,
          profile_key: input.profile_key,
          version: input.version,
          receiver_id: receiverId,
          schema_uri: input.schema_uri,
          schema_version: input.schema_version,
          adapter_key: input.adapter_key,
          adapter_version: input.adapter_version,
          config_json: config,
          content_hash: contentHash,
          status: 'draft',
          created_at: this.now(),
        });
      },
      201,
    );
  }

  async activateProfileVersion(
    operatorId: string,
    kind: 'proof' | 'domain' | 'receiver',
    profileId: string,
    idempotencyKey: string,
  ) {
    return this.core.idempotent(
      operatorId,
      `profile.activate:${kind}:${profileId}`,
      idempotencyKey,
      {},
      async (repo) => {
        const current = await repo.findProfileVersion(operatorId, kind, profileId);
        if (!current) throw new NotFoundError('AuthorityProfileVersion', profileId);
        if (kind === 'receiver') {
          const receiverId = typeof current.receiver_id === 'string' ? current.receiver_id : '';
          const receiver = receiverId ? await repo.findReceiver(operatorId, receiverId) : null;
          if (!receiver || receiver.status === 'revoked')
            throw new ForbiddenError('receiver profile owner is unavailable');
          const config = current.config_json as Record<string, unknown>;
          if (receiver.mode === 'internal') {
            if (
              !(await repo.isOwnedInternalReceiver(operatorId, receiver.canonical_identifier ?? ''))
            )
              throw new ForbiddenError();
            assertStackInternalProfile(config, receiver);
          } else if (receiver.mode === 'proxy_bridge') {
            assertStackProxyBridgeProfile(config, receiver);
          } else {
            this.core.presentationProtocolForConfig(config).validateProfile(config);
            const delivery = config.delivery as Record<string, unknown>;
            await validatePublicHttpsEndpoint(String(delivery.endpoint));
          }
        }
        const activated = await repo.activateProfileVersion(
          operatorId,
          kind,
          profileId,
          this.now(),
        );
        if (!activated)
          throw new ConflictError('authority profile activation lost a concurrent transition');
        return activated;
      },
    );
  }
}
