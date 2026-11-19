/** Composition root of the authority modules. */
import type { AuthorityServiceDeps } from './contracts.js';
import { ApprovalService } from './approvals.js';
import { AuthorityCore } from './core.js';
import { AuthorityGuards } from './guards.js';
import { AuthorityUseQueryService } from './authority-uses.js';
import { BindingService } from './bindings.js';
import { DomainSemantics } from './semantics.js';
import { ErasureService } from './erasure.js';
import { EvaluationService } from './evaluation.js';
import { FactDisclosure } from './fact-disclosure.js';
import { PassportRefService } from './passport-refs.js';
import { PresentationService } from './presentations.js';
import { PrincipalService } from './principals.js';
import { ProfileVersionService } from './profile-versions.js';
import { ProofCollectionService } from './proof-collection.js';
import { ProofService } from './proofs.js';
import { ReceiptService } from './receipts.js';
import { ReceiverService } from './receivers.js';
import { RuntimeUseService } from './runtime-use.js';

/** Every authority module, wired to one shared core. */
export interface AuthorityModules {
  core: AuthorityCore;
  guards: AuthorityGuards;
  semantics: DomainSemantics;
  principals: PrincipalService;
  proofs: ProofService;
  proofCollection: ProofCollectionService;
  erasure: ErasureService;
  bindings: BindingService;
  approvals: ApprovalService;
  evaluation: EvaluationService;
  runtimeUse: RuntimeUseService;
  passportRefs: PassportRefService;
  receivers: ReceiverService;
  profileVersions: ProfileVersionService;
  presentations: PresentationService;
  receipts: ReceiptService;
  uses: AuthorityUseQueryService;
}

/**
 * Builds the module graph. Modules depend on `core`, on the guards and on each
 * other only in this direction: guards, approvals, evaluation, runtime use,
 * presentations; nothing depends back up the list.
 */
export function createAuthorityModules(deps: AuthorityServiceDeps): AuthorityModules {
  const core = new AuthorityCore(deps);
  const guards = new AuthorityGuards(core);
  const semantics = new DomainSemantics(core);
  const approvals = new ApprovalService(core, guards);
  const runtimeUse = new RuntimeUseService(core);
  const evaluation = new EvaluationService(core, guards, approvals, semantics);
  const facts = new FactDisclosure(core, guards);
  return {
    core,
    guards,
    semantics,
    principals: new PrincipalService(core),
    proofs: new ProofService(core),
    proofCollection: new ProofCollectionService(core),
    erasure: new ErasureService(core),
    bindings: new BindingService(core, guards, approvals),
    approvals,
    evaluation,
    runtimeUse,
    passportRefs: new PassportRefService(core, guards),
    receivers: new ReceiverService(core),
    profileVersions: new ProfileVersionService(core),
    presentations: new PresentationService(
      core,
      guards,
      semantics,
      evaluation,
      approvals,
      runtimeUse,
      facts,
    ),
    receipts: new ReceiptService(core, guards, semantics, evaluation),
    uses: new AuthorityUseQueryService(core),
  };
}
