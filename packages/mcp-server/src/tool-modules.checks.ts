import type { ToolContext, ToolRegistrar } from './tools/context.js';
import type { McpToolModule } from './modules.js';

/**
 * Structural checks over tool modules, shared by the engine's test and the
 * hosted build's: each returns what is wrong, so a test can say it plainly.
 * They run the same against the engine's modules and against a deployment's.
 */

/** The names a module registers, in order, found by registering it on a recorder. */
export function registeredToolNames(module: McpToolModule): string[] {
  const names: string[] = [];
  const recorder: ToolRegistrar = {
    tool(name) {
      names.push(name);
    },
  };
  const unused = async () => {
    throw new Error('a tool handler ran while its module was only being listed');
  };
  module.register(recorder, { api: unused, apiRaw: unused } as ToolContext);
  return names;
}

const HINTS = ['readOnlyHint', 'destructiveHint', 'openWorldHint'] as const;

/** Every tool is annotated by the module that registers it, and by nothing else. */
export function annotationProblems(modules: readonly McpToolModule[]): string[] {
  const problems: string[] = [];
  const registeredBy = new Map<string, string>();
  for (const module of modules) {
    const names = registeredToolNames(module);
    for (const name of names) {
      const first = registeredBy.get(name);
      if (first) problems.push(`${name} is registered by ${first} and by ${module.id}`);
      registeredBy.set(name, module.id);
      const annotation = module.annotations[name];
      if (!annotation) {
        problems.push(`${module.id}: ${name} has no annotation in its own module`);
        continue;
      }
      if (!annotation.title.trim()) problems.push(`${module.id}: ${name} has an empty title`);
      for (const hint of HINTS) {
        if (typeof annotation[hint] !== 'boolean') problems.push(`${module.id}: ${name} has no explicit ${hint}`);
      }
      if (annotation.readOnlyHint && annotation.destructiveHint) {
        problems.push(`${module.id}: ${name} is read-only and destructive at once`);
      }
    }
    const own = new Set(names);
    for (const name of Object.keys(module.annotations)) {
      if (!own.has(name)) problems.push(`${module.id}: annotates ${name}, which it does not register`);
    }
    for (const [name, reason] of Object.entries(module.directoryExcluded ?? {})) {
      if (!own.has(name)) problems.push(`${module.id}: excludes ${name} from the directory, which it does not register`);
      if (!reason.trim()) problems.push(`${module.id}: excludes ${name} from the directory with no reason`);
    }
    for (const [name, text] of Object.entries(module.directoryDescriptions ?? {})) {
      if (!own.has(name)) problems.push(`${module.id}: gives ${name} a directory description, which it does not register`);
      if (!text.trim()) problems.push(`${module.id}: gives ${name} an empty directory description`);
      if (Object.hasOwn(module.directoryExcluded ?? {}, name)) problems.push(`${module.id}: gives ${name} a directory description and leaves it out of the directory`);
    }
  }
  return problems;
}

/**
 * What the modules say about who their tools are for: every exception names a tool the module registers, a piece
 * is one of the names given, and an audience is one of the three.
 */
export function exposureProblems(modules: readonly McpToolModule[], knownPieces: readonly string[]): string[] {
  const problems: string[] = [];
  const audiences = ['agent', 'owner', 'both'];
  const known = new Set(knownPieces);
  const pieceNames = (piece: string | readonly string[] | null | undefined): string[] =>
    piece === undefined || piece === null ? [] : typeof piece === 'string' ? [piece] : [...piece];
  for (const module of modules) {
    const rule = module.exposure;
    if (!rule) {
      problems.push(`${module.id}: has no exposure`);
      continue;
    }
    if (!audiences.includes(rule.audience)) problems.push(`${module.id}: audience ${String(rule.audience)} is not agent, owner or both`);
    for (const piece of pieceNames(rule.piece)) if (!known.has(piece)) problems.push(`${module.id}: piece ${piece} is not a known piece`);
    const own = new Set(registeredToolNames(module));
    for (const [name, tool] of Object.entries(rule.tools ?? {})) {
      if (!own.has(name)) problems.push(`${module.id}: sets the exposure of ${name}, which it does not register`);
      if (tool.audience !== undefined && !audiences.includes(tool.audience)) problems.push(`${module.id}: ${name} has audience ${String(tool.audience)}`);
      for (const piece of pieceNames(tool.piece)) if (!known.has(piece)) problems.push(`${module.id}: ${name} names piece ${piece}, which is not known`);
    }
  }
  return problems;
}

/** What the modules list says about itself: one id and one place each, and staff-only tools only for staff. */
export function moduleListProblems(modules: readonly McpToolModule[]): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  const orders = new Set<number>();
  for (const module of modules) {
    if (ids.has(module.id)) problems.push(`module id ${module.id} is listed twice`);
    ids.add(module.id);
    if (orders.has(module.order)) problems.push(`module ${module.id} shares its place in tools/list (${module.order}) with another`);
    orders.add(module.order);
    if (module.servedBy === 'private' && !module.staffOnly) {
      problems.push(`module ${module.id} is private to STACK's staff but is not registered for staff only`);
    }
  }
  return problems;
}
