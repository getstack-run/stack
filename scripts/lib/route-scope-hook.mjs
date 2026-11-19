// A module load hook for the OpenAPI generator (scripts/lib/rest-api-spec.mjs).
//
// A route reads its input with a schema that is usually a constant of its own file (`const DepositBody = z.object(...)`),
// which the file does not export. To write the input of every route into the OpenAPI document from those very schemas, the
// generator loads the built API with this hook registered: it appends to each built module of the API one export,
// `__stackScope`, whose properties read the module's top-level constants and its imports by name. The code that runs is the
// code that was built; the hook only makes its names readable.
//
// Nothing here writes a file: the added export exists in the loaded copy only.

const BUILT_API = /\/apps\/api\/dist\/.+\.js$/;

/** The names a built module binds at its top level: its constants and what it imports. */
export function topLevelNames(source) {
  const names = new Set();
  for (const match of source.matchAll(/^(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=/gm)) names.add(match[1]);
  for (const match of source.matchAll(/^import\s+([^;]*?)\s+from\s+['"][^'"]+['"];?/gm)) {
    const clause = match[1];
    const braces = /\{([^}]*)\}/.exec(clause);
    if (braces) {
      for (const part of braces[1].split(',')) {
        const piece = part.trim().replace(/^type\s+/, '');
        if (!piece) continue;
        const alias = /\bas\s+([A-Za-z_$][\w$]*)$/.exec(piece);
        names.add(alias ? alias[1] : piece);
      }
    }
    const rest = clause.replace(/\{[^}]*\}/, '');
    const namespace = /\*\s+as\s+([A-Za-z_$][\w$]*)/.exec(rest);
    if (namespace) names.add(namespace[1]);
    const defaultName = /^\s*([A-Za-z_$][\w$]*)\s*,?\s*$/.exec(rest.replace(/\*\s+as\s+[A-Za-z_$][\w$]*/, ''));
    if (defaultName) names.add(defaultName[1]);
  }
  return [...names];
}

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!BUILT_API.test(url) || result.format !== 'module' || result.source === undefined) return result;
  const source = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8');
  if (/export\s+const\s+__stackScope\b/.test(source)) return result;
  const getters = topLevelNames(source).map((name) => `  get ${JSON.stringify(name)}() { return ${name}; },`).join('\n');
  return { ...result, source: `${source}\nexport const __stackScope = {\n${getters}\n};\n` };
}
