// Conformance suite for a CATALOGUE PUBLISHER (spec/catalogue/SPEC.md).
//
// It judges one catalogue document, and, when you give it a URL, how that URL
// serves it. The document comes from
//   - `document`: the parsed document (a file you built), or
//   - `url` (and optional `headers`): the file as your server serves it. The
//     kit then also checks the validator and the conditional read.
//
// It uses nothing of STACK's: the rules here are the specification's text.

import { assert, assertEqual, fail, runChecks, skip } from './harness.mjs';
import { canonicalize, sha256Hex } from './canonical.mjs';

const KINDS = ['model', 'tool', 'service', 'skill', 'account', 'mcp_tool'];
const TOOL_AUDIENCES = ['agent', 'owner', 'both'];
const SOURCES = ['stack', 'models', 'tools', 'services', 'skills'];
const SOURCE_OF_KIND = { model: 'models', tool: 'tools', service: 'services', skill: 'skills', account: 'stack', mcp_tool: 'stack' };
const STATUSES = ['ok', 'not_configured', 'unavailable', 'stale'];
const UNITS = ['token', 'call', 'result', 'image', 'lines', 'free', 'varies'];
const PRICE_PER = ['token', 'character', 'second', 'request', 'image', 'search', 'megapixel_second', 'generation', 'audio_unit', 'minute', 'hour', 'month', 'message', 'segment', 'gigabyte', 'gigabyte_month'];
const COST_FIELDS = ['per_unit_usd_micros', 'flat_fee_usd_micros', 'input_per_million_tokens_usd_micros', 'output_per_million_tokens_usd_micros', 'worst_case_usd_micros', 'lines', 'tiers', 'discount'];
const LINE_KEYS = ['item', 'per', 'per_count', 'cost_usd_micros'];
const FREE_KEYS = ['item', 'per', 'count'];
const TRUSTS = ['standard', 'untrusted'];
const ORIGINS = ['stack', 'models', 'tools', 'publisher'];
const ENTRY_KEYS = new Set(['id', 'kind', 'name', 'description', 'origin', 'provider', 'modalities', 'context_length', 'max_completion_tokens', 'input_schema', 'price', 'result_trust', 'run', 'tool']);
const SCHEMA_KEYWORDS = new Set([
  'type', 'title', 'description', 'format', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum',
  'minItems', 'maxItems', 'minLength', 'maxLength', 'enum', 'default', 'additionalProperties',
  'properties', 'required', 'items', 'anyOf', 'oneOf',
]);
const LIMITS = {
  // A description, an input schema's property descriptions and an enum's values are kept in full (section 11 since
  // 1.4.0): only a name has a length limit.
  idChars: 330, nameChars: 120,
  schemaBytes: 16 * 1024, schemaDepth: 8, schemaProperties: 64, entries: 10_000, documentBytes: 64 * 1024 * 1024,
};
const ID = /^(model|tool|service|skill|account|mcp_tool):[A-Za-z0-9~][A-Za-z0-9._~:@/+-]*$/;
const RUN_PATH = /^\/v1\/[A-Za-z0-9._~\-/{}:]+$/;
const PLACEHOLDER = /\{([^}]*)\}/g;
const PLACEHOLDERS = new Set(['account_id', 'session_id']);
/* eslint-disable no-control-regex */
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/;
/* eslint-enable no-control-regex */
const MARKUP = /<\/?[A-Za-z!][^>]*>/;
const SECRET_SHAPES = [/sk_live_[A-Za-z0-9]{8,}/, /sk-or-[A-Za-z0-9_-]{8,}/, /sk-ant-[A-Za-z0-9_-]{8,}/, /\bBearer\s+[A-Za-z0-9._~+/-]{20,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/];

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isInt = (v) => Number.isSafeInteger(v);
const isNonNegativeInt = (v) => isInt(v) && v >= 0;

function* strings(value, path = '$') {
  if (typeof value === 'string') yield [path, value];
  else if (Array.isArray(value)) for (const [i, v] of value.entries()) yield* strings(v, `${path}[${i}]`);
  else if (isObject(value)) for (const [k, v] of Object.entries(value)) yield* strings(v, `${path}.${k}`);
}

function plainTextProblem(text, max) {
  if (text.length > max) return `is ${text.length} characters, above ${max}`;
  if (INVISIBLE.test(text)) return 'has a control, zero-width or direction-changing character';
  if (MARKUP.test(text)) return 'has markup';
  if (text.includes('```')) return 'has a code fence';
  if (text !== text.trim() || /\s{2,}|[\n\r\t]/.test(text)) return 'has white space that is not single spaces, trimmed';
  return null;
}

/** The problems with an input schema, or an empty list. */
function schemaProblems(schema) {
  const problems = [];
  if (Buffer.byteLength(JSON.stringify(schema)) > LIMITS.schemaBytes) problems.push(`is larger than ${LIMITS.schemaBytes} bytes`);
  const walk = (node, depth, path) => {
    if (!isObject(node)) {
      problems.push(`${path} is not an object`);
      return;
    }
    if (depth > LIMITS.schemaDepth) problems.push(`${path} is deeper than ${LIMITS.schemaDepth} levels`);
    for (const key of Object.keys(node)) {
      if (!SCHEMA_KEYWORDS.has(key)) problems.push(`${path} uses the keyword ${key}, which the catalogue drops`);
    }
    if (typeof node.description === 'string') {
      const text = plainTextProblem(node.description, Infinity);
      if (text) problems.push(`${path}.description ${text}`);
    }
    if (isObject(node.properties)) {
      const names = Object.keys(node.properties);
      if (names.length > LIMITS.schemaProperties) problems.push(`${path} has more than ${LIMITS.schemaProperties} properties`);
      for (const name of names) {
        if (!/^[A-Za-z_$][A-Za-z0-9_.$-]{0,63}$/.test(name)) problems.push(`${path}.properties has a name that is not an identifier`);
        walk(node.properties[name], depth + 1, `${path}.properties.${name}`);
      }
    }
    if (node.items !== undefined) walk(node.items, depth + 1, `${path}.items`);
    for (const key of ['anyOf', 'oneOf']) {
      if (Array.isArray(node[key])) for (const [i, child] of node[key].entries()) walk(child, depth + 1, `${path}.${key}[${i}]`);
    }
  };
  walk(schema, 0, 'input_schema');
  return problems;
}

/** The problems with the lines of a price: each is the provider's own name for it, what it is per, how many of those and the cost. */
function lineProblems(lines) {
  if (!Array.isArray(lines) || lines.length === 0 || lines.length > 64) return ['has lines that are not a list of 1 to 64'];
  const problems = [];
  for (const [index, line] of lines.entries()) {
    if (!isObject(line)) {
      problems.push(`has a line ${index} that is not an object`);
      continue;
    }
    for (const key of Object.keys(line)) if (!LINE_KEYS.includes(key)) problems.push(`has the line field ${key}`);
    if (typeof line.item !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(line.item)) problems.push(`has a line ${index} whose item is not a name`);
    if (!PRICE_PER.includes(line.per)) problems.push(`has a line ${index} that is per ${JSON.stringify(line.per)}`);
    if (line.per_count !== 1 && line.per_count !== 1_000_000) problems.push(`has a line ${index} whose per_count is not 1 or 1000000`);
    if (!isNonNegativeInt(line.cost_usd_micros)) problems.push(`has a line ${index} whose cost is not a whole non-negative number of micro-dollars`);
  }
  return problems;
}

/** The problems with the tiers of a price: each is the lines the model switches to, and the prompt length above which it does. */
function tierProblems(tiers) {
  if (!Array.isArray(tiers) || tiers.length === 0 || tiers.length > 16) return ['has tiers that are not a list of 1 to 16'];
  const problems = [];
  for (const [index, tier] of tiers.entries()) {
    if (!isObject(tier)) {
      problems.push(`has a tier ${index} that is not an object`);
      continue;
    }
    for (const key of Object.keys(tier)) if (!['above_prompt_tokens', 'lines'].includes(key)) problems.push(`has the tier field ${key}`);
    if (tier.above_prompt_tokens !== undefined && !(Number.isInteger(tier.above_prompt_tokens) && tier.above_prompt_tokens >= 1)) {
      problems.push(`has a tier ${index} whose above_prompt_tokens is not a whole number from 1`);
    }
    problems.push(...lineProblems(tier.lines).map((problem) => `in tier ${index}: ${problem}`));
  }
  return problems;
}

/** The problems with a price's free amounts: what the subscription includes each month, before the lines apply. */
function freeProblems(free) {
  if (!Array.isArray(free) || free.length === 0 || free.length > 8) return ['has free_per_month that is not a list of 1 to 8'];
  const problems = [];
  for (const [index, amount] of free.entries()) {
    if (!isObject(amount)) {
      problems.push(`has a free amount ${index} that is not an object`);
      continue;
    }
    for (const key of Object.keys(amount)) if (!FREE_KEYS.includes(key)) problems.push(`has the free amount field ${key}`);
    if (typeof amount.item !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(amount.item)) problems.push(`has a free amount ${index} whose item is not a name`);
    if (!PRICE_PER.includes(amount.per)) problems.push(`has a free amount ${index} that is per ${JSON.stringify(amount.per)}`);
    if (!isInt(amount.count) || amount.count < 1) problems.push(`has a free amount ${index} whose count is not a whole number of at least 1`);
  }
  return problems;
}

/** The version the specification says a document has (section 8). */
export function catalogueVersion(document) {
  return sha256Hex(canonicalize({
    entries: document.entries,
    pricing: document.pricing,
    sections: document.sections.map((s) => ({ source: s.source, status: s.status, count: s.count })),
  }));
}

/** The checks on a document alone. `getDocument` returns it. */
function documentChecks(getDocument) {
  const entriesOf = () => {
    const document = getDocument();
    assert(Array.isArray(document.entries), 'entries is not a list');
    return document.entries;
  };
  const eachEntry = (fn) => () => {
    const problems = [];
    for (const [index, entry] of entriesOf().entries()) {
      for (const problem of fn(entry) ?? []) problems.push(`entry ${index} (${entry?.id ?? '?'}): ${problem}`);
    }
    if (problems.length > 0) fail(problems.slice(0, 8).join('; ') + (problems.length > 8 ? `; and ${problems.length - 8} more` : ''));
  };
  const checks = [
    {
      id: 'C01', level: 'MUST', title: 'is a catalogue document of a version this specification defines',
      run() {
        const d = getDocument();
        assert(isObject(d), 'the document is not a JSON object');
        assertEqual(d.spec, 'stack.catalogue', 'spec');
        assertEqual(d.spec_version, '1', 'spec_version');
      },
    },
    {
      id: 'C02', level: 'MUST', title: 'has the header fields: version, generated_at, notice, pricing, sections and entries',
      run() {
        const d = getDocument();
        assert(/^[0-9a-f]{64}$/.test(d.version ?? ''), 'version is not 64 lower-case hexadecimal characters');
        assert(typeof d.generated_at === 'string' && !Number.isNaN(Date.parse(d.generated_at)), 'generated_at is not a date');
        assert(typeof d.notice === 'string' && d.notice.length > 0 && d.notice.length <= 400, 'notice is missing or longer than 400 characters');
        assert(isObject(d.pricing), 'pricing is missing');
        assert(Array.isArray(d.sections), 'sections is not a list');
        assert(Array.isArray(d.entries), 'entries is not a list');
        const extra = Object.keys(d).filter((k) => !['spec', 'spec_version', 'version', 'generated_at', 'notice', 'pricing', 'sections', 'entries'].includes(k));
        assert(extra.length === 0, `has fields this version does not define: ${extra.join(', ')}`);
      },
    },
    {
      id: 'C03', level: 'MUST', title: 'is within the size limits',
      run() {
        const d = getDocument();
        assert(d.entries.length <= LIMITS.entries, `has ${d.entries.length} entries, above ${LIMITS.entries}`);
        const size = Buffer.byteLength(JSON.stringify(d));
        assert(size <= LIMITS.documentBytes, `is ${size} bytes, above ${LIMITS.documentBytes}`);
      },
    },
    {
      id: 'C04', level: 'MUST', title: 'gives every entry its fields, and only the fields of this version',
      run: eachEntry((e) => {
        if (!isObject(e)) return ['is not an object'];
        const problems = [];
        for (const key of ['id', 'kind', 'name', 'description', 'origin', 'price', 'result_trust']) {
          if (e[key] === undefined) problems.push(`has no ${key}`);
        }
        for (const key of Object.keys(e)) if (!ENTRY_KEYS.has(key)) problems.push(`has the field ${key}, which this version does not define`);
        if (e.kind !== undefined && !KINDS.includes(e.kind)) problems.push(`has the kind ${JSON.stringify(e.kind)}`);
        if (e.origin !== undefined && !ORIGINS.includes(e.origin)) problems.push(`has the origin ${JSON.stringify(e.origin)}`);
        if (e.result_trust !== undefined && !TRUSTS.includes(e.result_trust)) problems.push(`has the result_trust ${JSON.stringify(e.result_trust)}`);
        if (e.provider !== undefined && (typeof e.provider !== 'string' || e.provider.length > 64)) problems.push('has a provider that is not a string of at most 64 characters');
        if (e.context_length !== undefined && !(isInt(e.context_length) && e.context_length >= 1)) problems.push('has a context_length that is not a positive integer');
        if (e.max_completion_tokens !== undefined && !(isInt(e.max_completion_tokens) && e.max_completion_tokens >= 1)) problems.push('has a max_completion_tokens that is not a positive integer');
        if (e.modalities !== undefined) {
          const m = e.modalities;
          if (!isObject(m) || !Array.isArray(m.input) || !Array.isArray(m.output) || ![...m.input, ...m.output].every((x) => typeof x === 'string' && x.length <= 32)) problems.push('has modalities that are not { input: string[], output: string[] }');
        }
        return problems;
      }),
    },
    {
      id: 'C05', level: 'MUST', title: 'has ids of the form kind:name that are unique, with the kind of the entry',
      run() {
        const seen = new Set();
        const problems = [];
        for (const e of entriesOf()) {
          if (typeof e.id !== 'string' || !ID.test(e.id) || e.id.length > LIMITS.idChars) problems.push(`${JSON.stringify(e.id)} is not an id`);
          else if (e.id.split(':', 1)[0] !== e.kind) problems.push(`${e.id} is not of the kind ${e.kind}`);
          if (seen.has(e.id)) problems.push(`${e.id} appears twice`);
          seen.add(e.id);
        }
        if (problems.length > 0) fail(problems.slice(0, 8).join('; '));
      },
    },
    {
      id: 'C06', level: 'MUST', title: 'writes names and descriptions as plain text',
      run: eachEntry((e) => {
        const problems = [];
        if (typeof e.name !== 'string' || e.name.length === 0) problems.push('has no name');
        else {
          const p = plainTextProblem(e.name, LIMITS.nameChars);
          if (p) problems.push(`name ${p}`);
        }
        if (typeof e.description !== 'string') problems.push('has no description');
        else {
          const p = plainTextProblem(e.description, Infinity);
          if (p) problems.push(`description ${p}`);
        }
        return problems;
      }),
    },
    {
      id: 'C07', level: 'MUST', title: 'prices every entry in dollars as whole micro-dollars, with the figures its unit needs',
      run: eachEntry((e) => {
        const p = e.price;
        if (!isObject(p)) return ['has no price'];
        const problems = [];
        if (!UNITS.includes(p.unit)) problems.push(`has the price unit ${JSON.stringify(p.unit)}`);
        if (p.currency !== 'USD') problems.push('has a price that is not in USD');
        if (p.free_per_month !== undefined) problems.push(...freeProblems(p.free_per_month));
        if (p.stack_actions !== 0 && p.stack_actions !== 1) problems.push('has stack_actions that is not 0 or 1');
        const cost = p.provider_cost;
        if (cost !== null && !isObject(cost)) problems.push('has a provider_cost that is neither null nor an object');
        if (isObject(cost)) {
          for (const [key, value] of Object.entries(cost)) {
            if (!COST_FIELDS.includes(key)) problems.push(`has the provider_cost field ${key}`);
            else if (key === 'lines') problems.push(...lineProblems(value));
            else if (key === 'tiers') problems.push(...tierProblems(value));
            else if (key === 'discount') {
              if (!(typeof value === 'number' && value >= 0 && value <= 1)) problems.push('has a discount that is not a number from 0 to 1');
            } else if (!isNonNegativeInt(value)) problems.push(`has ${key} that is not a whole non-negative number of micro-dollars`);
          }
          if (p.unit === 'lines' && !(Array.isArray(cost.lines) && cost.lines.length > 0)) problems.push('is priced in lines without any line');
          if (p.unit === 'token' && !(isInt(cost.input_per_million_tokens_usd_micros) && isInt(cost.output_per_million_tokens_usd_micros))) problems.push('is priced per token without input and output figures');
          if ((p.unit === 'call' || p.unit === 'result') && !isInt(cost.per_unit_usd_micros)) problems.push(`is priced per ${p.unit} without per_unit_usd_micros`);
          if (p.unit === 'free') problems.push('is free but has a provider_cost');
        }
        if (p.unit === 'lines' && !isObject(cost)) problems.push('is priced in lines but has no provider_cost');
        if (p.unit === 'free' && cost === undefined) problems.push('has no provider_cost (null for free)');
        return problems;
      }),
    },
    {
      id: 'C08', level: 'MUST', title: 'marks a skill\'s result untrusted',
      run: eachEntry((e) => (e.kind === 'skill' && e.result_trust !== 'untrusted' ? ['is a skill whose result is not untrusted'] : [])),
    },
    {
      id: 'C09', level: 'MUST', title: 'describes how to run an entry with a descriptor a client can follow',
      run: eachEntry((e) => {
        if (e.run === undefined) return [];
        const r = e.run;
        if (!isObject(r)) return ['has a run that is not an object'];
        const problems = [];
        if (!['GET', 'POST', 'PUT'].includes(r.method)) problems.push(`has the run method ${JSON.stringify(r.method)}`);
        if (typeof r.path !== 'string' || !RUN_PATH.test(r.path) || r.path.length > 200) problems.push('has a run path that is not a /v1/ path');
        else for (const m of r.path.matchAll(PLACEHOLDER)) if (!PLACEHOLDERS.has(m[1])) problems.push(`has the placeholder {${m[1]}} in its run path`);
        if (r.body !== undefined) {
          if (!isObject(r.body) || !Object.values(r.body).every((v) => (typeof v === 'string' && v.length <= 300) || typeof v === 'number' || typeof v === 'boolean')) problems.push('has a run body that is not scalar fields');
        }
        if (r.mcp_tool !== undefined && !(typeof r.mcp_tool === 'string' && /^stack_[a-z0-9_]+$/.test(r.mcp_tool))) problems.push('has an mcp_tool that is not a stack_ tool name');
        if (r.cost_cap !== undefined && !(isObject(r.cost_cap) && ['body', 'header'].includes(r.cost_cap.in) && typeof r.cost_cap.name === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(r.cost_cap.name))) problems.push('has a cost_cap that is not { in, name }');
        for (const key of Object.keys(r)) if (!['method', 'path', 'body', 'mcp_tool', 'cost_cap'].includes(key)) problems.push(`has the run field ${key}`);
        return problems;
      }),
    },
    {
      id: 'C10', level: 'MUST', title: 'reduces input schemas to the keywords, depth and size the specification keeps',
      run: eachEntry((e) => (e.input_schema === undefined ? [] : (isObject(e.input_schema) ? schemaProblems(e.input_schema) : ['has an input_schema that is not an object']))),
    },
    {
      id: 'C11', level: 'MUST', title: 'says how each section stands, and counts it right',
      run() {
        const d = getDocument();
        const problems = [];
        const seen = new Set();
        for (const s of d.sections) {
          if (!isObject(s)) {
            problems.push('a section is not an object');
            continue;
          }
          if (!SOURCES.includes(s.source)) problems.push(`has the section source ${JSON.stringify(s.source)}`);
          if (seen.has(s.source)) problems.push(`has the section ${s.source} twice`);
          seen.add(s.source);
          if (!STATUSES.includes(s.status)) problems.push(`${s.source}: has the status ${JSON.stringify(s.status)}`);
          if (s.refreshed_at !== null && (typeof s.refreshed_at !== 'string' || Number.isNaN(Date.parse(s.refreshed_at)))) problems.push(`${s.source}: refreshed_at is neither null nor a date`);
          const counted = d.entries.filter((e) => SOURCE_OF_KIND[e.kind] === s.source).length;
          if (s.count !== counted) problems.push(`${s.source}: count is ${s.count} but the document has ${counted} entries of its kinds`);
          if ((s.status === 'not_configured' || s.status === 'unavailable') && s.count !== 0) problems.push(`${s.source}: is ${s.status} but not empty`);
          if (s.status === 'stale' && s.refreshed_at === null) problems.push(`${s.source}: is stale with no refreshed_at`);
        }
        for (const e of d.entries) {
          if (SOURCE_OF_KIND[e.kind] && !seen.has(SOURCE_OF_KIND[e.kind])) problems.push(`${e.id}: its section ${SOURCE_OF_KIND[e.kind]} is not listed`);
        }
        if (problems.length > 0) fail(problems.slice(0, 8).join('; '));
      },
    },
    {
      id: 'C12', level: 'MUST', title: 'says what an action costs, in bands that rise to an open last band',
      run() {
        const p = getDocument().pricing;
        assertEqual(p.currency, 'USD', 'pricing.currency');
        assert(typeof p.rule === 'string' && p.rule.length > 0 && p.rule.length <= 300, 'pricing.rule is missing');
        assert(isNonNegativeInt(p.included_actions_per_month), 'included_actions_per_month is not a whole number');
        assert(Array.isArray(p.bands) && p.bands.length >= 1 && p.bands.length <= 12, 'bands is not a list of 1 to 12');
        let last = 0;
        for (const [i, band] of p.bands.entries()) {
          assert(isNonNegativeInt(band.usd_micros_per_action), `band ${i} has no whole usd_micros_per_action`);
          if (i < p.bands.length - 1) {
            assert(isInt(band.up_to) && band.up_to > last, `band ${i} does not end above the one before`);
            last = band.up_to;
          } else assert(band.up_to === null, 'the last band is not open (up_to null)');
        }
      },
    },
    {
      id: 'C13', level: 'MUST', title: 'has the version the specification says: the SHA-256 of its entries, pricing and section states',
      run() {
        const d = getDocument();
        assertEqual(d.version, catalogueVersion(d), 'version');
      },
    },
    {
      id: 'C14', level: 'MUST', title: 'carries no credential-shaped string',
      run() {
        const found = [];
        for (const [path, text] of strings(getDocument())) {
          if (SECRET_SHAPES.some((shape) => shape.test(text))) found.push(path);
        }
        assert(found.length === 0, `has a string that looks like a credential at ${found.slice(0, 5).join(', ')}`);
      },
    },
    {
      id: 'C16', level: 'MUST', title: 'gives an mcp_tool entry its tool facts (group, pieces, audience, on_demand), and no other entry any',
      run: eachEntry((e) => {
        if (e.kind !== 'mcp_tool') return e.tool === undefined ? [] : ['has tool facts but is not an mcp_tool'];
        const t = e.tool;
        if (!isObject(t)) return ['is an mcp_tool with no tool facts'];
        const problems = [];
        for (const key of Object.keys(t)) if (!['group', 'pieces', 'audience', 'on_demand'].includes(key)) problems.push(`has the tool field ${key}`);
        if (typeof t.group !== 'string' || t.group.length === 0 || t.group.length > 40) problems.push('has a tool group that is not a string of 1 to 40 characters');
        if (!Array.isArray(t.pieces) || t.pieces.length > 8 || !t.pieces.every((p) => typeof p === 'string' && p.length > 0 && p.length <= 32)) problems.push('has tool pieces that are not a list of at most 8 names');
        if (!TOOL_AUDIENCES.includes(t.audience)) problems.push(`has the tool audience ${JSON.stringify(t.audience)}`);
        if (typeof t.on_demand !== 'boolean') problems.push('has an on_demand that is not true or false');
        if (e.id !== undefined && !/^mcp_tool:[A-Za-z0-9_]+$/.test(e.id)) problems.push('has an id that is not mcp_tool: and a tool name');
        return problems;
      }),
    },
    {
      id: 'C15', level: 'SHOULD', title: 'lists entries by kind and then id, so the same content is the same bytes',
      run() {
        const entries = entriesOf();
        const order = (e) => `${KINDS.indexOf(e.kind)}:${e.id}`;
        for (let i = 1; i < entries.length; i += 1) {
          if (order(entries[i - 1]) > order(entries[i])) fail(`${entries[i].id} comes after ${entries[i - 1].id}`);
        }
      },
    },
  ];
  return checks;
}

/** The checks on how a URL serves the file. */
function transportChecks({ url, headers = {}, fetchImpl = fetch, timeoutMs = 10_000 }) {
  const get = async (extra = {}) => {
    const response = await fetchImpl(url, {
      method: 'GET',
      headers: { accept: 'application/json', ...headers, ...extra },
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { status: response.status, headers: response.headers, text: await response.text() };
  };
  return [
    {
      id: 'T01', level: 'MUST', title: 'answers 200 with a JSON document and an ETag',
      async run() {
        const r = await get();
        assertEqual(r.status, 200, 'status');
        assert(/json/i.test(r.headers.get('content-type') ?? ''), 'the content type is not JSON');
        assert(r.headers.get('etag'), 'there is no ETag');
        try {
          JSON.parse(r.text);
        } catch {
          fail('the body is not JSON');
        }
      },
    },
    {
      id: 'T02', level: 'MUST', title: 'answers 304 with no body to the validator it sent',
      async run() {
        const first = await get();
        const etag = first.headers.get('etag');
        if (!etag) return skip('no ETag to send');
        const again = await get({ 'if-none-match': etag });
        assertEqual(again.status, 304, 'status');
        assertEqual(again.text, '', 'body');
      },
    },
    {
      id: 'T03', level: 'MUST', title: 'answers the whole document to a validator it did not send',
      async run() {
        const r = await get({ 'if-none-match': 'W/"0000000000000000"' });
        assertEqual(r.status, 200, 'status');
        assert(r.text.length > 2, 'the body is empty');
      },
    },
    {
      id: 'T04', level: 'MUST', title: 'keeps its ETag between two reads of the same version, and ties it to the version',
      async run() {
        const a = await get();
        const b = await get();
        if (JSON.parse(a.text).version === JSON.parse(b.text).version) {
          assertEqual(a.headers.get('etag'), b.headers.get('etag'), 'the ETag of one version');
        }
        const version = JSON.parse(a.text).version;
        assert((a.headers.get('etag') ?? '').includes(version), 'the ETag is not a function of the version');
      },
    },
    {
      id: 'T05', level: 'SHOULD', title: 'says how long a copy may be kept',
      async run() {
        const r = await get();
        const control = r.headers.get('cache-control') ?? '';
        assert(/max-age=\d+/.test(control), 'there is no Cache-Control max-age');
        const age = Number(/max-age=(\d+)/.exec(control)?.[1]);
        assert(age <= 300, `max-age is ${age} seconds, above the 300 the specification allows a shared cache`);
      },
    },
    {
      id: 'T06', level: 'MUST', title: 'serves the document that was built: the version does not change between two reads in a row',
      async run() {
        const a = JSON.parse((await get()).text);
        const b = JSON.parse((await get()).text);
        assertEqual(a.version, b.version, 'version of two reads in a row');
        assertEqual(a.generated_at, b.generated_at, 'generated_at of two reads in a row (the document is built ahead of time, not for a request)');
      },
    },
  ];
}

/** The checks on one account's part against the document its ids refer to. `getView` returns it. */
function accountChecks(getView, getDocument) {
  return [
    {
      id: 'A01', level: 'MUST', title: 'names in an account\'s part only entries of the document, each once',
      run() {
        const view = getView();
        assert(isObject(view), 'the account view is not an object');
        const ids = new Set(getDocument().entries.map((e) => e.id));
        const problems = [];
        for (const [list, prefix] of [['pieces', 'account:'], ['connected_services', 'service:'], ['tools', 'mcp_tool:']]) {
          if (view[list] === undefined) continue;
          if (!Array.isArray(view[list])) {
            problems.push(`${list} is not a list`);
            continue;
          }
          const seen = new Set();
          for (const item of view[list]) {
            if (typeof item?.id !== 'string' || !item.id.startsWith(prefix)) problems.push(`${list} has an id that is not ${prefix}`);
            else if (list !== 'connected_services' && !ids.has(item.id)) problems.push(`${list} names ${item.id}, which is not in the document`);
            if (seen.has(item?.id)) problems.push(`${list} names ${item?.id} twice`);
            seen.add(item?.id);
          }
        }
        if (problems.length > 0) fail(problems.slice(0, 8).join('; '));
      },
    },
    {
      id: 'A02', level: 'MUST', title: 'says for every mcp_tool of the document, when it says anything, whether an agent session lists it',
      run() {
        const view = getView();
        if (view.tools === undefined) return skip('the publisher does not serve tools');
        const problems = [];
        for (const item of view.tools) if (typeof item.listed !== 'boolean') problems.push(`${item.id}: listed is not true or false`);
        const tools = getDocument().entries.filter((e) => e.kind === 'mcp_tool').map((e) => e.id);
        const named = new Set(view.tools.map((item) => item.id));
        const missing = tools.filter((id) => !named.has(id));
        if (missing.length > 0) problems.push(`leaves out ${missing.length} tool(s), such as ${missing[0]}`);
        // The core is always listed to an agent: a tool of no piece and audience agent or both is true here.
        const byId = new Map(getDocument().entries.map((e) => [e.id, e]));
        for (const item of view.tools) {
          const t = byId.get(item.id)?.tool;
          if (t && t.audience === 'owner' && item.listed === true) problems.push(`${item.id}: is an owner's tool but listed to an agent`);
          if (t && t.audience !== 'owner' && t.pieces.length === 0 && item.listed === false) problems.push(`${item.id}: is part of the core but not listed to an agent`);
        }
        if (problems.length > 0) fail(problems.slice(0, 8).join('; '));
      },
    },
  ];
}

/**
 * @param {{ document?: object, accountView?: object, url?: string, headers?: Record<string, string>, fetchImpl?: typeof fetch, timeoutMs?: number }} options
 */
export async function runCatalogueSuite(options) {
  const { url, headers, fetchImpl, timeoutMs } = options;
  let document = options.document;
  if (!document && url) {
    const response = await (fetchImpl ?? fetch)(url, { headers: { accept: 'application/json', ...(headers ?? {}) }, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs ?? 10_000) });
    if (response.status !== 200) throw new Error(`the catalogue answered ${response.status}`);
    document = JSON.parse(await response.text());
  }
  if (!document) throw new Error('give a document or a url');
  const checks = documentChecks(() => document);
  if (options.accountView) checks.push(...accountChecks(() => options.accountView, () => document));
  if (url) checks.push(...transportChecks({ url, headers, fetchImpl, timeoutMs }));
  return runChecks('catalogue', checks);
}
