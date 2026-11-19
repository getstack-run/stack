#!/usr/bin/env node
// stack-conformance: run a suite against your implementation.
//
//   stack-conformance decision --url https://your.host/stack/decide --secret whsec_...
//   stack-conformance events   --url https://your.host/stack/events --secret whsec_...
//   stack-conformance passport --module ./my-verifier.mjs          (exports verify(token, { jwks, issuer, audience }))
//   stack-conformance passport --command ./my-verifier [args...]   (JSON on stdin, JSON on stdout)
//   stack-conformance provider --module ./my-adapter-harness.mjs   (exports default () => ({ adapter, context?, provider? }))
//   stack-conformance record   --module ./my-verifier.mjs [--level 1|2|3]   (exports verifyPack(manifest, options))
//   stack-conformance record   --command ./stack-verify [args...] [--level 1|2|3]
//   stack-conformance webhooks --url https://your.host/stack/webhook --secret whsec_...
//   stack-conformance webhooks --module ./my-verifier.mjs --secret whsec_...   (exports verify({ headers, body, secrets, now }))
//   stack-conformance authority --module ./my-receiver.mjs [--request-alg ES256]   (exports createReceiver(config))
//   stack-conformance authority --command ./my-receiver [args...]   (JSON on stdin, JSON on stdout)
//   stack-conformance authority --delivery-url https://your.host/direct-post --delivery-key ./encryption-public-jwk.json
//   stack-conformance wallet --module ./my-client.mjs   (exports build({ appId, walletId, from, to, valueAtomic, validAfter, validBefore, nonce, sign }))
//   stack-conformance wallet --url https://your.host/v1/accounts/acct_x/wallet/payments --wallet ./test-wallet.json [--header "Authorization: Bearer ..."]
//   stack-conformance x402 --url https://your.site/priced-path [--accepts-test-payments]
//   stack-conformance x402 --module ./my-buyer.mjs   (exports pay({ paymentRequired, paymentRequiredHeader, payer, sign, now }))
//   stack-conformance rest-api --url https://your.host --api-key <test key> [--approve-command 'your-tool approve {id}'] [--probes ./probes.json]
//   stack-conformance credentials --dir ~/.stack | --module ./my-client.mjs   (exports write, writeAgentKey, read)
//   stack-conformance catalogue --file ./catalogue.json | --url https://your.host/v1/catalogue [--header "Authorization: Bearer ..."]
//   stack-conformance web-bot-auth [--signer ./signer.mjs] [--verifier ./verifier.mjs] [--directory-url https://your.host]
//   stack-conformance partner --url https://your.test --key sk_live_... [--non-partner-key ...] [--invite-email you@your.mailbox] [--release-email you@your.mailbox]
//   stack-conformance a2a --url https://your.host [--header "Authorization: Bearer ..."] [--from-agent ...] [--to-agent ...] [--other-header "Authorization: Bearer ..."]
//   stack-conformance mcp-listing --module ./open-session.mjs [--catalog ./tools.json]
//   stack-conformance service-mcp --url https://your.host/mcp --header "X-API-Key: ..." [--tool name --tool-arguments '{"a":1}']
//   stack-conformance network-verifier --module ./my-network.mjs | --command ./my-network   (exports verify(kind, token, ctx), and optionally signer)
//   stack-conformance network-service  --url https://your.host [--install-id ins_... --install-key ./install-key.pem] [--no-detection]
//   stack-conformance agent-jwt --minter ./my-minter.mjs                     (exports mint({ agentId, privateJwk }))
//   stack-conformance agent-jwt --verifier ./my-verifier.mjs                 (exports verify(token, { agentId, publicJwk }))
//   stack-conformance agent-jwt --url https://your.host --agent agt_... --key ./agent-private.jwk
//   stack-conformance agent-enrollment --url https://your.host --header "Authorization: Bearer ..." --approve-command "your-approve-program"
//   stack-conformance fleet-enrollment --url https://your.host --header "Authorization: Bearer ..." --approve-command "your-approve-program"
//   stack-conformance agent-keys --signer ./my-signer.mjs | --verifier ./my-verifier.mjs
//   stack-conformance workload-token --module ./my-acceptor.mjs              (exports accept({ kind, token, config, jwks }))
//   stack-conformance workload-exchange --url https://your.host [--no-rate-limit-checks]
//   stack-conformance oauth --url https://your.host [--no-rate-limit-checks]
//   stack-conformance oauth-client-metadata --module ./my-check.mjs          (exports validate(clientId, document), isMetadataClientId?)
//   stack-conformance passport-online --url https://your.host --header "Authorization: Bearer ..." --approve-command "your-approve-program"
//   stack-conformance agent-identity [--url https://your.host --agent ./test-agents.json] [--verifier ./verifier.mjs]
//   stack-conformance siem-exporter --module ./my-exporter-harness.mjs [--transports udp,tcp,tls,https]   (default export: (config) => ({ emit, pass, close }))
//   stack-conformance siem-collector --module ./my-collector-harness.mjs                                  (default export: ({ token }) => ({ udp?, tcp?, tls?, https?, records, close }))
//   stack-conformance sso-login --url https://your.test --configure-command "your-tool connect-sso" | --module ./connect.mjs   (exports configure({ issuer, client_id, client_secret, redirect_uri, slug }), and optionally domains { verified, verifiedElsewhere, recordRemoved })
//
// Add --json for a machine-readable report. The exit code is 0 when the
// implementation conforms (no MUST failed) and 1 otherwise; 2 is a usage error.

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import {
  commandReceiver,
  commandRecordVerifier,
  commandNetworkImplementation,
  commandVerifier,
  formatReport,
  runAuthorityReceiverSuite,
  runCatalogueSuite,
  runWalletRelaySuite,
  runX402Suite,
  walletKeyPair,
  runA2aSuite,
  runAgentIdentitySuite,
  runDecisionServerSuite,
  runEventsReceiverSuite,
  runMcpListingSuite,
  runServiceMcpSuite,
  runPartnerSuite,
  runNetworkServiceSuite,
  runNetworkVerifierSuite,
  presenterFromFunction,
  presenterFromServer,
  runAgentClaimSignerSuite,
  runAgentClaimVerifierSuite,
  runAgentEnrollmentSuite,
  runAgentJwtMinterSuite,
  runAgentJwtVerifierSuite,
  runClientMetadataSuite,
  runFleetEnrollmentSuite,
  runOAuthSuite,
  runPassportOnlineSuite,
  runPassportVerifierSuite,
  runSiemCollectorSuite,
  runSiemExporterSuite,
  runSsoLoginSuite,
  runCredentialsFilesSuite,
  runProviderAdapterSuite,
  runRecordVerifierSuite,
  runRestApiSuite,
  runWebBotAuthSuite,
  runWebhooksSuite,
  runWorkloadExchangeSuite,
  runWorkloadTokenSuite,
} from '../src/index.mjs';

const usage = () => {
  process.stderr.write(
    'usage: stack-conformance <decision|events|webhooks|passport|provider|record|catalogue|rest-api|credentials|authority|wallet|x402|web-bot-auth|partner|a2a|mcp-listing|service-mcp|network-verifier|network-service|agent-jwt|agent-enrollment|fleet-enrollment|agent-keys|workload-token|workload-exchange|oauth|oauth-client-metadata|passport-online|agent-identity|siem-exporter|siem-collector|sso-login> [options]\n' +
      '  decision, events:  --url <https://...> --secret <whsec_...>\n' +
      '  webhooks:          --url <https://...> --secret <whsec_...> | --module <file> --secret <whsec_...>\n' +
      '  passport:          --module <file> | --command <program> [-- args]\n' +
      '  provider:          --module <file>\n' +
      '  record:            --module <file> | --command <program> [-- args]   [--level 1|2|3]\n' +
      '  catalogue:         --file <catalogue.json> | --url <https://...> [--header "Name: value"]... [--account-view <account.json>]\n' +
      '  authority:         --module <file> | --command <program> [-- args]  [--request-alg EdDSA|ES256]  and/or  --delivery-url <https://...> --delivery-key <public-jwk.json>\n' +
      '  wallet:            --module <file> (a client) and/or --url <https://...> --wallet <file> [--header "Name: value"]... (a relay)\n' +
      '  x402:              --url <https://...> [--accepts-test-payments] and/or --module <file> (a client)\n' +
      '  rest-api:          --url <https://...> [--api-key <key> or STACK_CONFORMANCE_API_KEY] [--approve-command <command with {id}>] [--probes <probes.json>]\n' +
      '  credentials:       --dir <.stack directory> | --module <file exporting write, writeAgentKey, read>\n' +
      '  web-bot-auth:      [--signer <file>] [--verifier <file>] [--directory-url <https://...>]\n' +
      '  partner:           --url <https://...> --key <sk_live_...> [--non-partner-key <key>] [--invite-email <address>] [--release-email <address>]\n' +
      '  a2a:               --url <https://...> [--header "Name: value"]... [--from-agent <id> --to-agent <id>] [--other-header "Name: value"]...\n' +
      '  mcp-listing:       --module <file> [--catalog <tools.json>]\n' +
      '  service-mcp:       --url <https://...> [--header "Name: value"]... [--tool <name> [--tool-arguments <JSON object>]]\n' +
      '  network-verifier:  --module <file> | --command <program> [-- args]\n' +
      '  network-service:   --url <https://...> [--install-id <ins_...> --install-key <private key PEM file>] [--no-detection]\n' +
      '  agent-jwt:         --minter <file> | --verifier <file> | --url <https://...> --agent <id> --key <private-jwk.json>\n' +
      '  agent-enrollment:  --url <https://...> --header "Name: value"... --approve-command "<program> [args]"\n' +
      '  fleet-enrollment:  --url <https://...> --header "Name: value"... --approve-command "<program> [args]"\n' +
      '  agent-keys:        --signer <file> | --verifier <file>\n' +
      '  workload-token:    --module <file>\n' +
      '  workload-exchange: --url <https://...> [--no-rate-limit-checks]\n' +
      '  oauth:             --url <https://...> [--no-rate-limit-checks]\n' +
      '  oauth-client-metadata: --module <file>\n' +
      '  passport-online:   --url <https://...> --header "Name: value"... --approve-command "<program> [args]"\n' +
      '  agent-identity:    --url <https://...> --agent <test-agents.json> [--header "Name: value"]... [--probe-rate-limit]  and/or  --verifier <file>\n' +
      '  siem-exporter:     --module <file> [--transports udp,tcp,tls,https]\n' +
      '  siem-collector:    --module <file>\n' +
      '  sso-login:         --url <https://...> --configure-command "<program> [args]" | --module <file exporting configure>  [--redirect-uri <address>]\n' +
      '  all:               [--json]\n',
  );
  process.exit(2);
};

const [suite, ...rest] = process.argv.slice(2);
if (!suite || suite === '--help') usage();

const { values, positionals } = parseArgs({
  args: rest,
  allowPositionals: true,
  options: {
    url: { type: 'string' },
    secret: { type: 'string' },
    module: { type: 'string' },
    command: { type: 'string' },
    level: { type: 'string' },
    file: { type: 'string' },
    'account-view': { type: 'string' },
    'delivery-url': { type: 'string' },
    'delivery-key': { type: 'string' },
    'request-alg': { type: 'string' },
    wallet: { type: 'string' },
    'accepts-test-payments': { type: 'boolean', default: false },
    'api-key': { type: 'string' },
    'approve-command': { type: 'string' },
    probes: { type: 'string' },
    agent: { type: 'string' },
    'probe-rate-limit': { type: 'boolean', default: false },
    dir: { type: 'string' },
    signer: { type: 'string' },
    verifier: { type: 'string' },
    'directory-url': { type: 'string' },
    key: { type: 'string' },
    'non-partner-key': { type: 'string' },
    'invite-email': { type: 'string' },
    'release-email': { type: 'string' },
    'from-agent': { type: 'string' },
    'to-agent': { type: 'string' },
    'other-header': { type: 'string', multiple: true },
    catalog: { type: 'string' },
    tool: { type: 'string' },
    'tool-arguments': { type: 'string' },
    'install-id': { type: 'string' },
    'install-key': { type: 'string' },
    'no-detection': { type: 'boolean', default: false },
    header: { type: 'string', multiple: true },
    minter: { type: 'string' },
    'no-rate-limit-checks': { type: 'boolean', default: false },
    transports: { type: 'string' },
    'configure-command': { type: 'string' },
    'redirect-uri': { type: 'string' },
    json: { type: 'boolean', default: false },
  },
});

async function load(modulePath) {
  return import(pathToFileURL(resolve(modulePath)).href);
}

function headersOf(lines) {
  const headers = {};
  for (const line of lines ?? []) {
    const colon = line.indexOf(':');
    if (colon < 1) usage();
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  return headers;
}

/** `--approve-command "program arg"`: run with the approval id as its last argument; exit 0 means it was decided. */
function approver(command) {
  if (!command) usage();
  const [program, ...args] = command.split(/\s+/).filter(Boolean);
  return (approvalId) =>
    new Promise((resolveApproval, reject) => {
      const child = spawn(program, [...args, approvalId], { stdio: ['ignore', 'inherit', 'inherit'], shell: false });
      child.on('error', reject);
      child.on('exit', (code) => (code === 0 ? resolveApproval() : reject(new Error(`the approve command exited with ${code}`))));
    });
}

let report;
switch (suite) {
  case 'decision':
  case 'events': {
    if (!values.url || !values.secret) usage();
    const run = suite === 'decision' ? runDecisionServerSuite : runEventsReceiverSuite;
    report = await run({ url: values.url, secret: values.secret });
    break;
  }
  case 'webhooks': {
    if (!values.secret || (!values.url && !values.module)) usage();
    if (values.url) {
      report = await runWebhooksSuite({ url: values.url, secret: values.secret });
    } else {
      const mod = await load(values.module);
      const verify = mod.verify ?? mod.default;
      if (typeof verify !== 'function') usage();
      report = await runWebhooksSuite({ verify, secret: values.secret });
    }
    break;
  }
  case 'passport': {
    let verify;
    if (values.module) {
      const mod = await load(values.module);
      verify = mod.verify ?? mod.default;
    } else if (values.command) {
      verify = commandVerifier(values.command, positionals);
    }
    if (typeof verify !== 'function') usage();
    report = await runPassportVerifierSuite({ verify });
    break;
  }
  case 'provider': {
    if (!values.module) usage();
    const mod = await load(values.module);
    const make = mod.default ?? mod.createHarness;
    if (typeof make !== 'function') usage();
    report = await runProviderAdapterSuite(await make());
    break;
  }
  case 'record': {
    let verify;
    if (values.module) {
      const mod = await load(values.module);
      verify = mod.verifyPack ?? mod.default;
    } else if (values.command) {
      verify = commandRecordVerifier(values.command, positionals);
    }
    if (typeof verify !== 'function') usage();
    const level = Number(values.level ?? 1);
    if (![1, 2, 3].includes(level)) usage();
    report = await runRecordVerifierSuite({ verify, level });
    break;
  }
  case 'catalogue': {
    if (!values.file && !values.url) usage();
    const headers = {};
    for (const line of values.header ?? []) {
      const colon = line.indexOf(':');
      if (colon < 1) usage();
      headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
    }
    // A file is judged as a document; a URL is judged as a document and as a server of one.
    const document = values.file ? JSON.parse(readFileSync(resolve(values.file), 'utf8')) : undefined;
    // An account's part, when you give one, is judged against the document: its ids and what it says about the tools.
    const accountView = values['account-view'] ? JSON.parse(readFileSync(resolve(values['account-view']), 'utf8')) : undefined;
    report = await runCatalogueSuite({ ...(document ? { document } : {}), ...(accountView ? { accountView } : {}), ...(values.url ? { url: values.url } : {}), headers });
    break;
  }
  case 'authority': {
    let create;
    if (values.module) {
      const mod = await load(values.module);
      create = mod.createReceiver ?? mod.default;
    } else if (values.command) {
      create = commandReceiver(values.command, positionals);
    }
    if (!create && !values['delivery-url']) usage();
    if (values['delivery-url'] && !values['delivery-key']) usage();
    const deliveryJwk = values['delivery-key'] ? JSON.parse(readFileSync(resolve(values['delivery-key']), 'utf8')) : undefined;
    report = await runAuthorityReceiverSuite({
      ...(create ? { create } : {}),
      ...(values['delivery-url'] ? { deliveryUrl: values['delivery-url'], deliveryKey: { kid: deliveryJwk.kid, publicJwk: deliveryJwk } } : {}),
      ...(values['request-alg'] ? { requestAlg: values['request-alg'] } : {}),
    });
    break;
  }
  case 'wallet': {
    const mod = values.module ? await load(values.module) : undefined;
    const build = mod ? (mod.build ?? mod.default) : undefined;
    if (!build && !values.url) usage();
    const headers = {};
    for (const line of values.header ?? []) {
      const colon = line.indexOf(':');
      if (colon < 1) usage();
      headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
    }
    // The test wallet: { address, walletId, appId, perPaymentCapAtomic, dailyCapAtomic?, agentKeyPkcs8 } where agentKeyPkcs8 is the base64 PKCS#8 DER of the test agent key the wallet was registered with.
    const wallet = values.wallet ? JSON.parse(readFileSync(resolve(values.wallet), 'utf8')) : undefined;
    if (values.url && !wallet) usage();
    const key = walletKeyPair(wallet?.agentKeyPkcs8);
    if (values.url && !wallet.agentKeyPkcs8) usage();
    report = await runWalletRelaySuite({ ...(build ? { build } : {}), ...(values.url ? { url: values.url, wallet, headers } : {}), key });
    break;
  }
  case 'x402': {
    const mod = values.module ? await load(values.module) : undefined;
    const pay = mod ? (mod.pay ?? mod.default) : undefined;
    if (!pay && !values.url) usage();
    const headers = {};
    for (const line of values.header ?? []) {
      const colon = line.indexOf(':');
      if (colon < 1) usage();
      headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
    }
    report = await runX402Suite({ ...(pay ? { pay } : {}), ...(values.url ? { url: values.url, headers, acceptsTestPayments: values['accepts-test-payments'] } : {}) });
    break;
  }
  case 'rest-api': {
    if (!values.url) usage();
    const apiKey = values['api-key'] ?? process.env.STACK_CONFORMANCE_API_KEY;
    const probes = values.probes ? JSON.parse(readFileSync(resolve(values.probes), 'utf8')) : undefined;
    // The person who decides an approval: your own command, run with the approval id in place of {id}. The kit only
    // hands it an id made of letters, digits, _ and -.
    const approve = values['approve-command']
      ? (approvalId) => new Promise((done, failed) => {
          if (!/^gvr_[A-Za-z0-9_-]{1,64}$/.test(approvalId)) return failed(new Error('the approval id is not one the kit will pass to a command'));
          const child = spawn(values['approve-command'].replaceAll('{id}', approvalId), { shell: true, stdio: 'ignore' });
          child.on('exit', (status) => (status === 0 ? done() : failed(new Error(`the approve command failed with status ${status}`))));
        })
      : undefined;
    report = await runRestApiSuite({ url: values.url, ...(apiKey ? { apiKey } : {}), ...(approve ? { approve } : {}), ...(probes ? { probes } : {}) });
    break;
  }
  case 'credentials': {
    if (!values.dir && !values.module) usage();
    const client = values.module ? await load(values.module) : {};
    report = await runCredentialsFilesSuite({
      ...(values.dir ? { dir: resolve(values.dir) } : {}),
      ...(client.write ? { write: client.write } : {}),
      ...(client.writeAgentKey ? { writeAgentKey: client.writeAgentKey } : {}),
      ...(client.read ? { read: client.read } : {}),
    });
    break;
  }
  case 'web-bot-auth': {
    if (!values.signer && !values.verifier && !values['directory-url']) usage();
    const options = {};
    if (values.signer) {
      const make = (await load(values.signer)).default;
      if (typeof make !== 'function') usage();
      options.signer = make;
    }
    if (values.verifier) {
      const mod = await load(values.verifier);
      const verify = mod.verify ?? mod.default;
      if (typeof verify !== 'function') usage();
      options.verifier = verify;
    }
    if (values['directory-url']) {
      // The directory at a real address can be asked as that host only.
      const target = new URL(values['directory-url']);
      options.directoryHost = target.host;
      options.directory = async () => {
        const response = await fetch(new URL('/.well-known/http-message-signatures-directory', target.origin), { redirect: 'manual' });
        return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
      };
    }
    report = await runWebBotAuthSuite(options);
    break;
  }
  case 'agent-identity': {
    if (!values.url && !values.verifier) usage();
    const options = {};
    if (values.url) {
      // The test agents: { known: { key_id, site, agent_id, showName?, name? }, closed?: { agent_id, key_id?, site? }, hidden?: { key_id, site, agent_id } }.
      if (!values.agent) usage();
      Object.assign(options, JSON.parse(readFileSync(resolve(values.agent), 'utf8')), { url: values.url, probeRateLimit: values['probe-rate-limit'] });
      options.headers = {};
      for (const line of values.header ?? []) {
        const colon = line.indexOf(':');
        if (colon < 1) usage();
        options.headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
      }
    }
    if (values.verifier) {
      const mod = await load(values.verifier);
      const verify = mod.verify ?? mod.default;
      if (typeof verify !== 'function') usage();
      options.verifier = verify;
      options.vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../fixtures/agent-identity/vectors.json', import.meta.url)), 'utf8'));
    }
    report = await runAgentIdentitySuite(options);
    break;
  }
  case 'partner': {
    if (!values.url || !values.key) usage();
    report = await runPartnerSuite({
      url: values.url,
      partnerKey: values.key,
      ...(values['non-partner-key'] ? { nonPartnerKey: values['non-partner-key'] } : {}),
      ...(values['invite-email'] ? { inviteEmail: values['invite-email'] } : {}),
      ...(values['release-email'] ? { releaseEmail: values['release-email'] } : {}),
    });
    break;
  }
  case 'a2a': {
    if (!values.url) usage();
    const toHeaders = (lines) => {
      const out = {};
      for (const line of lines ?? []) {
        const colon = line.indexOf(':');
        if (colon < 1) usage();
        out[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
      }
      return out;
    };
    report = await runA2aSuite({
      url: values.url,
      headers: toHeaders(values.header),
      ...(values['other-header'] ? { otherHeaders: toHeaders(values['other-header']) } : {}),
      ...(values['from-agent'] ? { fromAgent: values['from-agent'] } : {}),
      ...(values['to-agent'] ? { toAgent: values['to-agent'] } : {}),
    });
    break;
  }
  case 'mcp-listing': {
    if (!values.module) usage();
    const open = (await load(values.module)).default;
    if (typeof open !== 'function') usage();
    // The catalog defaults to the specification's, next to this kit in a checkout of the repository.
    const catalogPath = values.catalog ? resolve(values.catalog) : fileURLToPath(new URL('../../mcp-tools/tools.json', import.meta.url));
    report = await runMcpListingSuite({ open, catalog: JSON.parse(readFileSync(catalogPath, 'utf8')) });
    break;
  }
  case 'service-mcp': {
    if (!values.url) usage();
    let args = {};
    if (values['tool-arguments'] !== undefined) {
      if (!values.tool) usage();
      try { args = JSON.parse(values['tool-arguments']); } catch { usage(); }
      if (typeof args !== 'object' || args === null || Array.isArray(args)) usage();
    }
    report = await runServiceMcpSuite({
      url: values.url,
      headers: headersOf(values.header),
      ...(values.tool ? { tool: { name: values.tool, arguments: args } } : {}),
    });
    break;
  }
  case 'network-verifier': {
    let implementation;
    if (values.module) {
      const mod = await load(values.module);
      implementation = mod.default && typeof mod.default === 'object' ? mod.default : { verify: mod.verify ?? mod.default, signer: mod.signer };
    } else if (values.command) {
      implementation = commandNetworkImplementation(values.command, positionals);
    }
    if (typeof implementation?.verify !== 'function') usage();
    report = await runNetworkVerifierSuite(implementation);
    break;
  }
  case 'network-service': {
    if (!values.url) usage();
    if (Boolean(values['install-id']) !== Boolean(values['install-key'])) usage();
    const install = values['install-id']
      ? { id: values['install-id'], privateKeyPem: readFileSync(resolve(values['install-key']), 'utf8') }
      : undefined;
    report = await runNetworkServiceSuite({ url: values.url, ...(install ? { install } : {}), detection: !values['no-detection'] });
    break;
  }
  case 'agent-jwt': {
    if (values.minter) {
      const mod = await load(values.minter);
      const mint = mod.mint ?? mod.default;
      if (typeof mint !== 'function') usage();
      report = await runAgentJwtMinterSuite({ mint });
    } else if (values.verifier) {
      const mod = await load(values.verifier);
      const verify = mod.verify ?? mod.default;
      if (typeof verify !== 'function') usage();
      report = await runAgentJwtVerifierSuite(presenterFromFunction(verify));
    } else if (values.url && values.agent && values.key) {
      const privateJwk = JSON.parse(readFileSync(resolve(values.key), 'utf8'));
      report = await runAgentJwtVerifierSuite(presenterFromServer({ baseUrl: values.url, agentId: values.agent, privateJwk }));
    } else usage();
    break;
  }
  case 'agent-enrollment':
  case 'fleet-enrollment':
  case 'passport-online': {
    if (!values.url || !values['approve-command'] || !(values.header ?? []).length) usage();
    const common = { baseUrl: values.url, headers: headersOf(values.header), approve: approver(values['approve-command']) };
    if (suite === 'agent-enrollment') {
      report = await runAgentEnrollmentSuite(common);
    } else if (suite === 'fleet-enrollment') {
      report = await runFleetEnrollmentSuite(common);
    } else {
      report = await runPassportOnlineSuite(common);
    }
    break;
  }
  case 'agent-keys': {
    if (values.signer) {
      const mod = await load(values.signer);
      const sign = mod.sign ?? mod.default;
      if (typeof sign !== 'function') usage();
      report = await runAgentClaimSignerSuite({ sign });
    } else if (values.verifier) {
      const mod = await load(values.verifier);
      const verify = mod.verify ?? mod.default;
      if (typeof verify !== 'function') usage();
      report = await runAgentClaimVerifierSuite({ verify });
    } else usage();
    break;
  }
  case 'workload-token':
  case 'oauth-client-metadata': {
    if (!values.module) usage();
    const mod = await load(values.module);
    if (suite === 'workload-token') {
      const accept = mod.accept ?? mod.default;
      if (typeof accept !== 'function') usage();
      report = await runWorkloadTokenSuite({ accept });
    } else {
      const validate = mod.validate ?? mod.default;
      if (typeof validate !== 'function') usage();
      report = await runClientMetadataSuite({ validate, ...(typeof mod.isMetadataClientId === 'function' ? { isMetadataClientId: mod.isMetadataClientId } : {}) });
    }
    break;
  }
  case 'workload-exchange':
  case 'oauth': {
    if (!values.url) usage();
    const run = suite === 'oauth' ? runOAuthSuite : runWorkloadExchangeSuite;
    report = await run({ baseUrl: values.url, rateLimits: !values['no-rate-limit-checks'] });
    break;
  }
  case 'siem-exporter': {
    if (!values.module) usage();
    const mod = await load(values.module);
    const exporter = mod.createExporter ?? mod.default;
    if (typeof exporter !== 'function') usage();
    report = await runSiemExporterSuite({ exporter, ...(values.transports ? { transports: values.transports.split(',').map((s) => s.trim()).filter(Boolean) } : {}) });
    break;
  }
  case 'siem-collector': {
    if (!values.module) usage();
    const mod = await load(values.module);
    const collector = mod.createCollector ?? mod.default;
    if (typeof collector !== 'function') usage();
    report = await runSiemCollectorSuite({ collector });
    break;
  }
  case 'sso-login': {
    if (!values.url) usage();
    let configure;
    let domains;
    if (values.module) {
      const mod = await load(values.module);
      configure = mod.configure ?? mod.default;
      if (typeof configure !== 'function') usage();
      // Optional: how to verify a domain for the account, so the checks of section 9.5 run.
      if (mod.domains) domains = mod.domains;
    } else if (values['configure-command']) {
      const [program, ...args] = values['configure-command'].split(/\s+/).filter(Boolean);
      configure = (connection) =>
        new Promise((resolveConfigure, reject) => {
          const child = spawn(program, args, { stdio: ['pipe', 'inherit', 'inherit'], shell: false });
          child.on('error', reject);
          child.on('exit', (code) => (code === 0 ? resolveConfigure() : reject(new Error(`the configure command exited with ${code}`))));
          child.stdin.end(JSON.stringify(connection));
        });
    } else usage();
    report = await runSsoLoginSuite({ baseUrl: values.url, configure, ...(domains ? { domains } : {}), ...(values['redirect-uri'] ? { redirectUri: values['redirect-uri'] } : {}) });
    break;
  }
  default:
    usage();
}

process.stdout.write(values.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatReport(report)}\n`);
process.exit(report.conforms ? 0 : 1);
