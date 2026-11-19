// The STACK conformance kit. Each suite takes your implementation (a URL, a
// function, an adapter) and returns a report; `formatReport` prints one.

export { formatReport, runChecks } from './harness.mjs';
export { runDecisionServerSuite, buildDecisionRequest, readAnswer, ACTION_TARGETS } from './decision-server.mjs';
export { runEventsReceiverSuite, makeBatch, makeEvents } from './events-receiver.mjs';
export { runPassportVerifierSuite, commandVerifier, keyFromSeed, signJwt } from './passport-verifier.mjs';
export { runProviderAdapterSuite, ACCOUNT_PIECE_KINDS } from './provider-adapter.mjs';
export { runCatalogueSuite, catalogueVersion } from './catalogue-document.mjs';
export { runRecordVerifierSuite, commandRecordVerifier, loadRecordFixtures } from './record-verifier.mjs';
export { signMessage, verifyMessage } from './webhook.mjs';
export { runWebhooksSuite, makeWebhookBody, LEGACY_SECRET } from './webhooks.mjs';
export { runRestApiSuite, envelopeProblem, defaultStepUp } from './rest-api.mjs';
export { runCredentialsFilesSuite, credentialsProblem, agentKeyProblem, makeAgentKey, makeCredentials } from './credentials-files.mjs';
export { runNetworkVerifierSuite, commandNetworkImplementation } from './network-verifier.mjs';
export { runNetworkServiceSuite, verifyStackObject } from './network-service.mjs';
export { buildNetworkVectors, VECTOR_NOW } from './network-vectors.mjs';
export { canonicalize } from './canonical.mjs';
export { merkleRoot } from './merkle.mjs';
export { runAuthorityReceiverSuite, commandReceiver, receiverConfig, readReceiverJws } from './authority-receiver.mjs';
export { FIXTURE as AUTHORITY_FIXTURE, fixtureKeys as authorityFixtureKeys } from './authority-fixtures.mjs';
export { runWalletRelaySuite, walletKeyPair, typedDataFor, signingString } from './wallet-relay.mjs';
export { runX402Suite, paymentFor, readRequirements } from './x402-site.mjs';
export { runWebBotAuthSuite } from './web-bot-auth.mjs';
export { runA2aSuite } from './a2a.mjs';
export { runAgentIdentitySuite, judgeStatement, signStatement, statementClaims, testKey, TEST_ISSUER_KEY, TEST_RETIRED_KEY } from './agent-identity.mjs';
export { runMcpListingSuite, isListed } from './mcp-listing.mjs';
export {
  runServiceMcpSuite,
  SERVICE_MCP_ACCEPT,
  SERVICE_MCP_PROTOCOL_VERSION,
  initializeBody as serviceMcpInitializeBody,
  INITIALIZED_BODY as SERVICE_MCP_INITIALIZED_BODY,
} from './service-mcp.mjs';
export { runPartnerSuite, RELEASE_STATUSES } from './partner.mjs';
export { runAgentJwtMinterSuite, runAgentJwtVerifierSuite, presenterFromFunction, presenterFromServer } from './agent-jwt.mjs';
export { runAgentEnrollmentSuite, enrollmentClient, registerAgent, requestChallenge, enrollBody, enrollAgent, agentJwt, signsIn } from './agent-enrollment.mjs';
export { runAgentClaimSignerSuite, runAgentClaimVerifierSuite, buildCose, sampleEnvelope, agentKid } from './agent-keys.mjs';
export { runWorkloadTokenSuite } from './workload-token.mjs';
export { runWorkloadExchangeSuite } from './workload-exchange.mjs';
export { runOAuthSuite } from './oauth.mjs';
export { runClientMetadataSuite } from './oauth-client-metadata.mjs';
export { runPassportOnlineSuite, revocationEventProblem } from './passport-online.mjs';
export { runFleetEnrollmentSuite, rotationMessage } from './fleet-enrollment.mjs';
export { runSiemExporterSuite, runSiemCollectorSuite, formatSyslogMessage, parseSyslogMessage, readOctetFrames, octetFrames, ndjson, recordProblem, makeRecords as makeSiemRecords, SIEM } from './siem-export.mjs';
export { runSsoLoginSuite } from './sso-login.mjs';
