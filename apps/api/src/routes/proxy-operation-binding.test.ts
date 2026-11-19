// The operation-binding contract is implemented below the route so every REST,
// MCP and SDK caller reaches the same canonicalizer. Import the contract suite
// here to keep the signed route-level acceptance command authoritative.
import '../lib/prepared-proxy-request.test.js';
