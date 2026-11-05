// Chainlink Functions source — executed by the Decentralized Oracle Network (DON).
// Used by src/chainlink/KYCScreeningFunctions.sol on a testnet (e.g. Sepolia / Base Sepolia).
//
// args[0]   = customer wallet address (pseudonymous; the only thing that goes on-chain)
// secrets   = { VAULT_API, VAULT_ORACLE_TOKEN, OPENSANCTIONS_API_KEY }  (DON-hosted, encrypted)
// returns   = abi.encode(bool hit, bytes32 evidenceHash)
//
// Flow: DON → vault API (oracle token) → applicant name/dob → OpenSanctions /match → result.
// The vault endpoint /api/oracle/subject/:address is enabled by setting ORACLE_API_TOKEN on a publicly
// reachable deployment of the server (the local demo uses the embedded oracle in server/oracle.js instead).

const subject = args[0];

const subjectResp = await Functions.makeHttpRequest({
  url: `${secrets.VAULT_API}/api/oracle/subject/${subject}`,
  headers: { Authorization: `Bearer ${secrets.VAULT_ORACLE_TOKEN}` },
  timeout: 8000,
});
if (subjectResp.error) throw Error("vault request failed");
const { fullName, dob, nationality } = subjectResp.data;

const match = await Functions.makeHttpRequest({
  url: "https://api.opensanctions.org/match/default?algorithm=logic-v1",
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `ApiKey ${secrets.OPENSANCTIONS_API_KEY}` },
  data: {
    queries: {
      q: {
        schema: "Person",
        properties: { name: [fullName], ...(dob ? { birthDate: [dob] } : {}), ...(nationality ? { nationality: [nationality] } : {}) },
      },
    },
  },
  timeout: 9000,
});
if (match.error) throw Error("screening API failed");

const results = (match.data.responses.q.results || []).filter((r) => r.match || r.score >= 0.7);
const hit = results.length > 0;

// Evidence hash: keccak-free digest available in the Functions runtime (SHA-256 via WebCrypto)
const evidence = JSON.stringify({ subject, hit, ids: results.map((r) => r.id), scores: results.map((r) => r.score), at: Date.now() });
const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(evidence)));

// abi.encode(bool, bytes32) = 32-byte bool word + 32-byte hash
const out = new Uint8Array(64);
out[31] = hit ? 1 : 0;
out.set(digest, 32);
return out;
