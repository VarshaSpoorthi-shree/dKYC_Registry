// API server + static dApp host + embedded oracle node. Zero npm dependencies.
//   GET  /                         dApp (frontend/)
//   POST /rpc                      JSON-RPC pass-through to the chain (avoids browser CORS issues)
//   GET  /api/config               contract address + ABI (+ demo accounts on local chains)
//   POST /api/vault/upload         wallet-signed upload of the encrypted KYC bundle
//   POST /api/vault/fetch          wallet-signed, ON-CHAIN-CONSENT-gated document release
//   GET  /api/vault/access-log     off-chain document access log for a customer
//   POST /api/screening/preview    run the sanctions/PEP engine without touching the chain
//   GET  /api/screening/report/:id redacted evidence report for a screening request
//   GET  /api/oracle/status        oracle + data-source health
//   GET  /api/oracle/subject/:addr screening inputs for the Chainlink DON (Bearer ORACLE_API_TOKEN)
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { config, ROOT, DEV_MNEMONIC } from "./config.js";
import { ethers, getProvider, getOracleWallet, getOracleWallets, getRegistry, loadDeployment, devWallet, uploadMessage, accessMessage, SCOPES, ROLES } from "./chain.js";
import * as vault from "./vault.js";
import { screen, sourceStatus, refreshOfac } from "./screening.js";
import { OracleNode, readReports } from "./oracle.js";

const FRONTEND = path.join(ROOT, "frontend");
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon" };
const MAX_BODY = 6 * 1024 * 1024;

const provider = getProvider();
const registryRO = () => getRegistry(getOracleWallet(provider)); // reads made "from" the oracle (allowed to read identities)
let oracles = [];

// ───────────────────────── helpers ─────────────────────────
function send(res, status, body, headers = {}) {
  const isStr = typeof body === "string" || Buffer.isBuffer(body);
  res.writeHead(status, { "Content-Type": isStr ? "text/plain" : "application/json", "X-Content-Type-Options": "nosniff", ...headers });
  res.end(isStr ? body : JSON.stringify(body, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error("Payload too large (max 6 MB)"), { status: 413 })); req.destroy(); }
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function json(req) {
  try { return JSON.parse((await readBody(req)) || "{}"); }
  catch (e) { throw Object.assign(new Error(e.status ? e.message : "Invalid JSON"), { status: e.status || 400 }); }
}

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

/** Verifies an EIP-191 signature and freshness (prevents replay of old signed requests). */
function verifySigned(message, signature, expected, ts) {
  if (!ethers.isAddress(expected)) throw bad("invalid address");
  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!Number.isFinite(age) || age > config.signatureMaxAgeSec) throw bad("signature expired — sign again", 401);
  let signer;
  try { signer = ethers.verifyMessage(message, signature); } catch { throw bad("malformed signature", 401); }
  if (signer.toLowerCase() !== expected.toLowerCase()) throw bad("signature does not match address", 401);
}

// ───────────────────────── route handlers ─────────────────────────
async function apiConfig() {
  const d = loadDeployment();
  const net = await provider.getNetwork();
  const out = { address: d.address, abi: d.abi, chainId: Number(net.chainId), deployBlock: d.deployBlock, scopes: SCOPES, roles: ROLES, orgs: d.orgs || [] };
  if (Number(net.chainId) === 31337) {
    // Public, well-known Anvil keys — exposed ONLY on the local dev chain for the role switcher.
    out.demoAccounts = (d.demoAccounts || []).map((a) => ({ ...a, privateKey: devWallet(a.index).privateKey }));
    out.devMnemonic = DEV_MNEMONIC;
  }
  return out;
}

async function vaultUpload(req) {
  const { owner, payload, timestamp, signature } = await json(req);
  if (typeof payload !== "string" || payload.length < 2) throw bad("payload must be a JSON string");
  try { JSON.parse(payload); } catch { throw bad("payload is not valid JSON"); }
  const payloadHash = ethers.sha256(ethers.toUtf8Bytes(payload));
  verifySigned(uploadMessage(owner, payloadHash, timestamp), signature, owner, timestamp);
  const parsed = JSON.parse(payload);
  if (parsed.owner?.toLowerCase() !== owner.toLowerCase()) throw bad("payload owner mismatch");
  const r = vault.store(owner, payload);
  vault.logAccess({ owner: owner.toLowerCase(), docId: r.docId, requester: owner.toLowerCase(), role: "owner", purpose: "upload" });
  return r;
}

async function vaultFetch(req) {
  const { docId, requester, timestamp, signature } = await json(req);
  verifySigned(accessMessage(docId, requester, timestamp), signature, requester, timestamp);
  const record = vault.getRecord(docId);
  if (!record) throw bad("document not found", 404);

  // ── authorisation is decided by the blockchain, not by this server ──
  const reg = registryRO();
  const owner = record.owner;
  let role = null;
  if (requester.toLowerCase() === owner) role = "owner";
  else if (await reg.hasRole(ROLES.PROVIDER, requester)) role = "provider";
  else if (await reg.hasRole(ROLES.ADMIN, requester)) role = "regulator";
  else if (await reg.hasConsent(owner, requester, SCOPES.DOCUMENTS)) role = "institution";
  if (!role) {
    vault.logAccess({ owner, docId, requester: requester.toLowerCase(), role: "denied", purpose: "no on-chain SCOPE_DOCUMENTS consent" });
    throw bad("Access denied: no active on-chain consent with SCOPE_DOCUMENTS", 403);
  }

  const identity = await reg.getIdentity(owner);
  const { payload, integrityOk } = vault.open(record);
  const anchored = identity.vaultURI === `vault://${docId}`;
  const hashMatchesChain = identity.documentHash === record.documentHash;
  vault.logAccess({ owner, docId, requester: requester.toLowerCase(), role, purpose: "document access" });
  return { docId, payload, integrity: { ciphertextHashOk: integrityOk, anchoredOnChain: anchored, hashMatchesChain, documentHash: record.documentHash } };
}

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  if (req.method === "POST" && p === "/rpc") {
    const body = await readBody(req);
    const r = await fetch(config.rpcUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    return send(res, r.status, await r.text(), { "Content-Type": "application/json" });
  }
  if (req.method === "GET" && p === "/api/health") return send(res, 200, { ok: true });
  if (req.method === "GET" && p === "/api/config") return send(res, 200, await apiConfig());
  if (req.method === "POST" && p === "/api/vault/upload") return send(res, 200, await vaultUpload(req));
  if (req.method === "POST" && p === "/api/vault/fetch") return send(res, 200, await vaultFetch(req));
  if (req.method === "GET" && p === "/api/vault/access-log") {
    const owner = url.searchParams.get("owner");
    if (!ethers.isAddress(owner)) throw bad("owner required");
    return send(res, 200, vault.readAccessLog(owner).map(({ docId, ...e }) => e));
  }
  if (req.method === "POST" && p === "/api/screening/preview") {
    const { fullName, dob, nationality } = await json(req);
    if (!fullName || String(fullName).length > 120) throw bad("fullName required");
    return send(res, 200, await screen({ fullName, dob, nationality }));
  }
  if (req.method === "POST" && p === "/api/screening/refresh") return send(res, 200, await refreshOfac(true).then(() => sourceStatus()));
  if (req.method === "GET" && p.startsWith("/api/screening/report/")) {
    const reports = readReports(p.split("/").pop());
    if (!reports.length) throw bad("report not found", 404);
    // One evidence report per voting oracle. Redacted: list-entry names are public data;
    // the applicant's own PII is never in a report.
    return send(res, 200, {
      requestId: reports[0].requestId,
      subject: reports[0].subject,
      votes: reports.map(({ oracle, ...r }) => ({ oracle, hit: r.hit, screenedAt: r.screenedAt, sourcesUsed: r.sourcesUsed, sourcesFailed: r.sourcesFailed, matches: r.matches, evidenceHash: ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(r))) })),
    });
  }
  if (req.method === "GET" && p.startsWith("/api/oracle/subject/")) {
    // Used by the Chainlink Functions DON (chainlink/screening-source.js). Disabled unless ORACLE_API_TOKEN is set.
    const token = (req.headers.authorization || "").replace(/^Bearer /, "");
    if (!config.oracleApiToken || token.length !== config.oracleApiToken.length || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(config.oracleApiToken))) throw bad("unauthorized", 401);
    const subject = p.split("/").pop();
    if (!ethers.isAddress(subject)) throw bad("invalid address");
    const identity = await registryRO().getIdentity(subject);
    const record = vault.getRecord(vault.docIdFromURI(identity.vaultURI));
    if (!record) throw bad("not found", 404);
    const { payload } = vault.open(record);
    vault.logAccess({ owner: subject.toLowerCase(), docId: record.docId, requester: "chainlink-don", role: "oracle", purpose: "sanctions/PEP screening" });
    const { fullName, dob, nationality } = payload.profile;
    return send(res, 200, { fullName, dob, nationality }); // minimum necessary data only
  }
  if (req.method === "GET" && p === "/api/oracle/status") return send(res, 200, { oracles: oracles.map((o) => o.status()), sources: sourceStatus() });

  // static files
  if (req.method === "GET") {
    const file = path.normalize(path.join(FRONTEND, p === "/" ? "index.html" : p));
    if (file.startsWith(FRONTEND) && fs.existsSync(file) && fs.statSync(file).isFile()) {
      res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "Cache-Control": "no-cache" });
      return fs.createReadStream(file).pipe(res);
    }
  }
  send(res, 404, { error: "not found" });
}

const server = http.createServer((req, res) => {
  route(req, res).catch((e) => {
    const reason = e.shortMessage || e.reason || e.message;
    if (!e.status) console.error("[api]", reason);
    send(res, e.status || 500, { error: reason });
  });
});

server.listen(config.port, async () => {
  console.log(`\n  Decentralized KYC Registry  →  http://localhost:${config.port}\n`);
  try {
    const d = loadDeployment();
    console.log(`[api] contract ${d.address} on ${config.rpcUrl}`);
  } catch (e) {
    console.error("[api]", e.message);
    return;
  }
  if (process.env.DISABLE_ORACLE !== "1") {
    oracles = getOracleWallets(provider).map((w, i) => new OracleNode(w, i));
    for (const o of oracles) o.start().catch((e) => console.error(`[${o.name}] failed to start:`, e.message));
  }
  if (config.screeningSources.includes("ofac")) {
    refreshOfac().then((s) => console.log(`[screening] OFAC SDN: ${s.entries.length} individuals${s.error ? " (" + s.error + ")" : ""}`));
  }
});
