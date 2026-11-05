// End-to-end scenario against a running chain + server (npm run chain / deploy / start).
// Walks through the whole lifecycle and asserts every expected outcome.
import { ethers, getProvider, devWallet, getRegistry, identityCommitment, attrCommitment, attrKey, uploadMessage, accessMessage, SCOPES } from "../server/chain.js";

const API = process.env.API_URL || "http://localhost:3000";
const provider = getProvider();
const W = (i) => devWallet(i, provider);
const regulator = W(0), providerOrg = W(1), bankAlpha = W(2), neoPay = W(3);
// Fresh customer wallets on every run so the demo is repeatable; funded with test ETH by the regulator account.
const aarav = ethers.Wallet.createRandom().connect(provider);
const viktor = ethers.Wallet.createRandom().connect(provider);
for (const w of [aarav, viktor]) await (await regulator.sendTransaction({ to: w.address, value: ethers.parseEther("1") })).wait();
const reg = (w) => getRegistry(w);
const STATUS = ["None", "Pending", "Verified", "Rejected", "Revoked"];
const SCREEN = ["NotScreened", "Pending", "Clear", "Hit", "Review"];

let step = 0;
const title = (t) => console.log(`\n\x1b[1m${++step}. ${t}\x1b[0m`);
const ok = (cond, msg) => {
  if (!cond) { console.error(`   \x1b[31m✗ ${msg}\x1b[0m`); process.exit(1); }
  console.log(`   \x1b[32m✓\x1b[0m ${msg}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const addr = (w) => w.getAddress();

async function post(path, body) {
  const r = await fetch(API + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json();
  return { status: r.status, ...j };
}

async function expectRevert(promise, name) {
  try { await promise; } catch (e) {
    let n = e.revert?.name;
    if (!n && e.data) try { n = reg(regulator).interface.parseError(e.data)?.name; } catch {}
    n = n || e.shortMessage || e.message;
    return ok(String(n).includes(name), `reverted with ${name}`);
  }
  ok(false, `expected revert ${name}`);
}

/** Customer side: build bundle, sign, upload to vault, anchor on-chain. Returns the private credential wallet. */
async function onboard(wallet, profile) {
  const owner = await addr(wallet);
  const identitySalt = ethers.hexlify(ethers.randomBytes(32));
  const age = Math.floor((Date.now() - Date.parse(profile.dob)) / (365.25 * 864e5));
  const claims = [
    ["AGE_OVER_18", String(age >= 18)],
    ["NATIONALITY", profile.nationality],
    ["COUNTRY_OF_RESIDENCE", profile.residence],
  ].map(([name, value]) => {
    const salt = ethers.hexlify(ethers.randomBytes(32));
    return { name, value, salt, commitment: attrCommitment(owner, name, value, salt) };
  });
  const payload = JSON.stringify({ version: 1, owner, profile, identitySalt, claims, documents: [], submittedAt: new Date().toISOString() });
  const ts = Math.floor(Date.now() / 1000);
  const signature = await wallet.signMessage(uploadMessage(owner, ethers.sha256(ethers.toUtf8Bytes(payload)), ts));
  const up = await post("/api/vault/upload", { owner, payload, timestamp: ts, signature });
  ok(up.status === 200, `encrypted bundle stored in vault (${up.vaultURI}, sha256 ${up.documentHash.slice(0, 14)}…)`);
  const commitment = identityCommitment(owner, profile.fullName, profile.dob, profile.idNumber, identitySalt);
  await (await reg(wallet).registerIdentity(commitment, up.documentHash, up.vaultURI)).wait();
  ok(Number(await reg(wallet).statusOf(owner)) === 1, "identity commitment anchored on-chain → status Pending (no PII on-chain)");
  return { owner, identitySalt, claims, vaultURI: up.vaultURI, commitment };
}

async function signedFetch(wallet, docId) {
  const requester = await addr(wallet);
  const ts = Math.floor(Date.now() / 1000);
  const signature = await wallet.signMessage(accessMessage(docId, requester, ts));
  return post("/api/vault/fetch", { docId, requester, timestamp: ts, signature });
}

/** Provider side: open the bundle, check every commitment, then decide. */
async function verify(user) {
  const r = await signedFetch(providerOrg, user.vaultURI.slice(8));
  ok(r.status === 200 && r.integrity.hashMatchesChain, "provider opened documents; ciphertext hash matches on-chain anchor");
  const { profile, identitySalt, claims } = r.payload;
  const recomputed = identityCommitment(user.owner, profile.fullName, profile.dob, profile.idNumber, identitySalt);
  const onchain = (await reg(providerOrg).getIdentity(user.owner)).identityCommitment;
  ok(recomputed === onchain, "identity commitment recomputed from documents = on-chain value");
  for (const c of claims) ok(attrCommitment(user.owner, c.name, c.value, c.salt) === c.commitment, `claim ${c.name}=${c.value} checked against documents`);
  const tx = await reg(providerOrg).decideVerification(user.owner, true, 2, 1, 365, claims.map((c) => attrKey(c.name)), claims.map((c) => c.commitment));
  await tx.wait();
  ok(true, "provider approved: tier 2, risk Low, valid 365 days, 3 attribute commitments anchored");
}

async function waitScreening(owner) {
  for (let i = 0; i < 30; i++) {
    const id = await reg(providerOrg).getIdentity(owner);
    if (Number(id.screening) >= 2) return id;
    await sleep(1000);
  }
  throw new Error("oracle did not respond — is the server running?");
}

// ════════════════════════════════════════════════════════════════
console.log(`\x1b[36mDecentralized KYC Registry — end-to-end demo\x1b[0m  (API ${API})`);
const health = await fetch(API + "/api/health").then((r) => r.ok).catch(() => false);
ok(health, "API server reachable");

title("Aarav registers once (customer)");
const aaravCred = await onboard(aarav, { fullName: "Aarav Mehta", dob: "1998-07-21", nationality: "IN", residence: "IN", idType: "PAN", idNumber: `ABCPM${Math.floor(1000 + Math.random() * 8999)}K`, address: "12 MG Road, Bengaluru", email: "aarav@example.com" });

title("TrustVerify (KYC provider) verifies Aarav");
await verify(aaravCred);
if (Number((await reg(providerOrg).getIdentity(aaravCred.owner)).screening) === 1) {
  ok(!(await reg(regulator).isKYCValid(aaravCred.owner)), "not yet valid: waiting for sanctions/PEP screening");
}

title("Oracle screens Aarav against sanctions / PEP lists");
let id = await waitScreening(aaravCred.owner);
ok(SCREEN[Number(id.screening)] === "Clear", `screening result: ${SCREEN[Number(id.screening)]}`);
{
  const k = Number(await reg(regulator).screeningQuorum());
  const n = Number(await reg(regulator).oracleCount());
  const votes = await reg(regulator).queryFilter(reg(regulator).filters.ScreeningVote(null, aaravCred.owner));
  ok(votes.length >= k, `${votes.length} independent oracle votes recorded; quorum ${k} of ${n} reached`);
}
ok(await reg(regulator).isKYCValid(aaravCred.owner), "Aarav's KYC is now VALID and reusable");

title("Bank Alpha tries to read Aarav's KYC without consent");
await expectRevert(reg(bankAlpha).accessKYC(aaravCred.owner), "NoConsent");

title("Bank Alpha requests access; Aarav grants STATUS+RISK+ATTRIBUTES for 30 days");
await (await reg(bankAlpha).requestAccess(aaravCred.owner, SCOPES.STATUS | SCOPES.RISK | SCOPES.ATTRIBUTES, "Savings account opening")).wait();
const reqs = await reg(aarav).getAccessRequests(aaravCred.owner);
ok(reqs.length >= 1, `Aarav sees access request: "${reqs[reqs.length - 1].purpose}"`);
await (await reg(aarav).grantConsent(await addr(bankAlpha), SCOPES.STATUS | SCOPES.RISK | SCOPES.ATTRIBUTES, 30)).wait();

title("Bank Alpha reuses the KYC — no new paperwork");
await (await reg(bankAlpha).accessKYC(aaravCred.owner)).wait();
const view = await reg(bankAlpha).getKYCForInstitution(aaravCred.owner);
ok(view.valid && Number(view.tier) === 2, `valid=${view.valid}, tier=${view.tier}, status=${STATUS[Number(view.status)]}, screening=${SCREEN[Number(view.screening)]}`);
const logs = await reg(regulator).queryFilter(reg(regulator).filters.KYCAccessed(await addr(bankAlpha), aaravCred.owner));
ok(logs.length >= 1, "access written to immutable on-chain audit log (KYCAccessed)");

title("Freshness policy: Bank Alpha only accepts screenings from the last 24 hours");
await (await reg(bankAlpha).setFreshnessPolicy(24 * 3600)).wait();
ok(await reg(bankAlpha).isKYCValidFor(aaravCred.owner, await addr(bankAlpha)), "fresh screening: valid for Bank Alpha");
await provider.send("evm_increaseTime", [2 * 24 * 3600]);
await provider.send("evm_mine", []);
ok(!(await reg(bankAlpha).isKYCValidFor(aaravCred.owner, await addr(bankAlpha))), "2 days later: too stale for Bank Alpha's policy");
ok(await reg(neoPay).isKYCValidFor(aaravCred.owner, await addr(neoPay)), "still valid for NeoPay, which sets no freshness policy");
await (await reg(bankAlpha).requestScreening(aaravCred.owner)).wait();
for (let i = 0; i < 30 && !(await reg(bankAlpha).isKYCValidFor(aaravCred.owner, await addr(bankAlpha))); i++) await sleep(1000);
ok(await reg(bankAlpha).isKYCValidFor(aaravCred.owner, await addr(bankAlpha)), "Bank Alpha requested re-screening; oracles re-voted; valid again");
await (await reg(bankAlpha).setFreshnessPolicy(0)).wait();

title("Selective disclosure: Aarav proves AGE_OVER_18 without revealing his date of birth");
const ageClaim = aaravCred.claims.find((c) => c.name === "AGE_OVER_18");
ok(await reg(bankAlpha).verifyAttribute(aaravCred.owner, attrKey("AGE_OVER_18"), ageClaim.value, ageClaim.salt), "AGE_OVER_18 = true verified against on-chain commitment");
ok(!(await reg(bankAlpha).verifyAttribute(aaravCred.owner, attrKey("NATIONALITY"), "US", aaravCred.claims[1].salt)), "forged NATIONALITY=US rejected");

title("Document vault enforces on-chain consent");
let doc = await signedFetch(bankAlpha, aaravCred.vaultURI.slice(8));
ok(doc.status === 403, "Bank Alpha denied documents (consent lacks SCOPE_DOCUMENTS)");
await (await reg(aarav).grantConsent(await addr(bankAlpha), 15, 30)).wait();
doc = await signedFetch(bankAlpha, aaravCred.vaultURI.slice(8));
ok(doc.status === 200 && doc.payload.profile.fullName === "Aarav Mehta", "after consent upgrade, documents released with integrity proof");

title("NeoPay (other institution) is still blocked");
await expectRevert(reg(neoPay).accessKYC(aaravCred.owner), "NoConsent");

title("Viktor (watchlisted name) goes through the same flow");
const vikCred = await onboard(viktor, { fullName: "Viktor Mordant", dob: "1971-02-03", nationality: "XX", residence: "IN", idType: "Passport", idNumber: "Z9988776", address: "Unknown", email: "v@example.com" });
await verify(vikCred);
id = await waitScreening(vikCred.owner);
ok(SCREEN[Number(id.screening)] === "Hit", "oracle flagged a sanctions HIT");
ok(!(await reg(regulator).isKYCValid(vikCred.owner)), "Viktor's KYC is INVALID everywhere; risk forced to High");
const fulfilled = await reg(regulator).queryFilter(reg(regulator).filters.ScreeningFulfilled(null, vikCred.owner));
const report = await fetch(`${API}/api/screening/report/${fulfilled.at(-1).args.requestId}`).then((r) => r.json());
const m = report.votes?.[0]?.matches?.[0];
ok(m, `${report.votes.length} oracle evidence reports; matched "${m.name}" on ${m.list} (score ${m.score})`);

title("Aarav revokes Bank Alpha's consent");
await (await reg(aarav).revokeConsent(await addr(bankAlpha))).wait();
await expectRevert(reg(bankAlpha).accessKYC(aaravCred.owner), "NoConsent");

console.log("\n\x1b[32m\x1b[1mAll steps passed — KYC once, reuse everywhere, with consent.\x1b[0m\n");
process.exit(0);
