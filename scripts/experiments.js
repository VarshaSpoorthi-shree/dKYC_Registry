// Gas experiments for the research extensions (run against a dedicated Anvil instance).
//   anvil --port 8546 &
//   RPC_URL=http://127.0.0.1:8546 node scripts/experiments.js
// Measures full transaction gas from receipts (including the 21,000 base cost and calldata),
// so the numbers are what an account actually pays on an EVM chain.
import fs from "node:fs";
import path from "node:path";
import { ROOT } from "../server/config.js";
import { ethers, getProvider, devWallet } from "../server/chain.js";

const provider = getProvider();
const admin = devWallet(0, provider);
const providerOrg = devWallet(1, provider);
const bank = devWallet(2, provider);
const ORACLES = 5;
const oracles = Array.from({ length: ORACLES }, () => ethers.Wallet.createRandom().connect(provider));

const art = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, "out", `${name}.sol`, `${name}.json`), "utf8"));
const ROLE = { PROVIDER: ethers.id("PROVIDER_ROLE"), INSTITUTION: ethers.id("INSTITUTION_ROLE"), ORACLE: ethers.id("ORACLE_ROLE") };
const attrs = ["AGE_OVER_18", "NATIONALITY", "COUNTRY_OF_RESIDENCE"].map((n) => ethers.id(n));

let nonceFix = 0;
async function gas(txPromise) {
  const tx = await txPromise;
  const r = await tx.wait();
  return Number(r.gasUsed);
}

async function fund() {
  for (const w of oracles) await (await admin.sendTransaction({ to: w.address, value: ethers.parseEther("10") })).wait();
}

async function deploy(name, nOracles) {
  const a = art(name);
  const c = await new ethers.ContractFactory(a.abi, a.bytecode.object, admin).deploy(admin.address);
  await c.waitForDeployment();
  const r = c.connect(admin);
  await (await r.registerOrganization(providerOrg.address, ROLE.PROVIDER, "Provider")).wait();
  await (await r.registerOrganization(bank.address, ROLE.INSTITUTION, "Bank")).wait();
  for (const w of oracles.slice(0, nOracles)) await (await r.registerOrganization(w.address, ROLE.ORACLE, "Oracle")).wait();
  return c;
}

async function newCustomer() {
  const w = ethers.Wallet.createRandom().connect(provider);
  await (await admin.sendTransaction({ to: w.address, value: ethers.parseEther("1") })).wait();
  return w;
}

/** Onboards a customer and returns the screening request id emitted by decideVerification. */
async function onboard(c, user) {
  await (await c.connect(user).registerIdentity(ethers.id("c" + user.address), ethers.id("d"), "vault://x")).wait();
  const comms = attrs.map((k, i) => ethers.id(user.address + i));
  const tx = await c.connect(providerOrg).decideVerification(user.address, true, 2, 1, 365, attrs, comms);
  const rc = await tx.wait();
  const ev = rc.logs.map((l) => { try { return c.interface.parseLog(l); } catch { return null; } }).find((e) => e?.name === "ScreeningRequested");
  return { requestId: ev.args.requestId, decideGas: Number(rc.gasUsed) };
}

async function requestRescreen(c, user) {
  const rc = await (await c.connect(oracles[0]).requestScreening(user.address)).wait();
  const ev = rc.logs.map((l) => { try { return c.interface.parseLog(l); } catch { return null; } }).find((e) => e?.name === "ScreeningRequested");
  return { requestId: ev.args.requestId, gas: Number(rc.gasUsed) };
}

const results = { meta: { date: new Date().toISOString(), oracles: ORACLES, note: "full transaction gas from receipts" } };

await fund();

// ── E0 baseline: original single-oracle contract ──
{
  const c = await deploy("KYCRegistryV1", 1);
  const u = await newCustomer();
  const { requestId } = await onboard(c, u);
  const vote = await gas(c.connect(oracles[0]).fulfillScreening(requestId, false, ethers.ZeroHash, "local"));
  await (await c.connect(u).grantConsent(bank.address, 3, 30)).wait();
  const access = await gas(c.connect(bank).accessKYC(u.address));
  results.baseline = { screeningTotal: vote, accessKYC: access };
  console.log("baseline (v1):", results.baseline);
}

// ── E1 screening cost vs quorum size k (n = 5 oracles registered) ──
results.quorum = [];
for (let k = 1; k <= ORACLES; k++) {
  const c = await deploy("KYCRegistry", ORACLES);
  await (await c.connect(admin).setScreeningQuorum(k)).wait();
  const u = await newCustomer();
  const { requestId } = await onboard(c, u);
  const votes = [];
  for (let i = 0; i < k; i++) votes.push(await gas(c.connect(oracles[i]).fulfillScreening(requestId, false, ethers.id("e" + i), "local")));
  const status = (await c.connect(admin).getIdentity(u.address)).screening;
  // a periodic re-screen of an already-clear record, also finalised by k votes
  const re = await requestRescreen(c, u);
  const reVotes = [];
  for (let i = 0; i < k; i++) reVotes.push(await gas(c.connect(oracles[i]).fulfillScreening(re.requestId, false, ethers.id("r" + i), "local")));
  const row = {
    k,
    nonFinalVote: k > 1 ? votes[0] : null,
    finalVote: votes.at(-1),
    screeningTotal: votes.reduce((a, b) => a + b, 0),
    rescreenRequest: re.gas,
    rescreenTotal: re.gas + reVotes.reduce((a, b) => a + b, 0),
    finalStatus: Number(status),
  };
  results.quorum.push(row);
  console.log("quorum", row);
}

// ── E2 disagreement path: k = 3, votes clear/clear/hit → Review, then regulator resolves ──
{
  const c = await deploy("KYCRegistry", ORACLES);
  await (await c.connect(admin).setScreeningQuorum(3)).wait();
  const u = await newCustomer();
  const { requestId } = await onboard(c, u);
  const g = [];
  g.push(await gas(c.connect(oracles[0]).fulfillScreening(requestId, false, ethers.ZeroHash, "a")));
  g.push(await gas(c.connect(oracles[1]).fulfillScreening(requestId, false, ethers.ZeroHash, "b")));
  g.push(await gas(c.connect(oracles[2]).fulfillScreening(requestId, true, ethers.ZeroHash, "c")));
  const status = Number((await c.connect(admin).getIdentity(u.address)).screening);
  const resolve = await gas(c.connect(admin).resolveReview(u.address, false, "false positive after manual review"));
  results.review = { votes: g, statusAfterVotes: status, resolveReview: resolve, statusAfterResolve: Number((await c.connect(admin).getIdentity(u.address)).screening) };
  console.log("review", results.review);
}

// ── E3 freshness policy: cost of setting it and of the extra check on every audited read ──
{
  const c = await deploy("KYCRegistry", 1);
  const u = await newCustomer();
  const { requestId } = await onboard(c, u);
  await (await c.connect(oracles[0]).fulfillScreening(requestId, false, ethers.ZeroHash, "local")).wait();
  await (await c.connect(u).grantConsent(bank.address, 3, 30)).wait();
  const accessNoPolicy = await gas(c.connect(bank).accessKYC(u.address));
  const setPolicy = await gas(c.connect(bank).setFreshnessPolicy(86400));
  const accessWithPolicy = await gas(c.connect(bank).accessKYC(u.address));
  await provider.send("evm_increaseTime", [2 * 86400]);
  await provider.send("evm_mine", []);
  const accessStale = await gas(c.connect(bank).accessKYC(u.address));
  const validForStale = await c.isKYCValidFor(u.address, bank.address);
  results.freshness = { setPolicy, accessNoPolicy, accessWithPolicy, accessStale, validForStaleAfter2Days: validForStale };
  console.log("freshness", results.freshness);
}

fs.mkdirSync(path.join(ROOT, "docs"), { recursive: true });
fs.writeFileSync(path.join(ROOT, "docs", "experiments.json"), JSON.stringify(results, null, 2));

const fmt = (n) => (n == null ? "–" : n.toLocaleString("en-US"));
const md = [
  "# Gas experiments (full transaction gas from receipts)",
  "",
  `Run: ${results.meta.date} · ${ORACLES} oracles registered · local Anvil`,
  "",
  "## Baseline (original single-oracle contract)",
  "",
  `- Screening (one oracle callback): ${fmt(results.baseline.screeningTotal)} gas`,
  `- Audited access (accessKYC): ${fmt(results.baseline.accessKYC)} gas`,
  "",
  "## Screening cost vs quorum k",
  "",
  "| k | non-final vote | final vote | total initial screening | total periodic re-screen |",
  "|---|---|---|---|---|",
  ...results.quorum.map((r) => `| ${r.k} | ${fmt(r.nonFinalVote)} | ${fmt(r.finalVote)} | ${fmt(r.screeningTotal)} | ${fmt(r.rescreenTotal)} |`),
  "",
  "## Disagreement path (k = 3: clear, clear, hit)",
  "",
  `- Votes: ${results.review.votes.map(fmt).join(", ")} gas; status after votes = ${results.review.statusAfterVotes} (4 = Review)`,
  `- resolveReview by regulator: ${fmt(results.review.resolveReview)} gas; status after = ${results.review.statusAfterResolve} (2 = Clear)`,
  "",
  "## Freshness policy",
  "",
  `- setFreshnessPolicy (one-time per institution): ${fmt(results.freshness.setPolicy)} gas`,
  `- accessKYC without policy: ${fmt(results.freshness.accessNoPolicy)} gas`,
  `- accessKYC with 24 h policy: ${fmt(results.freshness.accessWithPolicy)} gas`,
  `- accessKYC with policy, screening 2 days old: ${fmt(results.freshness.accessStale)} gas (valid for this bank: ${results.freshness.validForStaleAfter2Days})`,
  "",
];
fs.writeFileSync(path.join(ROOT, "docs", "experiments.md"), md.join("\n"));
console.log("\nSaved docs/experiments.json and docs/experiments.md");
process.exit(0);
