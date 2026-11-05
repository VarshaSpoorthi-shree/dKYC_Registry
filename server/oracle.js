// Off-chain oracle node.
//  1. Watches ScreeningRequested events from KYCRegistry.
//  2. Loads the applicant's details from the encrypted vault (oracle is a trusted, role-gated party).
//  3. Screens them against live sanctions / PEP sources (see screening.js).
//  4. Stores the full evidence report off-chain and writes the result + evidence hash on-chain.
//  5. Perpetual KYC: periodically re-screens every valid customer so a new sanctions listing
//     invalidates their KYC everywhere, instantly.
// Production alternative: src/chainlink/KYCScreeningFunctions.sol + chainlink/screening-source.js
import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";
import { ethers, getProvider, getOracleWallet, getRegistry, loadDeployment } from "./chain.js";
// Each OracleNode is one independent oracle identity. With a k-of-n quorum on-chain, several nodes
// vote on every request; the contract finalises once k agree (or escalates to review if they differ).
import * as vault from "./vault.js";
import { screen } from "./screening.js";

const REPORT_DIR = path.join(config.dataDir, "screening-reports");
fs.mkdirSync(REPORT_DIR, { recursive: true });

export class OracleNode {
  constructor(wallet, index = 0) {
    this.provider = getProvider();
    this.wallet = wallet ? wallet.connect(this.provider) : getOracleWallet(this.provider);
    this.index = index;
    this.name = `oracle ${String.fromCharCode(65 + index)}`;
    this.registry = getRegistry(this.wallet);
    this.lastBlock = Number(loadDeployment().deployBlock || 0) - 1;
    this.processed = 0;
    this.hits = 0;
    this.lastError = null;
    this.lastRescreen = Date.now(); // first perpetual re-screen after one interval
    this.attempts = new Map();
    this.busy = false;
    this.recent = [];
  }

  log(...a) { console.log(`[${this.name} ${new Date().toISOString().slice(11, 19)}]`, ...a); }

  async start() {
    const isOracle = await this.registry.hasRole(ethers.id("ORACLE_ROLE"), this.wallet.address);
    if (!isOracle) this.log(`WARNING ${this.wallet.address} does not hold ORACLE_ROLE — results will revert.`);
    this.log(`running as ${this.wallet.address}, polling every ${config.oraclePollMs}ms`);
    this.timer = setInterval(() => this.tick().catch((e) => { this.lastError = e.message; this.log("tick error:", e.message); }), config.oraclePollMs);
    await this.tick();
  }

  stop() { clearInterval(this.timer); }

  async tick() {
    if (this.busy) return;
    this.busy = true;
    try {
      const head = await this.provider.getBlockNumber();
      if (head > this.lastBlock) {
        const events = await this.registry.queryFilter(this.registry.filters.ScreeningRequested(), this.lastBlock + 1, head);
        for (const ev of events) {
          const id = ev.args.requestId;
          try {
            await this.handle(id, ev.args.subject);
          } catch (e) {
            const n = (this.attempts.get(id) || 0) + 1;
            this.attempts.set(id, n);
            this.lastError = `${id.slice(0, 10)}…: ${e.message}`;
            this.log(`attempt ${n} failed: ${e.message}`);
            if (n < 5) return; // keep lastBlock so this block range is retried next tick
          }
        }
        this.lastBlock = head;
      }
      // only the first node schedules perpetual re-screens (every node then votes on them)
      if (this.index === 0 && config.rescreenIntervalMin > 0 && Date.now() - this.lastRescreen > config.rescreenIntervalMin * 60e3) {
        this.lastRescreen = Date.now();
        await this.rescreenAll();
      }
    } finally {
      this.busy = false;
    }
  }

  async handle(requestId, subject) {
    const req = await this.registry.screeningRequests(requestId);
    if (req.fulfilled || (await this.registry.hasVoted(requestId, this.wallet.address))) return;
    this.log(`screening request ${requestId.slice(0, 10)}… for ${subject}`);

    const identity = await this.registry.getIdentity(subject);
    const record = vault.getRecord(vault.docIdFromURI(identity.vaultURI));
    if (!record) throw new Error(`vault document missing for ${subject}`);
    const { payload, integrityOk } = vault.open(record);
    if (!integrityOk || record.documentHash !== identity.documentHash) throw new Error(`document integrity failure for ${subject}`);
    vault.logAccess({ owner: subject.toLowerCase(), docId: record.docId, requester: this.wallet.address.toLowerCase(), role: "oracle", purpose: "sanctions/PEP screening" });

    const p = payload.profile;
    const report = await screen({ fullName: p.fullName, dob: p.dob, nationality: p.nationality });
    const stored = { requestId, subject, ...report };
    const json = JSON.stringify(stored);
    const evidenceHash = ethers.keccak256(ethers.toUtf8Bytes(json));
    fs.writeFileSync(path.join(REPORT_DIR, `${requestId}-${this.wallet.address.toLowerCase()}.json`), json);

    let tx;
    try {
      // Fixed gas limit: the gas estimate is taken before other oracles' votes land, and the vote
      // that completes the quorum costs more (it finalises the record), so an estimate can run short.
      tx = await this.registry.fulfillScreening(requestId, report.hit, evidenceHash, report.sourcesUsed.join("+"), { gasLimit: 250_000 });
      await tx.wait();
    } catch (e) {
      // another oracle may have completed the quorum while we were screening
      const again = await this.registry.screeningRequests(requestId);
      if (again.fulfilled) {
        this.log(`request ${requestId.slice(0, 10)}… already finalised by the other oracles`);
        return;
      }
      throw e;
    }
    this.processed++;
    if (report.hit) this.hits++;
    this.recent.unshift({ requestId, subject, hit: report.hit, sources: report.sourcesUsed, at: report.screenedAt, tx: tx.hash });
    this.recent = this.recent.slice(0, 20);
    this.log(`→ ${report.hit ? "HIT" : "clear"} (${report.sourcesUsed.join(", ")}) tx ${tx.hash.slice(0, 10)}…`);
  }

  async rescreenAll() {
    const n = Number(await this.registry.subjectCount());
    const subjects = n ? await this.registry.getSubjects(0, n) : [];
    let count = 0;
    for (const s of subjects) {
      if (!(await this.registry.isKYCValid(s))) continue;
      const tx = await this.registry.requestScreening(s);
      await tx.wait();
      count++;
    }
    if (count) this.log(`perpetual KYC: queued re-screening for ${count} customer(s)`);
  }

  status() {
    return {
      name: this.name,
      address: this.wallet.address,
      lastBlock: this.lastBlock,
      processed: this.processed,
      hits: this.hits,
      lastError: this.lastError,
      rescreenIntervalMin: config.rescreenIntervalMin,
      recent: this.recent,
    };
  }
}

/** All oracles' evidence reports for one request (one file per voting oracle). */
export function readReports(requestId) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(requestId)) return [];
  return fs
    .readdirSync(REPORT_DIR)
    .filter((f) => f.startsWith(requestId.toLowerCase()) || f.startsWith(requestId))
    .map((f) => ({ oracle: f.slice(67, -5) || null, ...JSON.parse(fs.readFileSync(path.join(REPORT_DIR, f), "utf8")) }));
}

// Allow running standalone:  node server/oracle.js
if (import.meta.url === `file://${process.argv[1]}`) {
  new OracleNode().start();
}
