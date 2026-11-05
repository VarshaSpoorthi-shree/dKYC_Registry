// Clears local off-chain state (vault, reports, logs, deployment). Run after restarting Anvil.
import fs from "node:fs";
import path from "node:path";
import { config } from "../server/config.js";

for (const p of ["vault", "screening-reports", "vault-access-log.jsonl", "deployment.json"]) {
  fs.rmSync(path.join(config.dataDir, p), { recursive: true, force: true });
}
console.log("Local off-chain state cleared. Now run: npm run deploy");
