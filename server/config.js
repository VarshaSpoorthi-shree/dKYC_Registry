// Central configuration. Values come from environment variables or a local .env file.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Tiny .env loader (no dependencies)
const envFile = path.join(ROOT, ".env");
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

// Anvil / Hardhat well-known development mnemonic (public — never use on a real network)
export const DEV_MNEMONIC = "test test test test test test test test test test test junk";

export const config = {
  port: Number(process.env.PORT || 3000),
  rpcUrl: process.env.RPC_URL || "http://127.0.0.1:8545",
  deploymentFile: path.join(ROOT, "data", "deployment.json"),
  dataDir: path.join(ROOT, "data"),
  // Oracle signer. Default = dev account #9.
  oraclePrivateKey: process.env.ORACLE_PRIVATE_KEY || "",
  // Several independent oracle signers (comma-separated keys). Local default = dev accounts #9, #8, #7.
  oraclePrivateKeys: (process.env.ORACLE_PRIVATE_KEYS || "").split(",").map((s) => s.trim()).filter(Boolean),
  oracleCount: Number(process.env.ORACLE_COUNT || 3),
  // 32-byte hex master key for the document vault (AES-256-GCM, per-document HKDF keys)
  vaultMasterKey: process.env.VAULT_MASTER_KEY || "",
  // Comma separated: local, ofac, opensanctions
  screeningSources: (process.env.SCREENING_SOURCES || "local,ofac").split(",").map((s) => s.trim()).filter(Boolean),
  // Bearer token for the Chainlink Functions DON to fetch screening inputs (endpoint disabled if empty)
  oracleApiToken: process.env.ORACLE_API_TOKEN || "",
  openSanctionsApiKey: process.env.OPENSANCTIONS_API_KEY || "",
  ofacUrl: process.env.OFAC_SDN_URL || "https://www.treasury.gov/ofac/downloads/sdn.csv",
  ofacRefreshHours: Number(process.env.OFAC_REFRESH_HOURS || 24),
  matchThreshold: Number(process.env.MATCH_THRESHOLD || 0.92),
  rescreenIntervalMin: Number(process.env.RESCREEN_INTERVAL_MIN || 30),
  oraclePollMs: Number(process.env.ORACLE_POLL_MS || 2000),
  signatureMaxAgeSec: 300,
};
