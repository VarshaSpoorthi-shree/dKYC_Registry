// Blockchain connection helpers shared by the API server, oracle and scripts.
import fs from "node:fs";
import { ethers } from "../vendor/ethers.js";
import { config, DEV_MNEMONIC } from "./config.js";

export { ethers };

export function loadDeployment() {
  if (!fs.existsSync(config.deploymentFile)) {
    throw new Error(`No deployment found at ${config.deploymentFile}. Run "npm run deploy" first.`);
  }
  return JSON.parse(fs.readFileSync(config.deploymentFile, "utf8"));
}

export function getProvider() {
  const p = new ethers.JsonRpcProvider(config.rpcUrl, undefined, { staticNetwork: true, cacheTimeout: -1 });
  p.pollingInterval = 1000;
  return p;
}

/** Dev account i derived from the public Anvil mnemonic. */
export function devWallet(i, provider) {
  const w = ethers.HDNodeWallet.fromPhrase(DEV_MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`);
  return provider ? w.connect(provider) : w;
}

export function getOracleWallet(provider) {
  if (config.oraclePrivateKey) return new ethers.Wallet(config.oraclePrivateKey, provider);
  return devWallet(9, provider);
}

/** All oracle signers run by this server (independent identities voting on each request). */
export function getOracleWallets(provider) {
  if (config.oraclePrivateKeys.length) return config.oraclePrivateKeys.map((k) => new ethers.Wallet(k, provider));
  if (config.oraclePrivateKey) return [new ethers.Wallet(config.oraclePrivateKey, provider)];
  return [9, 8, 7].slice(0, Math.max(1, config.oracleCount)).map((i) => devWallet(i, provider));
}

export function getRegistry(runner) {
  const d = loadDeployment();
  return new ethers.Contract(d.address, d.abi, runner);
}

export const SCOPES = { STATUS: 1, RISK: 2, ATTRIBUTES: 4, DOCUMENTS: 8 };
export const ROLES = {
  ADMIN: ethers.ZeroHash,
  PROVIDER: ethers.id("PROVIDER_ROLE"),
  INSTITUTION: ethers.id("INSTITUTION_ROLE"),
  ORACLE: ethers.id("ORACLE_ROLE"),
};

// ───── Commitment helpers (identical logic lives in frontend/app.js) ─────
const coder = ethers.AbiCoder.defaultAbiCoder();
export const normName = (s) => s.normalize("NFKD").replace(/[̀-ͯ]/g, "").toUpperCase().replace(/\s+/g, " ").trim();

export function identityCommitment(owner, fullName, dob, idNumber, salt) {
  return ethers.keccak256(
    coder.encode(["address", "string", "string", "string", "bytes32"], [owner, normName(fullName), dob, idNumber.toUpperCase().trim(), salt]),
  );
}
export const attrKey = (name) => ethers.id(name);
export function attrCommitment(owner, name, value, salt) {
  return ethers.keccak256(coder.encode(["address", "bytes32", "string", "bytes32"], [owner, attrKey(name), value, salt]));
}

// ───── Signed-request helpers (wallet authentication for the vault API) ─────
export const uploadMessage = (owner, payloadHash, ts) =>
  `DKYC vault upload\nowner:${owner.toLowerCase()}\npayloadHash:${payloadHash}\ntimestamp:${ts}`;
export const accessMessage = (docId, requester, ts) =>
  `DKYC vault access\ndoc:${docId}\nrequester:${requester.toLowerCase()}\ntimestamp:${ts}`;
