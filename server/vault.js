// Encrypted off-chain document vault.
//  - Documents are encrypted at rest with AES-256-GCM using a per-document key
//    derived via HKDF from the vault master key.
//  - documentHash = sha256(ciphertext) is anchored on-chain, so any tampering is detectable.
//  - Release is gated by ON-CHAIN consent (SCOPE_DOCUMENTS) — see canAccess().
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { config } from "./config.js";

const VAULT_DIR = path.join(config.dataDir, "vault");
const LOG_FILE = path.join(config.dataDir, "vault-access-log.jsonl");
fs.mkdirSync(VAULT_DIR, { recursive: true });

function masterKey() {
  if (config.vaultMasterKey) return Buffer.from(config.vaultMasterKey.replace(/^0x/, ""), "hex");
  // Development fallback: a key generated once and stored locally.
  const keyFile = path.join(config.dataDir, ".vault-dev-key");
  if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(keyFile, "utf8").trim(), "hex");
}

const docKey = (docId) => Buffer.from(crypto.hkdfSync("sha256", masterKey(), Buffer.from(docId), Buffer.from("dkyc-vault-v1"), 32));
const sha256hex = (buf) => "0x" + crypto.createHash("sha256").update(buf).digest("hex");
const validId = (id) => typeof id === "string" && /^[a-f0-9]{32}$/.test(id);

export function store(owner, payloadString) {
  const docId = crypto.randomBytes(16).toString("hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", docKey(docId), iv);
  cipher.setAAD(Buffer.from(owner.toLowerCase()));
  const ciphertext = Buffer.concat([cipher.update(payloadString, "utf8"), cipher.final()]);
  const record = {
    docId,
    owner: owner.toLowerCase(),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    documentHash: sha256hex(ciphertext),
    createdAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(VAULT_DIR, `${docId}.json`), JSON.stringify(record));
  return { docId, vaultURI: `vault://${docId}`, documentHash: record.documentHash };
}

export function getRecord(docId) {
  if (!validId(docId)) return null;
  const f = path.join(VAULT_DIR, `${docId}.json`);
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : null;
}

/** Decrypts and re-checks integrity (sha256 of ciphertext). */
export function open(record) {
  const ciphertext = Buffer.from(record.ciphertext, "base64");
  const integrityOk = sha256hex(ciphertext) === record.documentHash;
  const decipher = crypto.createDecipheriv("aes-256-gcm", docKey(record.docId), Buffer.from(record.iv, "base64"));
  decipher.setAAD(Buffer.from(record.owner));
  decipher.setAuthTag(Buffer.from(record.tag, "base64"));
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return { payload: JSON.parse(plaintext), integrityOk };
}

export const docIdFromURI = (uri) => (typeof uri === "string" && uri.startsWith("vault://") ? uri.slice(8) : null);

export function logAccess(entry) {
  fs.appendFileSync(LOG_FILE, JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n");
}

export function readAccessLog(owner) {
  if (!fs.existsSync(LOG_FILE)) return [];
  return fs
    .readFileSync(LOG_FILE, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l))
    .filter((e) => !owner || e.owner === owner.toLowerCase())
    .reverse();
}
