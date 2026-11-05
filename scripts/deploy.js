// Deploys KYCRegistry from the Foundry build output and onboards the demo organisations.
//   Local (Anvil):   npm run deploy
//   Testnet:         RPC_URL=https://sepolia... PRIVATE_KEY=0x... ORACLE_ADDRESS=0x... npm run deploy
import fs from "node:fs";
import path from "node:path";
import { config, ROOT } from "../server/config.js";
import { ethers, getProvider, devWallet } from "../server/chain.js";

const artifactPath = path.join(ROOT, "out", "KYCRegistry.sol", "KYCRegistry.json");
if (!fs.existsSync(artifactPath)) {
  console.error('Build output missing. Run "forge build" first.');
  process.exit(1);
}
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

const provider = getProvider();
const { chainId } = await provider.getNetwork();
const isLocal = Number(chainId) === 31337;
const deployer = process.env.PRIVATE_KEY ? new ethers.Wallet(process.env.PRIVATE_KEY, provider) : devWallet(0, provider);

console.log(`Deploying to chain ${chainId} from ${deployer.address} ...`);
const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode.object, deployer);
const registry = await factory.deploy(deployer.address);
const receipt = await registry.deploymentTransaction().wait();
const address = await registry.getAddress();
console.log(`KYCRegistry deployed at ${address} (block ${receipt.blockNumber}, gas ${receipt.gasUsed})`);

const PROVIDER = ethers.id("PROVIDER_ROLE");
const INSTITUTION = ethers.id("INSTITUTION_ROLE");
const ORACLE = ethers.id("ORACLE_ROLE");

// Demo cast (fictional organisations) mapped to Anvil dev accounts
const demo = [
  { index: 0, label: "Regulator (Admin)", kind: "admin" },
  { index: 1, label: "TrustVerify KYC Services", kind: "provider", role: PROVIDER },
  { index: 2, label: "Bank Alpha", kind: "institution", role: INSTITUTION },
  { index: 3, label: "NeoPay FinTech", kind: "institution", role: INSTITUTION },
  { index: 4, label: "Customer — Aarav", kind: "user" },
  { index: 5, label: "Customer — Meera", kind: "user" },
  { index: 6, label: "Customer — Viktor (watchlisted)", kind: "user" },
  { index: 9, label: "Screening Oracle A", kind: "oracle", role: ORACLE },
  { index: 8, label: "Screening Oracle B", kind: "oracle", role: ORACLE },
  { index: 7, label: "Screening Oracle C", kind: "oracle", role: ORACLE },
];
const QUORUM = Number(process.env.SCREENING_QUORUM || 2);

const orgs = [];
if (isLocal) {
  for (const a of demo.filter((d) => d.role)) {
    const addr = devWallet(a.index).address;
    await (await registry.registerOrganization(addr, a.role, a.label)).wait();
    orgs.push({ address: addr, name: a.label, kind: a.kind });
    console.log(`  + ${a.kind.padEnd(11)} ${a.label.padEnd(28)} ${addr}`);
  }
  await (await registry.setScreeningQuorum(QUORUM)).wait();
  console.log(`  screening quorum: ${QUORUM} of ${await registry.oracleCount()} oracles must agree`);
} else {
  // Testnet: onboard whatever addresses are supplied
  const env = [
    ["ORACLE_ADDRESS", ORACLE, "Sanctions Screening Oracle", "oracle"],
    ["PROVIDER_ADDRESS", PROVIDER, "KYC Provider", "provider"],
    ["INSTITUTION_ADDRESS", INSTITUTION, "Partner Bank", "institution"],
  ];
  for (const [key, role, name, kind] of env) {
    if (!process.env[key]) continue;
    await (await registry.registerOrganization(process.env[key], role, name)).wait();
    orgs.push({ address: process.env[key], name, kind });
    console.log(`  + ${kind} ${process.env[key]}`);
  }
}

const out = {
  chainId: Number(chainId),
  address,
  deployBlock: receipt.blockNumber,
  deployer: deployer.address,
  deployedAt: new Date().toISOString(),
  orgs,
  demoAccounts: isLocal ? demo.map((d) => ({ index: d.index, label: d.label, kind: d.kind, address: devWallet(d.index).address })) : [],
  abi: artifact.abi,
};
fs.mkdirSync(config.dataDir, { recursive: true });
fs.writeFileSync(config.deploymentFile, JSON.stringify(out, null, 2));
console.log(`Saved ${path.relative(ROOT, config.deploymentFile)}`);
