/* dKYC Registry — browser dApp (vanilla JS + ethers v6 UMD). */
"use strict";
const { ethers } = window;

// ═══════════════════════════ state ═══════════════════════════
const S = {
  cfg: null,
  provider: null, // read provider (JSON-RPC via /rpc proxy)
  read: null, // read-only contract
  signer: null,
  account: null,
  c: null, // contract bound to signer
  roles: {},
  tab: "customer",
  names: {}, // address(lower) -> label
  block: 0,
  busy: false,
  ui: {}, // per-tab transient UI state
};
const STATUS = ["None", "Pending", "Verified", "Rejected", "Revoked"];
const RISK = ["Unassessed", "Low", "Medium", "High"];
const SCREEN = ["Not screened", "Pending", "Clear", "Hit", "Under review"];
const FRESH_OPTS = [[0, "No requirement"], [3600, "1 hour"], [86400, "24 hours"], [604800, "7 days"], [2592000, "30 days"]];
const ageText = (sec) => (FRESH_OPTS.find(([v]) => v === Number(sec)) || [0, `${Math.round(Number(sec) / 3600)} h`])[1];
const SCOPE_LIST = [
  [1, "STATUS", "KYC status, tier & expiry"],
  [2, "RISK", "Risk level & sanctions screening"],
  [4, "ATTRIBUTES", "Verify disclosed attributes"],
  [8, "DOCUMENTS", "Download encrypted documents"],
];
const ROLE_TAB = { customer: "user", provider: "provider", institution: "institution", regulator: "admin" };

// ═══════════════════════════ utils ═══════════════════════════
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : "—");
const nameOf = (a) => S.names[String(a).toLowerCase()];
const who = (a) => {
  const n = nameOf(a);
  return n ? `<span class="name-addr">${esc(n)}<small>${short(a)}</small></span>` : `<span class="addr" title="${esc(a)}">${short(a)}</span>`;
};
const date = (ts) => (Number(ts) ? new Date(Number(ts) * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
const dateOnly = (ts) => (Number(ts) ? new Date(Number(ts) * 1000).toLocaleDateString(undefined, { dateStyle: "medium" }) : "—");
const scopesPills = (m) => SCOPE_LIST.filter(([b]) => Number(m) & b).map(([, n]) => `<span class="pill info">${n}</span>`).join(" ") || '<span class="pill">none</span>';
const statusPill = (s) => {
  const n = STATUS[Number(s)];
  const cls = { Verified: "ok", Pending: "warn", Rejected: "bad", Revoked: "bad" }[n] || "";
  return `<span class="pill ${cls}">${n}</span>`;
};
const screenPill = (s) => {
  const n = SCREEN[Number(s)];
  return `<span class="pill ${{ Clear: "ok", Hit: "bad", Pending: "warn", "Under review": "warn" }[n] || ""}">${n}</span>`;
};
const riskPill = (r) => `<span class="pill ${["", "ok", "warn", "bad"][Number(r)]}">${RISK[Number(r)]}</span>`;
const now = () => Math.floor(Date.now() / 1000);

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "err" ? 9000 : 5000);
}

const FRIENDLY = {
  NoConsent: (a) => `No active customer consent for scope ${SCOPE_LIST.find(([b]) => b === Number(a[0]))?.[1] || ""}`.trim(),
  AlreadyRegistered: () => "Already registered (pending or currently valid)",
  NotRegistered: () => "This address has not registered an identity",
  NotPending: () => "This identity is not awaiting verification",
  NotVerified: () => "Identity is not in Verified state",
  NotInstitution: () => "Target is not a registered institution",
  NotAuthorized: () => "Your account is not authorised for this action",
  InvalidInput: () => "Invalid input",
  InvalidAddress: () => "Invalid address",
  AccessControlUnauthorizedAccount: () => "Your account does not hold the required role",
  EnforcedPause: () => "The registry is paused by the regulator",
  AlreadyFulfilled: () => "Already fulfilled",
};
function errMsg(e) {
  const data = e?.data || e?.info?.error?.data || e?.error?.data || e?.revert?.data;
  if (e?.revert?.name) return FRIENDLY[e.revert.name]?.(e.revert.args) || e.revert.name;
  if (typeof data === "string" && data.length >= 10) {
    try {
      const pe = S.read.interface.parseError(data);
      if (pe) return FRIENDLY[pe.name]?.(pe.args) || pe.name;
    } catch {}
  }
  if (e?.code === "ACTION_REJECTED") return "Rejected in wallet";
  return e?.shortMessage || e?.reason || e?.message || String(e);
}

async function api(path, body) {
  const r = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

/** Send a transaction with toasts, then refresh the view. */
async function send(label, fn) {
  if (S.busy) return;
  S.busy = true;
  document.querySelectorAll("#view button.btn").forEach((b) => (b.disabled = true));
  try {
    toast(`${label}: waiting for signature…`);
    const tx = await fn();
    toast(`${label}: submitted ${tx.hash.slice(0, 10)}…`);
    const r = await tx.wait();
    toast(`${label}: confirmed in block ${r.blockNumber}`, "ok");
    return r;
  } catch (e) {
    toast(`${label} failed — ${errMsg(e)}`, "err");
    if (e && typeof e === "object") e.toasted = true;
    throw e;
  } finally {
    S.busy = false;
    await render();
  }
}
const attempt = (p) => p.catch(() => {});

// ── commitments (must match server/chain.js and KYCRegistry.sol) ──
const coder = ethers.AbiCoder.defaultAbiCoder();
const normName = (s) => s.normalize("NFKD").replace(/[̀-ͯ]/g, "").toUpperCase().replace(/\s+/g, " ").trim();
const identityCommitment = (owner, fullName, dob, idNumber, salt) =>
  ethers.keccak256(coder.encode(["address", "string", "string", "string", "bytes32"], [owner, normName(fullName), dob, idNumber.toUpperCase().trim(), salt]));
const attrKey = (n) => ethers.id(n);
const attrCommitment = (owner, n, v, salt) => ethers.keccak256(coder.encode(["address", "bytes32", "string", "bytes32"], [owner, attrKey(n), v, salt]));
const uploadMessage = (owner, h, ts) => `DKYC vault upload\nowner:${owner.toLowerCase()}\npayloadHash:${h}\ntimestamp:${ts}`;
const accessMessage = (doc, req, ts) => `DKYC vault access\ndoc:${doc}\nrequester:${req.toLowerCase()}\ntimestamp:${ts}`;
const ageFromDob = (dob) => Math.floor((Date.now() - Date.parse(dob)) / (365.25 * 864e5));

async function vaultFetch(docId) {
  const ts = now();
  const signature = await S.signer.signMessage(accessMessage(docId, S.account, ts));
  return api("/api/vault/fetch", { docId, requester: S.account, timestamp: ts, signature });
}

// credential wallet (salts) is kept client-side only
const credKey = (a) => `dkyc-cred-${S.cfg.address}-${a.toLowerCase()}`;
const loadCred = (a) => { try { return JSON.parse(localStorage.getItem(credKey(a)) || "null"); } catch { return null; } };
const saveCred = (a, c) => { try { localStorage.setItem(credKey(a), JSON.stringify(c)); } catch {} };
function download(name, obj) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" }));
  a.download = name;
  a.click();
}
function modal(html) {
  $("#modalBody").innerHTML = html;
  $("#modal").showModal();
}

// ═══════════════════════════ wallet ═══════════════════════════
async function init() {
  S.cfg = await api("/api/config");
  S.provider = new ethers.JsonRpcProvider(location.origin + "/rpc", S.cfg.chainId, { staticNetwork: true });
  S.read = new ethers.Contract(S.cfg.address, S.cfg.abi, S.provider);
  for (const o of S.cfg.orgs) S.names[o.address.toLowerCase()] = o.name;
  for (const a of S.cfg.demoAccounts || []) S.names[a.address.toLowerCase()] ||= a.label;
  await loadOrgNames();

  const sel = $("#accountSelect");
  const opts = (S.cfg.demoAccounts || []).map((a) => `<option value="demo:${a.index}">${esc(a.label)} — ${short(a.address)}</option>`);
  if (window.ethereum) opts.push(`<option value="metamask">🦊 Connect MetaMask / browser wallet</option>`);
  if (!opts.length) opts.push(`<option value="">No wallet available — install MetaMask</option>`);
  sel.innerHTML = opts.join("");
  sel.onchange = () => useAccount(sel.value).catch((e) => toast(errMsg(e), "err"));

  document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => switchTab(b.dataset.tab)));
  const start = (location.hash || "#customer").slice(1);
  await switchTab(ROLE_TAB[start] || start === "about" ? start : "customer", true);
  setInterval(poll, 2000);
}

async function useAccount(v) {
  if (v.startsWith("demo:")) {
    const a = S.cfg.demoAccounts.find((x) => `demo:${x.index}` === v);
    S.signer = new ethers.Wallet(a.privateKey, S.provider);
  } else if (v === "metamask") {
    const bp = new ethers.BrowserProvider(window.ethereum);
    await bp.send("eth_requestAccounts", []);
    S.signer = await bp.getSigner();
    const net = await bp.getNetwork();
    if (Number(net.chainId) !== S.cfg.chainId) toast(`Wallet is on chain ${net.chainId}; switch to ${S.cfg.chainId}`, "err");
  } else return;
  $("#accountSelect").value = v;
  S.account = await S.signer.getAddress();
  S.c = new ethers.Contract(S.cfg.address, S.cfg.abi, S.signer);
  const R = S.cfg.roles;
  const [admin, provider, institution, oracle] = await Promise.all([R.ADMIN, R.PROVIDER, R.INSTITUTION, R.ORACLE].map((r) => S.read.hasRole(r, S.account)));
  S.roles = { admin, provider, institution, oracle };
  S.ui = {};
  const bal = await S.provider.getBalance(S.account);
  $("#accountMeta").innerHTML =
    `<span>${short(S.account)}</span><span>· ${Number(ethers.formatEther(bal)).toFixed(3)} ETH</span>` +
    Object.entries(S.roles).filter(([, v]) => v).map(([k]) => `<span class="pill dark">${k}</span>`).join("") +
    (!Object.values(S.roles).some(Boolean) ? `<span class="pill dark">customer</span>` : "");
  await render();
}

async function switchTab(tab, first = false) {
  S.tab = tab;
  history.replaceState(null, "", "#" + tab);
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  // Demo convenience: jump to an account that fits the selected role
  const want = ROLE_TAB[tab];
  if (S.cfg.demoAccounts?.length && want) {
    const cur = S.cfg.demoAccounts.find((a) => a.address === S.account);
    if (first || !cur || cur.kind !== want) {
      const pick = S.cfg.demoAccounts.find((a) => a.kind === want);
      if (pick) return useAccount(`demo:${pick.index}`);
    }
  } else if (first && window.ethereum) {
    return useAccount("metamask").catch(() => render());
  }
  await render();
}

async function poll() {
  try {
    const b = await S.provider.getBlockNumber();
    const paused = await S.read.paused();
    $("#chainInfo").innerHTML = `<span class="dot"></span> chain ${S.cfg.chainId} · block ${b} · registry ${short(S.cfg.address)}${paused ? ' · <span class="pill bad">PAUSED</span>' : ""}`;
    if (b !== S.block) {
      const firstPoll = S.block === 0;
      S.block = b;
      const ae = document.activeElement;
      const typing = ae?.closest?.("main") && ae.matches("input, textarea, select");
      const fileChosen = [...document.querySelectorAll("#view input[type=file]")].some((f) => f.files.length);
      if (!firstPoll && !S.busy && !typing && !fileChosen && !$("#modal").open) await render({ keep: true });
    }
  } catch {
    $("#chainInfo").innerHTML = `<span class="pill bad">chain unreachable</span>`;
  }
}

async function loadOrgNames() {
  const evs = await S.read.queryFilter(S.read.filters.OrganizationRegistered(), S.cfg.deployBlock);
  for (const e of evs) S.names[e.args.org.toLowerCase()] = e.args.name;
}

async function institutions() {
  const evs = await S.read.queryFilter(S.read.filters.OrganizationRegistered(null, S.cfg.roles.INSTITUTION), S.cfg.deployBlock);
  const uniq = [...new Set(evs.map((e) => e.args.org))];
  const active = await Promise.all(uniq.map((a) => S.read.hasRole(S.cfg.roles.INSTITUTION, a)));
  return uniq.filter((_, i) => active[i]);
}

async function allSubjects() {
  const n = Number(await S.read.subjectCount());
  return n ? [...(await S.read.getSubjects(0, n))] : [];
}

// ═══════════════════════════ render ═══════════════════════════
let renderSeq = 0;
/** Snapshot / restore form values so background refreshes never wipe what the user is typing. */
function snapshotForm() {
  const snap = {};
  document.querySelectorAll("#view input, #view select, #view textarea").forEach((el) => {
    const k = el.id || el.name;
    if (!k || el.type === "file") return;
    if (el.type === "checkbox") snap[`${k}:${el.value}`] = el.checked;
    else snap[k] = el.value;
  });
  return snap;
}
function restoreForm(snap) {
  document.querySelectorAll("#view input, #view select, #view textarea").forEach((el) => {
    const k = el.id || el.name;
    if (!k || el.type === "file") return;
    if (el.type === "checkbox") { if (`${k}:${el.value}` in snap) el.checked = snap[`${k}:${el.value}`]; }
    else if (k in snap) el.value = snap[k];
  });
}

async function render(opts = {}) {
  if (!S.cfg) return;
  const seq = ++renderSeq;
  const views = { customer: customerView, provider: providerView, institution: institutionView, regulator: regulatorView, about: aboutView };
  try {
    const html = await views[S.tab]();
    if (seq !== renderSeq) return; // a newer render started
    const scroll = window.scrollY;
    const snap = opts.keep ? snapshotForm() : null;
    $("#view").innerHTML = html;
    if (snap) restoreForm(snap);
    window.scrollTo(0, scroll);
    bind[S.tab]?.();
  } catch (e) {
    console.error(e);
    $("#view").innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="sub">${esc(errMsg(e))}</p></div>`;
  }
}

const head = (t, p, right = "") => `<div class="page-head"><div><h1>${t}</h1><p>${p}</p></div>${right}</div>`;
const roleWarning = (role, text) => (S.roles[role] ? "" : `<div class="notice">⚠ The current account does not hold the <b>${role}</b> role. ${text}</div>`);

// ───────────────────────── Customer ─────────────────────────
async function customerView() {
  const me = S.account;
  const id = await S.c.getIdentity(me);
  const status = STATUS[Number(id.status)];
  const valid = await S.read.isKYCValid(me);
  const cred = loadCred(me);
  const expired = status === "Verified" && Number(id.expiresAt) <= now();
  const canRegister = ["None", "Rejected", "Revoked"].includes(status) || expired;

  let verdict;
  if (status === "None") verdict = `<div class="verdict none"><div><div class="big">Not registered</div><small>Submit your details once — every partner bank can then reuse your KYC with your consent.</small></div></div>`;
  else if (valid) verdict = `<div class="verdict ok"><div><div class="big">✓ KYC valid & reusable</div><small>Verified by ${esc(nameOf(id.verifiedBy) || short(id.verifiedBy))} · expires ${dateOnly(id.expiresAt)}</small></div></div>`;
  else if (status === "Pending") verdict = `<div class="verdict warn"><div><div class="big">⏳ Awaiting verification</div><small>A KYC provider is reviewing your documents.</small></div></div>`;
  else if (status === "Verified" && SCREEN[Number(id.screening)] === "Under review") verdict = `<div class="verdict warn"><div><div class="big">⏳ Screening under regulator review</div><small>The screening oracles disagreed; the regulator will resolve it.</small></div></div>`;
  else if (status === "Verified" && SCREEN[Number(id.screening)] === "Pending") verdict = `<div class="verdict warn"><div><div class="big">⏳ Sanctions screening in progress</div><small>The oracle is checking sanctions / PEP lists.</small></div></div>`;
  else verdict = `<div class="verdict bad"><div><div class="big">✗ KYC not valid</div><small>${expired ? "Verification expired — please re-submit." : SCREEN[Number(id.screening)] === "Hit" ? "Flagged by sanctions / PEP screening." : `Status: ${status}`}</small></div></div>`;

  let html = head("My digital identity", "Your personal data never goes on-chain. The blockchain only holds hashes (commitments) and your consent decisions.");
  html += `<div class="grid g2">`;
  html += `<div class="card ${valid ? "hl" : ""}"><h2>KYC status</h2>${verdict}
    ${status !== "None" ? `<dl class="kv">
      <dt>Status</dt><dd>${statusPill(id.status)}</dd>
      <dt>Tier</dt><dd>${Number(id.tier) || "—"}</dd>
      <dt>Risk</dt><dd>${riskPill(id.risk)}</dd>
      <dt>Screening</dt><dd>${screenPill(id.screening)} <small>${Number(id.lastScreenedAt) ? "at " + date(id.lastScreenedAt) : ""}</small></dd>
      <dt>Registered</dt><dd>${date(id.registeredAt)}</dd>
      <dt>Identity hash</dt><dd class="mono">${short(id.identityCommitment)}</dd>
      <dt>Document hash</dt><dd class="mono">${short(id.documentHash)}</dd>
    </dl>` : ""}</div>`;

  // credential wallet
  html += `<div class="card"><h2>Credential wallet</h2><p class="sub">Secret salts that let you prove single facts (selective disclosure). Stored only in this browser — download a backup.</p>`;
  if (cred) {
    html += `<table><tr><th>Attribute</th><th>Value</th><th></th></tr>${cred.claims
      .map((c, i) => `<tr><td><b>${esc(c.name)}</b></td><td>${esc(c.value)}</td><td style="text-align:right"><button class="btn sm ghost" data-proof="${i}">Share proof</button></td></tr>`)
      .join("")}</table><div class="row end" style="margin-top:10px"><button class="btn sm ghost" id="dlCred">Download backup</button></div>`;
  } else {
    html += `<div class="empty">${status === "None" ? "Created when you register." : "No credential found in this browser. Restore a backup:"}</div>${status !== "None" ? `<input type="file" id="restoreCred" accept="application/json">` : ""}`;
  }
  html += `</div>`;

  if (canRegister) html += registrationForm(status !== "None");

  if (status !== "None") {
    const [reqs, insts, accessEv] = await Promise.all([
      S.read.getAccessRequests(me),
      S.read.getConsentedInstitutions(me),
      S.read.queryFilter(S.read.filters.KYCAccessed(null, me), S.cfg.deployBlock),
    ]);
    const consents = await Promise.all(insts.map(async (a) => ({ a, c: await S.read.getConsent(me, a) })));
    const active = new Map(consents.filter(({ c }) => c.active && Number(c.expiresAt) > now()).map(({ a, c }) => [a.toLowerCase(), c]));

    html += `<div class="card"><h2>Access requests</h2><p class="sub">Institutions asking to rely on your KYC.</p>`;
    const open = [...reqs].reverse().filter((r) => !active.has(r.institution.toLowerCase()) || (Number(active.get(r.institution.toLowerCase()).scopes) & Number(r.scopes)) !== Number(r.scopes));
    html += open.length
      ? `<table><tr><th>Institution</th><th>Scopes · purpose</th><th></th></tr>${open
          .map((r) => `<tr><td>${who(r.institution)}<br><small>${date(r.requestedAt)}</small></td><td>${scopesPills(r.scopes)}<br><small>${esc(r.purpose)}</small></td>
          <td style="text-align:right"><button class="btn sm ok" data-approve="${r.institution}" data-scopes="${r.scopes}">Approve 30d</button></td></tr>`)
          .join("")}</table>`
      : `<div class="empty">No pending requests.</div>`;
    html += `<h3>Grant consent manually</h3><div class="form">
      <label class="f">Institution<select id="gInst">${(await institutions()).map((a) => `<option value="${a}">${esc(nameOf(a) || a)}</option>`).join("")}</select></label>
      <label class="f">Duration<select id="gDays"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="365">1 year</option></select></label>
      <div class="full checks">${SCOPE_LIST.map(([b, n, d]) => `<label title="${d}"><input type="checkbox" class="gScope" value="${b}" ${b <= 2 ? "checked" : ""}> ${n}</label>`).join("")}</div>
      <div class="full row end"><button class="btn" id="grantBtn">Grant consent</button></div></div></div>`;

    html += `<div class="card"><h2>Active consents</h2><p class="sub">Revoke at any time — access stops immediately, on-chain.</p>`;
    html += consents.length
      ? `<table><tr><th>Institution</th><th>Scopes</th><th>Expires</th><th></th></tr>${consents
          .map(({ a, c }) => {
            const live = c.active && Number(c.expiresAt) > now();
            return `<tr><td>${who(a)}</td><td>${scopesPills(c.scopes)}</td><td>${live ? dateOnly(c.expiresAt) : `<span class="pill">${c.active ? "expired" : "revoked"}</span>`}</td>
            <td style="text-align:right">${live ? `<button class="btn sm danger" data-revoke="${a}">Revoke</button>` : ""}</td></tr>`;
          })
          .join("")}</table>`
      : `<div class="empty">You have not shared your KYC with anyone.</div>`;
    html += `</div>`;

    let vaultLog = [];
    try { vaultLog = await api(`/api/vault/access-log?owner=${me}`); } catch {}
    const rows = [
      ...accessEv.map((e) => ({ t: Number(e.args[4]), who: e.args.institution, what: `KYC record read (${e.args.valid ? "valid" : "invalid"})`, where: "on-chain audit log" })),
      ...vaultLog.filter((e) => e.role !== "owner").map((e) => ({ t: Date.parse(e.at) / 1000, who: e.requester, what: e.role === "denied" ? "Document access DENIED" : `Documents opened (${e.purpose})`, where: "vault log" })),
    ].sort((a, b) => b.t - a.t);
    html += `<div class="card span2"><h2>Who accessed my data</h2><p class="sub">Every institutional read is logged on-chain; document opens are logged by the vault.</p>${
      rows.length
        ? `<div class="table-wrap"><table><tr><th>When</th><th>Who</th><th>What</th><th>Source</th></tr>${rows
            .slice(0, 25)
            .map((r) => `<tr><td>${date(r.t)}</td><td>${who(r.who)}</td><td>${esc(r.what)}</td><td><span class="pill">${r.where}</span></td></tr>`)
            .join("")}</table></div>`
        : `<div class="empty">No access yet.</div>`
    }</div>`;
  }
  html += `</div>`;
  return html;
}

function registrationForm(resubmit) {
  return `<div class="card span2"><h2>${resubmit ? "Re-submit KYC" : "Register your identity"}</h2>
  <p class="sub">Your documents are encrypted in the vault; only their SHA-256 hash and a salted identity commitment are written to the blockchain.</p>
  <form class="form" id="regForm" onsubmit="return false">
    <label class="f">Full name (as on ID)<input name="fullName" required maxlength="80"></label>
    <label class="f">Date of birth<input name="dob" type="date" required></label>
    <label class="f">Nationality<select name="nationality">${["IN", "US", "GB", "AE", "SG", "DE", "XX"].map((c) => `<option>${c}</option>`).join("")}</select></label>
    <label class="f">Country of residence<select name="residence">${["IN", "US", "GB", "AE", "SG", "DE"].map((c) => `<option>${c}</option>`).join("")}</select></label>
    <label class="f">ID type<select name="idType"><option>PAN</option><option>Passport</option><option>Driving Licence</option><option>Voter ID</option></select></label>
    <label class="f">ID number<input name="idNumber" required maxlength="30"></label>
    <label class="f full">Address<input name="address" maxlength="160"></label>
    <label class="f">Email<input name="email" type="email" maxlength="80"></label>
    <label class="f">ID document scan (image/PDF, ≤ 2 MB)<input name="doc" type="file" accept="image/*,application/pdf"></label>
    <div class="full row"><button type="button" class="btn ghost" id="sampleA">Fill sample: clean customer</button><button type="button" class="btn ghost" id="sampleB">Fill sample: watch-listed name</button><span class="spacer"></span><button class="btn" id="regBtn">Encrypt, upload & register</button></div>
  </form></div>`;
}

// ───────────────────────── Provider ─────────────────────────
async function providerView() {
  let html = head("KYC verification desk", "Review submitted documents, check them against the on-chain commitments, then record the decision.");
  html += roleWarning("provider", "Switch to the KYC provider account to verify customers.");
  const subs = await allSubjects();
  const ids = await Promise.all(subs.map(async (a) => ({ a, id: await S.c.getIdentity(a).catch(() => null), valid: await S.read.isKYCValid(a) })));
  const pending = ids.filter((x) => x.id && Number(x.id.status) === 1);
  const done = ids.filter((x) => x.id && Number(x.id.status) > 1).sort((x, y) => Number(y.id.verifiedAt) - Number(x.id.verifiedAt));

  html += `<div class="grid g2"><div class="card"><h2>Review queue <span class="pill warn">${pending.length}</span></h2><p class="sub">Customers awaiting verification.</p>${
    pending.length
      ? `<table><tr><th>Customer</th><th>Submitted</th><th></th></tr>${pending
          .map((x) => `<tr><td>${who(x.a)}</td><td>${date(x.id.registeredAt)}</td><td style="text-align:right"><button class="btn sm" data-review="${x.a}">Review</button></td></tr>`)
          .join("")}</table>`
      : `<div class="empty">Queue is empty.</div>`
  }</div>`;

  html += `<div class="card"><h2>Decided</h2><p class="sub">Verification history.</p>${
    done.length
      ? `<div class="table-wrap"><table><tr><th>Customer</th><th>Status</th><th>Screening</th><th></th></tr>${done
          .map((x) => `<tr><td>${who(x.a)}</td><td>${statusPill(x.id.status)} ${x.valid ? '<span class="pill ok">valid</span>' : ""}</td><td>${screenPill(x.id.screening)}</td>
          <td style="text-align:right">${Number(x.id.status) === 2 ? `<button class="btn sm ghost" data-rescreen="${x.a}">Re-screen</button> <button class="btn sm danger" data-revokev="${x.a}">Revoke</button>` : ""}</td></tr>`)
          .join("")}</table></div>`
      : `<div class="empty">Nothing decided yet.</div>`
  }</div>`;

  const r = S.ui.review;
  if (r) html += reviewPanel(r);
  html += `</div>`;
  return html;
}

function reviewPanel(r) {
  const p = r.payload.profile;
  const age = ageFromDob(p.dob);
  const checks = [
    [r.integrity.ciphertextHashOk, "Vault ciphertext hash is intact"],
    [r.integrity.hashMatchesChain && r.integrity.anchoredOnChain, "Document hash matches the on-chain anchor"],
    [r.identityOk, "Identity commitment recomputed from documents = on-chain value"],
    ...r.payload.claims.map((c) => [attrCommitment(r.owner, c.name, c.value, c.salt) === c.commitment && claimConsistent(c, p), `Claim ${c.name} = ${c.value} is consistent with documents`]),
  ];
  const allOk = checks.every(([ok]) => ok);
  const docs = (r.payload.documents || [])
    .map((d) => (d.mime?.startsWith("image/") ? `<img class="doc-preview" alt="${esc(d.name)}" src="data:${esc(d.mime)};base64,${esc(d.dataBase64)}">` : `<div><a download="${esc(d.name)}" href="data:${esc(d.mime)};base64,${esc(d.dataBase64)}">${esc(d.name)}</a></div>`))
    .join("");
  const sc = r.screen;
  return `<div class="card span2 hl"><div class="row"><h2>Reviewing ${who(r.owner)}</h2><span class="spacer"></span><button class="btn sm ghost" id="closeReview">Close</button></div>
  <div class="grid g2" style="margin-top:10px"><div>
    <h3>Submitted profile (decrypted from vault)</h3>
    <dl class="kv"><dt>Full name</dt><dd>${esc(p.fullName)}</dd><dt>Date of birth</dt><dd>${esc(p.dob)} <small>(age ${age})</small></dd><dt>Nationality</dt><dd>${esc(p.nationality)}</dd>
    <dt>Residence</dt><dd>${esc(p.residence)}</dd><dt>${esc(p.idType)}</dt><dd>${esc(p.idNumber)}</dd><dt>Address</dt><dd>${esc(p.address)}</dd><dt>Email</dt><dd>${esc(p.email)}</dd></dl>
    ${docs ? `<h3>Documents</h3>${docs}` : `<p class="sub" style="margin-top:12px">No document scan attached.</p>`}
  </div><div>
    <h3>Automated checks</h3><ul class="checklist">${checks.map(([ok, t]) => `<li><span class="i ${ok ? "ok" : "bad"}">${ok ? "✓" : "✗"}</span>${esc(t)}</li>`).join("")}</ul>
    <h3>Sanctions / PEP pre-check</h3>${
      sc
        ? `<div>${sc.hit ? `<span class="pill bad">Potential match</span> ${sc.matches.slice(0, 3).map((m) => `${esc(m.name)} — ${esc(m.list)} (${m.score})`).join("; ")}` : '<span class="pill ok">No match</span>'} <small>sources: ${esc(sc.sourcesUsed.join(", "))}</small></div>`
        : `<button class="btn sm ghost" id="preScreen">Run pre-check</button>`
    }
    <p class="sub" style="margin-top:8px">The binding screening is always performed by the oracle after approval.</p>
    <h3>Decision</h3>
    <div class="form">
      <label class="f">Tier<select id="dTier"><option value="1">1 · Basic</option><option value="2" selected>2 · Standard</option><option value="3">3 · Enhanced (EDD)</option></select></label>
      <label class="f">Risk rating<select id="dRisk"><option value="1">Low</option><option value="2">Medium</option><option value="3">High</option></select></label>
      <label class="f">Validity<select id="dDays"><option value="180">6 months</option><option value="365" selected>1 year</option><option value="730">2 years</option></select></label>
      <div class="row end" style="align-self:end"><button class="btn danger" id="rejectBtn">Reject</button><button class="btn ok" id="approveBtn" ${allOk ? "" : "disabled title='Checks failed'"}>Approve</button></div>
    </div>
  </div></div></div>`;
}

function claimConsistent(c, p) {
  if (c.name === "AGE_OVER_18") return c.value === String(ageFromDob(p.dob) >= 18);
  if (c.name === "NATIONALITY") return c.value === p.nationality;
  if (c.name === "COUNTRY_OF_RESIDENCE") return c.value === p.residence;
  return true;
}

// ───────────────────────── Institution ─────────────────────────
async function institutionView() {
  let html = head("Customer due-diligence console", "Rely on an existing verification instead of repeating KYC. Every lookup needs customer consent and is written to the audit log.");
  html += roleWarning("institution", "Switch to Bank Alpha or NeoPay to query customer KYC.");
  const subs = await allSubjects();
  const target = S.ui.target || "";

  html += `<div class="grid g2"><div class="card"><h2>Find customer</h2><p class="sub">Customers share their wallet address with you (e.g. via QR at onboarding).</p>
    <div class="row"><input id="tAddr" placeholder="0x… customer address" value="${esc(target)}" style="flex:1"><button class="btn" id="tGo">Look up</button></div>
    ${subs.length ? `<h3>Registered addresses (public)</h3><div class="row">${subs.slice(-8).reverse().map((a) => `<button class="btn sm ghost" data-pick="${a}">${esc(nameOf(a) || short(a))}</button>`).join("")}</div>` : ""}
  </div>`;

  // my customers (consents granted to me)
  const grants = S.account ? await S.read.queryFilter(S.read.filters.ConsentGranted(null, S.account), S.cfg.deployBlock) : [];
  const custs = [...new Set(grants.map((g) => g.args.user))];
  const cons = await Promise.all(custs.map(async (u) => ({ u, c: await S.read.getConsent(u, S.account) })));
  const policy = S.roles.institution ? Number(await S.read.freshnessPolicy(S.account)) : 0;
  html += `<div class="card"><h2>Compliance policy</h2><p class="sub">Maximum age of the last sanctions screening that ${esc(nameOf(S.account) || "this institution")} accepts. Enforced on-chain on every KYC check.</p>
    <div class="row"><select id="freshSel">${FRESH_OPTS.map(([v, l]) => `<option value="${v}" ${v === policy ? "selected" : ""}>${l}</option>`).join("")}</select><button class="btn" id="freshBtn">Save policy</button>
    <span class="pill ${policy ? "info" : ""}">current: ${esc(ageText(policy))}</span></div></div>`;
  html += `<div class="card span2"><h2>Customers who shared with me</h2><p class="sub">Consents granted to ${esc(nameOf(S.account) || "this account")}.</p>${
    cons.length
      ? `<table><tr><th>Customer</th><th>Scopes</th><th>Until</th></tr>${cons
          .map(({ u, c }) => `<tr><td><a href="#" data-pick="${u}">${who(u)}</a></td><td>${scopesPills(c.scopes)}</td><td>${c.active && Number(c.expiresAt) > now() ? dateOnly(c.expiresAt) : `<span class="pill">${c.active ? "expired" : "revoked"}</span>`}</td></tr>`)
          .join("")}</table>`
      : `<div class="empty">None yet.</div>`
  }</div>`;

  if (target && ethers.isAddress(target)) {
    const pub = Number(await S.read.statusOf(target));
    const consent = await S.read.getConsent(target, S.account);
    const live = consent.active && Number(consent.expiresAt) > now();
    html += `<div class="card span2 hl"><div class="row"><h2>Customer file · ${who(target)}</h2><span class="spacer"></span>${statusPill(pub)} ${live ? `<span class="pill info">consent until ${dateOnly(consent.expiresAt)}</span> ${scopesPills(consent.scopes)}` : '<span class="pill">no consent</span>'}</div>`;
    if (pub === 0) html += `<div class="empty">This address has not registered an identity.</div>`;
    else {
      html += `<div class="grid g2" style="margin-top:12px"><div>
        <h3>1 · Request access</h3><div class="checks">${SCOPE_LIST.map(([b, n, d]) => `<label title="${d}"><input type="checkbox" class="rScope" value="${b}" ${b <= 4 ? "checked" : ""}> ${n}</label>`).join("")}</div>
        <div class="row" style="margin-top:8px"><input id="rPurpose" maxlength="140" placeholder="Purpose, e.g. Savings account opening" value="Account opening — reuse of existing KYC" style="flex:1"><button class="btn ghost" id="reqBtn">Send request</button></div>
        <h3>2 · Audited KYC check</h3><div class="row"><button class="btn" id="checkBtn">Run KYC check (logged on-chain)</button>${live && Number(consent.scopes) & 2 ? '<button class="btn ghost" id="bankRescreen">Request fresh screening</button>' : ""}</div>
        ${S.ui.result ? kycResult(S.ui.result) : ""}
      </div><div>
        <h3>3 · Verify a disclosed attribute</h3><p class="sub">Paste the proof the customer shared (their "Share proof" button).</p>
        <textarea id="proofIn" placeholder='{"attribute":"AGE_OVER_18","value":"true","salt":"0x…"}'>${esc(S.ui.proofText || "")}</textarea>
        <div class="row end" style="margin-top:8px"><button class="btn ghost" id="proofBtn">Verify against chain</button></div>
        ${S.ui.proofRes ? `<div class="verdict ${S.ui.proofRes.ok ? "ok" : "bad"}" style="margin-top:10px"><div><div class="big">${S.ui.proofRes.ok ? "✓ Proof valid" : "✗ Proof invalid"}</div><small>${esc(S.ui.proofRes.text)}</small></div></div>` : ""}
        <h3>4 · Documents</h3><div class="row"><button class="btn ghost" id="docsBtn">Open documents (needs DOCUMENTS scope)</button></div>
        ${S.ui.docs ? docsBlock(S.ui.docs) : ""}
      </div></div>`;
    }
    html += `</div>`;
  }
  html += `</div>`;
  return html;
}

function kycResult(v) {
  const reasons = [];
  if (STATUS[Number(v.status)] !== "Verified") reasons.push(`status ${STATUS[Number(v.status)]}`);
  if (Number(v.expiresAt) && Number(v.expiresAt) <= now()) reasons.push("expired");
  if (v.hasRisk && SCREEN[Number(v.screening)] !== "Clear") reasons.push(`screening ${SCREEN[Number(v.screening)]}`);
  if (v.fresh === false) reasons.push(`last screening is older than your freshness policy (${ageText(v.policy)}); request fresh screening`);
  if (!v.hasRisk && !v.valid && !reasons.length) reasons.push("screening not clear (ask for RISK scope for details)");
  return `<div style="margin-top:12px"><div class="verdict ${v.valid ? "ok" : "bad"}"><div><div class="big">${v.valid ? "✓ KYC VALID — reuse approved" : "✗ KYC NOT VALID"}</div><small>${v.valid ? "No need to repeat KYC for this customer." : "Reason: " + esc(reasons.join(", "))}</small></div></div>
  <dl class="kv"><dt>Status</dt><dd>${statusPill(v.status)}</dd><dt>Tier</dt><dd>${v.tier}</dd><dt>Verified by</dt><dd>${who(v.verifiedBy)}</dd><dt>Verified on</dt><dd>${date(v.verifiedAt)}</dd><dt>Expires</dt><dd>${date(v.expiresAt)}</dd>
  <dt>Freshness</dt><dd>${v.fresh ? '<span class="pill ok">meets policy</span>' : '<span class="pill bad">too old</span>'} <small>policy: ${esc(ageText(v.policy))}</small></dd>
  ${v.hasRisk ? `<dt>Risk</dt><dd>${riskPill(v.risk)}</dd><dt>Screening</dt><dd>${screenPill(v.screening)} <small>${date(v.lastScreenedAt)}</small></dd>` : `<dt>Risk</dt><dd><small>hidden — no RISK scope</small></dd>`}
  <dt>Audit tx</dt><dd class="mono">${short(v.tx)}</dd></dl></div>`;
}

function docsBlock(d) {
  const p = d.payload.profile;
  return `<div style="margin-top:10px"><ul class="checklist"><li><span class="i ${d.integrity.hashMatchesChain ? "ok" : "bad"}">${d.integrity.hashMatchesChain ? "✓" : "✗"}</span>Document hash matches on-chain anchor</li></ul>
  <dl class="kv" style="margin-top:8px"><dt>Name</dt><dd>${esc(p.fullName)}</dd><dt>DOB</dt><dd>${esc(p.dob)}</dd><dt>${esc(p.idType)}</dt><dd>${esc(p.idNumber)}</dd><dt>Address</dt><dd>${esc(p.address)}</dd></dl>
  ${(d.payload.documents || []).filter((x) => x.mime?.startsWith("image/")).map((x) => `<img class="doc-preview" alt="document" src="data:${esc(x.mime)};base64,${esc(x.dataBase64)}">`).join("")}</div>`;
}

// ───────────────────────── Regulator ─────────────────────────
async function regulatorView() {
  let html = head("Regulator & network governance", "Onboard accredited providers and institutions, monitor the oracle and audit every access.", "");
  html += roleWarning("admin", "Switch to the Regulator account to onboard organisations or pause the registry.");
  const subs = await allSubjects();
  const [ids, events, orgEv, health, paused, quorum, oracleCount] = await Promise.all([
    Promise.all(subs.map(async (a) => ({ a, id: await S.c.getIdentity(a).catch(() => null), valid: await S.read.isKYCValid(a) }))),
    S.read.queryFilter("*", S.cfg.deployBlock),
    S.read.queryFilter(S.read.filters.OrganizationRegistered(), S.cfg.deployBlock),
    api("/api/oracle/status").catch(() => null),
    S.read.paused(),
    S.read.screeningQuorum(),
    S.read.oracleCount(),
  ]);
  const inReview = ids.filter((x) => x.id && Number(x.id.screening) === 4);
  const count = (n) => events.filter((e) => e.fragment?.name === n).length;
  const hits = events.filter((e) => e.fragment?.name === "ScreeningFulfilled" && e.args.hit).length;
  html += `<div class="grid g4">
    <div class="card stat"><div class="n">${subs.length}</div><div class="l">Registered identities</div></div>
    <div class="card stat"><div class="n">${ids.filter((x) => x.valid).length}</div><div class="l">Valid, reusable KYC</div></div>
    <div class="card stat"><div class="n">${count("KYCAccessed")}</div><div class="l">KYC re-uses (audited reads)</div></div>
    <div class="card stat"><div class="n">${hits}</div><div class="l">Sanctions / PEP hits</div></div></div>`;

  const roleName = (r) => ({ [S.cfg.roles.PROVIDER]: "KYC provider", [S.cfg.roles.INSTITUTION]: "Institution", [S.cfg.roles.ORACLE]: "Oracle" })[r] || "?";
  const orgs = await Promise.all(orgEv.map(async (e) => ({ org: e.args.org, role: e.args.role, name: e.args.name, active: await S.read.hasRole(e.args.role, e.args.org) })));
  html += `<div class="grid g2" style="margin-top:18px"><div class="card"><h2>Onboard organisation</h2><p class="sub">Grant a role to an accredited entity.</p><div class="form">
    <label class="f full">Address<input id="oAddr" placeholder="0x…"></label>
    <label class="f">Role<select id="oRole"><option value="${S.cfg.roles.INSTITUTION}">Institution (bank / FinTech)</option><option value="${S.cfg.roles.PROVIDER}">KYC provider</option><option value="${S.cfg.roles.ORACLE}">Screening oracle</option></select></label>
    <label class="f">Name<input id="oName" maxlength="64" placeholder="e.g. Bank Gamma"></label>
    <div class="full row"><button class="btn ${paused ? "ok" : "danger"}" id="pauseBtn">${paused ? "Unpause registry" : "Emergency pause"}</button><span class="spacer"></span><button class="btn" id="orgBtn">Register organisation</button></div></div>
    <h3>Organisations</h3><table><tr><th>Name</th><th>Role</th><th></th></tr>${orgs
      .map((o) => `<tr><td>${who(o.org)}</td><td>${roleName(o.role)}</td><td style="text-align:right">${o.active ? `<button class="btn sm ghost" data-offboard="${o.org}" data-role="${o.role}">Offboard</button>` : '<span class="pill">removed</span>'}</td></tr>`)
      .join("")}</table></div>`;

  html += `<div class="card"><h2>Oracle quorum & live data sources</h2>
    <p class="sub">A screening is final only when <b>${quorum}</b> of <b>${oracleCount}</b> independent oracles agree; any disagreement goes to the review queue.</p>
    <div class="row"><label class="f" style="flex-direction:row;align-items:center;gap:8px">Quorum k<select id="quorumSel">${Array.from({ length: Number(oracleCount) }, (_, i) => i + 1).map((k) => `<option ${k === Number(quorum) ? "selected" : ""}>${k}</option>`).join("")}</select></label><button class="btn sm" id="quorumBtn">Set quorum</button></div>
    <h3>Review queue <span class="pill ${inReview.length ? "warn" : ""}">${inReview.length}</span></h3>${
      inReview.length
        ? `<table>${inReview.map((x) => `<tr><td>${who(x.a)}</td><td style="text-align:right"><button class="btn sm ok" data-resolve="${x.a}" data-hit="0">Clear</button> <button class="btn sm danger" data-resolve="${x.a}" data-hit="1">Confirm hit</button></td></tr>`).join("")}</table>`
        : '<div class="empty">No disputed screenings.</div>'
    }
    ${health ? oracleBlock(health) : '<div class="empty">Oracle status unavailable</div>'}</div>`;

  const label = (e) => {
    const a = e.args || {};
    switch (e.fragment?.name) {
      case "IdentityRegistered": return [a.user, "Identity registered", `doc ${short(a.documentHash)}`];
      case "VerificationDecided": return [a.provider, `Verification ${STATUS[Number(a.status)]}`, `${who(a.user)} tier ${a.tier}`];
      case "VerificationRevoked": return [a.by, "Verification revoked", `${who(a.user)} — ${esc(a.reason)}`];
      case "AccessRequested": return [a.institution, "Access requested", `${who(a.user)} ${scopesPills(a.scopes)}`];
      case "ConsentGranted": return [a.user, "Consent granted", `→ ${who(a.institution)} ${scopesPills(a.scopes)}`];
      case "ConsentRevoked": return [a.user, "Consent revoked", `→ ${who(a.institution)}`];
      case "KYCAccessed": return [a.institution, "KYC accessed", `${who(a.user)} ${a.valid ? '<span class="pill ok">valid</span>' : '<span class="pill bad">invalid</span>'}`];
      case "ScreeningRequested": return [a.requester, "Screening requested", who(a.subject)];
      case "ScreeningFulfilled": return [null, "Screening result", `${who(a.subject)} ${a.hit ? '<span class="pill bad">HIT</span>' : '<span class="pill ok">clear</span>'} <small>${esc(a.source)}</small>`];
      case "OrganizationRegistered": return [a.org, "Organisation onboarded", esc(a.name)];
      case "ScreeningVote": return [a.oracle, "Oracle vote", `${who(a.subject)} ${a.hit ? '<span class="pill bad">hit</span>' : '<span class="pill ok">clear</span>'}`];
      case "ScreeningEscalated": return [null, "Screening escalated to review", `${who(a.subject)} <small>${a.clearVotes} clear · ${a.hitVotes} hit</small>`];
      case "ReviewResolved": return [a.by, "Review resolved", `${who(a.user)} ${a.hit ? '<span class="pill bad">hit</span>' : '<span class="pill ok">clear</span>'} — ${esc(a.reason)}`];
      case "ScreeningQuorumSet": return [null, "Screening quorum set", `k = ${a.quorum}`];
      case "FreshnessPolicySet": return [a.institution, "Freshness policy set", esc(ageText(a.maxAge))];
      case "AttributeAnchored": case "RoleGranted": return null; // RoleGranted is covered by "Organisation onboarded"
      case "RoleRevoked": return [a.sender, "Organisation offboarded", who(a.account)];
      case "Paused": return [a.account, "Registry PAUSED", ""];
      case "Unpaused": return [a.account, "Registry unpaused", ""];
      default: return [null, e.fragment?.name || e.eventName || "event", ""];
    }
  };
  const rows = events.slice().reverse().map((e) => [e, label(e)]).filter(([, l]) => l).slice(0, 60);
  html += `<div class="card span2"><h2>Global audit trail</h2><p class="sub">Immutable, on-chain. Addresses are pseudonymous; no personal data appears here.</p><div class="table-wrap"><table><tr><th>Block</th><th>Event</th><th>Actor</th><th>Details</th></tr>${rows
    .map(([e, [actor, what, det]]) => `<tr><td class="mono">${e.blockNumber}</td><td><b>${what}</b></td><td>${actor ? who(actor) : "—"}</td><td>${det}</td></tr>`)
    .join("")}</table></div></div></div>`;
  return html;
}

function oracleBlock(h) {
  const list = h.oracles || [], s = h.sources;
  const o = list[0];
  return `<h3>Oracle nodes</h3><table>${list.map((n) => `<tr><td>${who(n.address)}</td><td><small>${n.processed} votes · ${n.hits} hits</small></td></tr>`).join("") || '<tr><td>not running</td></tr>'}</table>
    <dl class="kv" style="margin-top:10px">
    <dt>Perpetual KYC</dt><dd>re-screen every ${o?.rescreenIntervalMin ?? "—"} min</dd>
    <dt>Sources enabled</dt><dd>${s.configured.map((x) => `<span class="pill info">${esc(x)}</span>`).join(" ")}</dd>
    <dt>Local watchlist</dt><dd>${s.local.entries} entries</dd>
    <dt>OFAC SDN (live)</dt><dd>${s.ofac.entries ? `<span class="pill ok">${s.ofac.entries.toLocaleString()} individuals</span> <small>${s.ofac.fromCache ? "from cache" : "downloaded"} ${s.ofac.loadedAt ? new Date(s.ofac.loadedAt).toLocaleString() : ""}</small>` : `<span class="pill warn">not loaded</span> <small>${esc(s.ofac.error || "")}</small>`}</dd>
    <dt>OpenSanctions</dt><dd>${s.opensanctions.enabled ? '<span class="pill ok">API key set</span>' : '<span class="pill">no API key</span>'}</dd>
    ${list.filter((n) => n.lastError).map((n) => `<dt>${esc(n.name)} error</dt><dd><small>${esc(n.lastError)}</small></dd>`).join("")}</dl>
    <div class="row end" style="margin-top:10px"><button class="btn sm ghost" id="refreshOfac">Refresh OFAC list now</button></div>
    ${o?.recent?.length ? `<h3>Recent results</h3><table>${o.recent.slice(0, 6).map((r) => `<tr><td>${who(r.subject)}</td><td>${r.hit ? '<span class="pill bad">HIT</span>' : '<span class="pill ok">clear</span>'}</td><td><small>${esc(r.sources.join("+"))}</small></td><td><a href="#" data-report="${r.requestId}">report</a></td></tr>`).join("")}</table>` : ""}`;
}

// ───────────────────────── About ─────────────────────────
async function aboutView() {
  return head("How it works", "Problem Statement 3 — Decentralized KYC / Digital Identity Sharing Registry") +
    `<div class="grid"><div class="card"><h2>Architecture</h2><p class="sub">Personal data stays off-chain; trust, consent and audit live on-chain.</p>
    <div class="flow">
      <div class="node"><b>Customer wallet</b>Registers once. Holds secret salts for selective disclosure. Grants / revokes consent.</div>
      <div class="node"><b>Encrypted vault</b>AES-256-GCM document store. Releases files only if the chain says the requester has consent.</div>
      <div class="node chain-node"><b>KYCRegistry.sol</b>Roles · commitments · verification · scoped consent · audit events.</div>
      <div class="node"><b>Screening oracle</b>Watches requests, checks OFAC SDN (live) / OpenSanctions / watchlist, writes result + evidence hash.</div>
      <div class="node"><b>Banks & FinTechs</b>Request access, run audited KYC checks, verify single attributes.</div>
    </div></div>
    <div class="grid g2">
      <div class="card"><h2>Lifecycle</h2><ol class="steps">
        <li>Customer encrypts documents into the vault and anchors <code>identityCommitment</code> + <code>documentHash</code> on-chain.</li>
        <li>An accredited KYC provider opens the bundle, re-computes every hash, and approves (tier, risk, expiry, attribute commitments).</li>
        <li>Approval automatically emits <code>ScreeningRequested</code>; the oracle screens sanctions / PEP lists and calls <code>fulfillScreening</code>.</li>
        <li>KYC becomes <b>valid</b> only when Verified ∧ not expired ∧ screening Clear.</li>
        <li>A bank requests access; the customer grants scoped, time-bound consent.</li>
        <li>The bank calls <code>accessKYC</code> → result + immutable <code>KYCAccessed</code> audit event. No repeated paperwork.</li>
        <li>Perpetual KYC: the oracle re-screens valid customers periodically; a new listing invalidates KYC everywhere.</li>
      </ol></div>
      <div class="card"><h2>Consent scopes</h2><table>${SCOPE_LIST.map(([b, n, d]) => `<tr><td><span class="pill info">${n}</span></td><td class="mono">${b}</td><td>${d}</td></tr>`).join("")}</table>
      <h3>Privacy by design</h3><ul class="checklist">
        <li><span class="i ok">✓</span>No PII on-chain — only salted keccak256 commitments and a SHA-256 document hash.</li>
        <li><span class="i ok">✓</span>Selective disclosure: prove <code>AGE_OVER_18</code> without revealing the date of birth.</li>
        <li><span class="i ok">✓</span>Commitments are bound to the owner address — they cannot be replayed by someone else.</li>
        <li><span class="i ok">✓</span>Vault access requires a fresh wallet signature and on-chain consent.</li>
      </ul></div></div></div>`;
}

// ═══════════════════════════ event bindings ═══════════════════════════
const on = (sel, fn) => { const el = $(sel); if (el) el.onclick = fn; };
const onAll = (sel, fn) => document.querySelectorAll(sel).forEach((el) => (el.onclick = (ev) => { ev.preventDefault(); fn(el); }));

const SAMPLES = {
  a: { fullName: "Aarav Mehta", dob: "1998-07-21", nationality: "IN", residence: "IN", idType: "PAN", idNumber: "ABCPM1234K", address: "12 MG Road, Bengaluru 560001", email: "aarav@example.com" },
  b: { fullName: "Viktor Mordant", dob: "1971-02-03", nationality: "XX", residence: "AE", idType: "Passport", idNumber: "Z9988776", address: "Unit 4, Marina Towers, Dubai", email: "viktor@example.com" },
};

const bind = {
  customer() {
    const fill = (s) => () => { const f = $("#regForm"); for (const [k, v] of Object.entries(SAMPLES[s])) if (f.elements[k]) f.elements[k].value = v; };
    on("#sampleA", fill("a"));
    on("#sampleB", fill("b"));
    on("#regBtn", registerIdentity);
    on("#dlCred", () => download(`dkyc-credential-${S.account.slice(0, 8)}.json`, loadCred(S.account)));
    const restore = $("#restoreCred");
    if (restore) restore.onchange = async () => { try { const c = JSON.parse(await restore.files[0].text()); if (c.owner?.toLowerCase() !== S.account.toLowerCase()) throw new Error("backup belongs to another address"); saveCred(S.account, c); toast("Credential restored", "ok"); render(); } catch (e) { toast(e.message, "err"); } };
    onAll("[data-proof]", (el) => {
      const c = loadCred(S.account).claims[Number(el.dataset.proof)];
      const proof = JSON.stringify({ user: S.account, attribute: c.name, value: c.value, salt: c.salt }, null, 2);
      modal(`<h2>Share proof: ${esc(c.name)}</h2><p class="sub">Give this to the bank. It reveals only this one attribute; the bank checks it against the on-chain commitment.</p><textarea readonly style="width:100%;min-height:150px">${esc(proof)}</textarea>`);
      navigator.clipboard?.writeText(proof).then(() => toast("Proof copied to clipboard", "ok")).catch(() => {});
    });
    onAll("[data-approve]", (el) => attempt(send("Grant consent", () => S.c.grantConsent(el.dataset.approve, Number(el.dataset.scopes), 30))));
    onAll("[data-revoke]", (el) => attempt(send("Revoke consent", () => S.c.revokeConsent(el.dataset.revoke))));
    on("#grantBtn", () => {
      const scopes = [...document.querySelectorAll(".gScope:checked")].reduce((m, x) => m | Number(x.value), 0);
      if (!scopes) return toast("Pick at least one scope", "err");
      attempt(send("Grant consent", () => S.c.grantConsent($("#gInst").value, scopes, Number($("#gDays").value))));
    });
  },
  provider() {
    onAll("[data-review]", async (el) => {
      try {
        const owner = el.dataset.review;
        const id = await S.c.getIdentity(owner);
        const r = await vaultFetch(id.vaultURI.replace("vault://", ""));
        const p = r.payload.profile;
        r.owner = owner;
        r.identityOk = identityCommitment(owner, p.fullName, p.dob, p.idNumber, r.payload.identitySalt) === id.identityCommitment;
        S.ui.review = r;
        await render();
        $(".card.hl")?.scrollIntoView({ behavior: "smooth" });
      } catch (e) { toast(errMsg(e), "err"); }
    });
    on("#closeReview", () => { S.ui.review = null; render(); });
    on("#preScreen", async () => {
      const p = S.ui.review.payload.profile;
      try { S.ui.review.screen = await api("/api/screening/preview", { fullName: p.fullName, dob: p.dob, nationality: p.nationality }); render(); } catch (e) { toast(errMsg(e), "err"); }
    });
    on("#approveBtn", () => {
      const r = S.ui.review;
      const claims = r.payload.claims;
      attempt(send("Approve KYC", () => S.c.decideVerification(r.owner, true, Number($("#dTier").value), Number($("#dRisk").value), Number($("#dDays").value), claims.map((c) => attrKey(c.name)), claims.map((c) => c.commitment))).then(() => (S.ui.review = null)));
    });
    on("#rejectBtn", () => attempt(send("Reject KYC", () => S.c.decideVerification(S.ui.review.owner, false, 0, 0, 0, [], [])).then(() => (S.ui.review = null))));
    onAll("[data-revokev]", (el) => { const reason = prompt("Reason for revocation (stored on-chain, no PII):", "Document found to be forged"); if (reason) attempt(send("Revoke verification", () => S.c.revokeVerification(el.dataset.revokev, reason))); });
    onAll("[data-rescreen]", (el) => attempt(send("Request screening", () => S.c.requestScreening(el.dataset.rescreen))));
  },
  institution() {
    const go = (a) => { S.ui = { target: a }; render(); };
    on("#tGo", () => { const a = $("#tAddr").value.trim(); if (!ethers.isAddress(a)) return toast("Enter a valid address", "err"); go(ethers.getAddress(a)); });
    onAll("[data-pick]", (el) => go(el.dataset.pick));
    on("#reqBtn", () => {
      const scopes = [...document.querySelectorAll(".rScope:checked")].reduce((m, x) => m | Number(x.value), 0);
      if (!scopes) return toast("Pick at least one scope", "err");
      attempt(send("Request access", () => S.c.requestAccess(S.ui.target, scopes, $("#rPurpose").value.slice(0, 140))));
    });
    on("#checkBtn", async () => {
      try {
        const rc = await send("Audited KYC check", () => S.c.accessKYC(S.ui.target));
        const v = await S.c.getKYCForInstitution(S.ui.target);
        const hasRisk = await S.read.hasConsent(S.ui.target, S.account, 2);
        const policy = await S.read.freshnessPolicy(S.account);
        S.ui.result = { status: v.status, tier: v.tier, verifiedAt: v.verifiedAt, expiresAt: v.expiresAt, verifiedBy: v.verifiedBy, valid: v.valid, fresh: v.fresh, policy, risk: v.risk, screening: v.screening, lastScreenedAt: v.lastScreenedAt, hasRisk, tx: rc.hash };
        render();
      } catch {}
    });
    on("#freshBtn", () => attempt(send("Set freshness policy", () => S.c.setFreshnessPolicy(Number($("#freshSel").value)))));
    on("#bankRescreen", () => attempt(send("Request screening", () => S.c.requestScreening(S.ui.target))));
    on("#proofBtn", async () => {
      S.ui.proofText = $("#proofIn").value;
      try {
        const p = JSON.parse(S.ui.proofText);
        if (p.user && p.user.toLowerCase() !== S.ui.target.toLowerCase()) throw new Error("Proof is for a different customer");
        const ok = await S.c.verifyAttribute(S.ui.target, attrKey(p.attribute), String(p.value), p.salt);
        S.ui.proofRes = { ok, text: ok ? `${p.attribute} = ${p.value} matches the commitment anchored by the KYC provider.` : "Value or salt does not match the on-chain commitment." };
      } catch (e) { S.ui.proofRes = { ok: false, text: errMsg(e) }; }
      render();
    });
    on("#docsBtn", async () => {
      try {
        const id = await S.read.statusOf(S.ui.target);
        if (!Number(id)) return;
        // vault URI isn't public; the vault resolves it from the customer's on-chain record
        const grants = await S.read.hasConsent(S.ui.target, S.account, 8);
        if (!grants) throw new Error("No active consent with DOCUMENTS scope");
        const ev = await S.read.queryFilter(S.read.filters.IdentityRegistered(S.ui.target), S.cfg.deployBlock);
        const uri = ev.at(-1).args.vaultURI;
        S.ui.docs = await vaultFetch(uri.replace("vault://", ""));
        render();
      } catch (e) { toast(errMsg(e), "err"); }
    });
  },
  regulator() {
    on("#orgBtn", () => {
      const a = $("#oAddr").value.trim(), n = $("#oName").value.trim();
      if (!ethers.isAddress(a) || !n) return toast("Address and name required", "err");
      attempt(send("Register organisation", () => S.c.registerOrganization(a, $("#oRole").value, n)).then(loadOrgNames));
    });
    on("#quorumBtn", () => attempt(send("Set quorum", () => S.c.setScreeningQuorum(Number($("#quorumSel").value)))));
    onAll("[data-resolve]", (el) => {
      const hit = el.dataset.hit === "1";
      const reason = prompt("Reason (stored on-chain, no personal data):", hit ? "Confirmed match on sanctions list" : "False positive after manual review");
      if (reason) attempt(send("Resolve review", () => S.c.resolveReview(el.dataset.resolve, hit, reason)));
    });
    on("#pauseBtn", async () => attempt(send((await S.read.paused()) ? "Unpause" : "Pause", async () => ((await S.read.paused()) ? S.c.unpause() : S.c.pause()))));
    onAll("[data-offboard]", (el) => attempt(send("Offboard organisation", () => S.c.revokeRole(el.dataset.role, el.dataset.offboard))));
    on("#refreshOfac", async () => { toast("Downloading OFAC SDN list…"); try { const s = await api("/api/screening/refresh", {}); toast(s.ofac.entries ? `OFAC: ${s.ofac.entries} individuals loaded` : `OFAC: ${s.ofac.error}`, s.ofac.entries ? "ok" : "err"); render(); } catch (e) { toast(errMsg(e), "err"); } });
    onAll("[data-report]", async (el) => {
      try {
        const r = await api(`/api/screening/report/${el.dataset.report}`);
        modal(`<h2>Screening evidence</h2><p class="sub">Hash of this report is stored on-chain in the ScreeningFulfilled event.</p><pre class="mono" style="white-space:pre-wrap;max-height:60vh;overflow:auto">${esc(JSON.stringify(r, null, 2))}</pre>`);
      } catch (e) { toast(errMsg(e), "err"); }
    });
  },
};

// ═══════════════════════ customer registration ═══════════════════════
async function registerIdentity() {
  const f = $("#regForm");
  if (!f.reportValidity()) return;
  const v = Object.fromEntries(new FormData(f).entries());
  const owner = S.account;
  try {
    const documents = [];
    const file = f.elements.doc.files[0];
    if (file) {
      if (file.size > 2 * 1024 * 1024) throw new Error("Document larger than 2 MB");
      const b64 = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(",")[1]); r.onerror = rej; r.readAsDataURL(file); });
      documents.push({ name: file.name, mime: file.type || "application/octet-stream", dataBase64: b64 });
    }
    const profile = { fullName: v.fullName.trim(), dob: v.dob, nationality: v.nationality, residence: v.residence, idType: v.idType, idNumber: v.idNumber.trim(), address: v.address, email: v.email };
    const rnd = () => ethers.hexlify(ethers.randomBytes(32));
    const identitySalt = rnd();
    const claims = [["AGE_OVER_18", String(ageFromDob(profile.dob) >= 18)], ["NATIONALITY", profile.nationality], ["COUNTRY_OF_RESIDENCE", profile.residence]].map(([name, value]) => {
      const salt = rnd();
      return { name, value, salt, commitment: attrCommitment(owner, name, value, salt) };
    });
    const payload = JSON.stringify({ version: 1, owner, profile, identitySalt, claims, documents, submittedAt: new Date().toISOString() });
    toast("Sign the vault upload request…");
    const ts = now();
    const signature = await S.signer.signMessage(uploadMessage(owner, ethers.sha256(ethers.toUtf8Bytes(payload)), ts));
    const up = await api("/api/vault/upload", { owner, payload, timestamp: ts, signature });
    toast(`Encrypted in vault · sha256 ${up.documentHash.slice(0, 12)}…`, "ok");
    const commitment = identityCommitment(owner, profile.fullName, profile.dob, profile.idNumber, identitySalt);
    saveCred(owner, { owner, registry: S.cfg.address, identitySalt, identityCommitment: commitment, claims, vaultURI: up.vaultURI, createdAt: new Date().toISOString() });
    await send("Register identity", () => S.c.registerIdentity(commitment, up.documentHash, up.vaultURI));
  } catch (e) {
    if (!e?.toasted) toast(errMsg(e), "err");
  }
}

init().catch((e) => {
  console.error(e);
  $("#view").innerHTML = `<div class="card"><h2>Cannot connect</h2><p class="sub">${esc(e.message)}</p><p>Make sure Anvil is running, the contract is deployed (<code>npm run deploy</code>) and the server is started (<code>npm start</code>).</p></div>`;
});
