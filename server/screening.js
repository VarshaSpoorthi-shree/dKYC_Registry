// Sanctions / PEP screening engine used by the oracle.
// Sources (configurable via SCREENING_SOURCES):
//   local          – bundled demo watchlist (data/watchlist.json, fictional names)
//   ofac           – LIVE US Treasury OFAC SDN list, downloaded & cached (refreshed every 24h)
//   opensanctions  – LIVE OpenSanctions /match API (sanctions + PEPs), needs OPENSANCTIONS_API_KEY
import fs from "node:fs";
import path from "node:path";
import { config } from "./config.js";

const CACHE_DIR = path.join(config.dataDir, "cache");
fs.mkdirSync(CACHE_DIR, { recursive: true });

// ───────────────────────── name matching ─────────────────────────
export function normalize(name) {
  return String(name || "")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toUpperCase()
    .replace(/[^A-Z0-9 ]+/g, " ")
    .replace(/\b(MR|MRS|MS|DR|SHRI|SMT)\b/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function jaroWinkler(a, b) {
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;
  const range = Math.max(0, Math.floor(Math.max(a.length, b.length) / 2) - 1);
  const am = new Array(a.length).fill(false);
  const bm = new Array(b.length).fill(false);
  let matches = 0;
  for (let i = 0; i < a.length; i++) {
    for (let j = Math.max(0, i - range); j < Math.min(b.length, i + range + 1); j++) {
      if (!bm[j] && a[i] === b[j]) { am[i] = bm[j] = true; matches++; break; }
    }
  }
  if (!matches) return 0;
  let t = 0, k = 0;
  for (let i = 0; i < a.length; i++) {
    if (!am[i]) continue;
    while (!bm[k]) k++;
    if (a[i] !== b[k]) t++;
    k++;
  }
  const jaro = (matches / a.length + matches / b.length + (matches - t / 2) / matches) / 3;
  let p = 0;
  while (p < 4 && a[p] === b[p]) p++;
  return jaro + p * 0.1 * (1 - jaro);
}

/** Order-insensitive similarity ("PUTIN, Vladimir" ≈ "Vladimir Putin"). */
export function nameScore(a, b) {
  const ta = normalize(a).split(" ").filter(Boolean);
  const tb = normalize(b).split(" ").filter(Boolean);
  if (!ta.length || !tb.length) return 0;
  const sorted = jaroWinkler(ta.slice().sort().join(" "), tb.slice().sort().join(" "));
  // token alignment: every token of the shorter name must closely match a token of the longer one
  const [short, long] = ta.length <= tb.length ? [ta, tb] : [tb, ta];
  const aligned = short.reduce((s, t) => s + Math.max(...long.map((u) => jaroWinkler(t, u))), 0) / short.length;
  const coverage = short.length / long.length; // penalise "John" vs "John Smith Kumar"
  return Math.max(sorted, aligned * (0.85 + 0.15 * coverage));
}

// ───────────────────────── sources ─────────────────────────
function loadLocal() {
  const f = path.join(config.dataDir, "watchlist.json");
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, "utf8")) : [];
}

// Minimal RFC-4180 CSV line parser
function parseCsvLine(line) {
  const out = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

const ofacState = { entries: [], loadedAt: null, error: null, fromCache: false };

export async function refreshOfac(force = false) {
  const cacheFile = path.join(CACHE_DIR, "ofac-sdn.csv");
  const fresh = fs.existsSync(cacheFile) && Date.now() - fs.statSync(cacheFile).mtimeMs < config.ofacRefreshHours * 3600e3;
  let csv = null;
  if (!fresh || force) {
    // Primary (classic Treasury URL) then the newer OFAC Sanctions List Service export
    const urls = [config.ofacUrl, "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"];
    for (const url of urls) {
      try {
        const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(30000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        if (!/individual/i.test(text)) throw new Error("unexpected file format");
        csv = text;
        fs.writeFileSync(cacheFile, csv);
        ofacState.fromCache = false;
        ofacState.error = null;
        break;
      } catch (e) {
        ofacState.error = `OFAC download failed: ${e.cause?.code || e.message}`;
      }
    }
  }
  if (!csv && fs.existsSync(cacheFile)) {
    csv = fs.readFileSync(cacheFile, "utf8");
    ofacState.fromCache = true;
  }
  if (!csv) return ofacState;
  // sdn.csv columns: ent_num, SDN_Name, SDN_Type, Program, Title, ...
  ofacState.entries = csv
    .split(/\r?\n/)
    .map(parseCsvLine)
    .filter((r) => r.length > 3 && r[2]?.trim().toLowerCase() === "individual")
    .map((r) => {
      const raw = r[1].trim();
      const [last, first] = raw.split(",").map((s) => s.trim());
      return { name: first ? `${first} ${last}` : raw, list: "OFAC SDN", program: r[3]?.trim(), ref: `OFAC-${r[0].trim()}`, category: "sanctions" };
    });
  ofacState.loadedAt = new Date().toISOString();
  return ofacState;
}

async function screenOpenSanctions(subject) {
  const res = await fetch("https://api.opensanctions.org/match/default?algorithm=logic-v1", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `ApiKey ${config.openSanctionsApiKey}` },
    body: JSON.stringify({
      queries: {
        q: {
          schema: "Person",
          properties: {
            name: [subject.fullName],
            ...(subject.dob ? { birthDate: [subject.dob] } : {}),
            ...(subject.nationality ? { nationality: [subject.nationality] } : {}),
          },
        },
      },
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`OpenSanctions HTTP ${res.status}`);
  const data = await res.json();
  return (data.responses?.q?.results || [])
    .filter((r) => r.match || r.score >= 0.7)
    .map((r) => ({
      name: r.caption,
      list: "OpenSanctions",
      category: (r.properties?.topics || []).includes("role.pep") ? "pep" : "sanctions",
      ref: r.id,
      score: Number(r.score.toFixed(3)),
    }));
}

// ───────────────────────── public API ─────────────────────────
export function sourceStatus() {
  return {
    configured: config.screeningSources,
    local: { entries: loadLocal().length },
    ofac: { entries: ofacState.entries.length, loadedAt: ofacState.loadedAt, fromCache: ofacState.fromCache, error: ofacState.error },
    opensanctions: { enabled: !!config.openSanctionsApiKey },
  };
}

function matchList(subject, list) {
  const subjectDob = subject.dob || null;
  const out = [];
  for (const e of list) {
    let score = nameScore(subject.fullName, e.name);
    for (const alias of e.aliases || []) score = Math.max(score, nameScore(subject.fullName, alias));
    if (score < config.matchThreshold) continue;
    // A different, known DOB is strong evidence of a false positive
    if (subjectDob && e.dob && e.dob !== subjectDob) score -= 0.15;
    if (score >= config.matchThreshold) out.push({ name: e.name, list: e.list, category: e.category, ref: e.ref, program: e.program, score: Number(score.toFixed(3)) });
  }
  return out;
}

/**
 * Screen a person. Returns a report; `hit` is true if any source matched.
 * Fail-closed policy: if NO source could be checked, the call throws so the oracle retries.
 */
export async function screen(subject) {
  const report = { screenedAt: new Date().toISOString(), threshold: config.matchThreshold, sourcesUsed: [], sourcesFailed: [], matches: [] };
  for (const src of config.screeningSources) {
    try {
      if (src === "local") {
        report.matches.push(...matchList(subject, loadLocal()));
      } else if (src === "ofac") {
        if (!ofacState.entries.length || Date.now() - Date.parse(ofacState.loadedAt || 0) > config.ofacRefreshHours * 3600e3) await refreshOfac();
        if (!ofacState.entries.length) throw new Error(ofacState.error || "OFAC list unavailable");
        report.matches.push(...matchList(subject, ofacState.entries));
      } else if (src === "opensanctions") {
        if (!config.openSanctionsApiKey) throw new Error("OPENSANCTIONS_API_KEY not set");
        report.matches.push(...(await screenOpenSanctions(subject)));
      } else continue;
      report.sourcesUsed.push(src);
    } catch (e) {
      report.sourcesFailed.push({ source: src, error: e.message });
    }
  }
  if (!report.sourcesUsed.length) throw new Error("No screening source available: " + JSON.stringify(report.sourcesFailed));
  report.matches.sort((a, b) => b.score - a.score);
  report.hit = report.matches.length > 0;
  return report;
}
