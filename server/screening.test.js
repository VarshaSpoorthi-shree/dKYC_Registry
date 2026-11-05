// node --test server/   — unit tests for the screening engine (no network needed)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dkyc-"));
const sdn = path.join(tmp, "sdn.csv");
// Sample in the official OFAC SDN CSV layout (ent_num, SDN_Name, SDN_Type, Program, ...)
fs.writeFileSync(sdn, [
  '36,"AEROCARIBBEAN AIRLINES",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0-',
  '173,"ABU ZUBAYDAH, Zayn al-Abidin",individual,"SDGT",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 12 Mar 1971"',
  '9999,"DOE, John Quincy",individual,"TEST",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0-',
].join("\n"));
process.env.OFAC_SDN_URL = "file://" + sdn; // fetch() cannot read file:// → falls back to cache we seed below
process.env.SCREENING_SOURCES = "local,ofac";

const { nameScore, normalize, jaroWinkler, refreshOfac, screen } = await import("./screening.js");
const { config } = await import("./config.js");
fs.mkdirSync(path.join(config.dataDir, "cache"), { recursive: true });
const cacheFile = path.join(config.dataDir, "cache", "ofac-sdn.csv");
const hadCache = fs.existsSync(cacheFile);
const backup = hadCache ? fs.readFileSync(cacheFile) : null;
fs.copyFileSync(sdn, cacheFile);

test.after(() => { if (backup) fs.writeFileSync(cacheFile, backup); else fs.rmSync(cacheFile, { force: true }); });

test("normalize strips accents, titles and punctuation", () => {
  assert.equal(normalize("  Dr. José  O'Neil "), "JOSE O NEIL");
});

test("jaro-winkler basics", () => {
  assert.equal(jaroWinkler("MARTHA", "MARTHA"), 1);
  assert.ok(jaroWinkler("MARTHA", "MARHTA") > 0.95);
  assert.ok(jaroWinkler("ABC", "XYZ") < 0.5);
});

test("name matching is order-insensitive and typo tolerant", () => {
  assert.ok(nameScore("Viktor Mordant", "MORDANT, Viktor") >= 0.95);
  assert.ok(nameScore("Victor Mordant", "Viktor Mordant") >= 0.92);
  assert.ok(nameScore("Aarav Mehta", "Viktor Mordant") < 0.7);
});

test("OFAC CSV parser keeps individuals only and reorders names", async () => {
  const s = await refreshOfac();
  assert.equal(s.entries.length, 2);
  assert.equal(s.entries[1].name, "John Quincy DOE");
});

test("screen() hits on OFAC and local lists, clears innocent names", async () => {
  assert.equal((await screen({ fullName: "John Quincy Doe" })).hit, true);
  assert.equal((await screen({ fullName: "Viktor Mordant", dob: "1971-02-03" })).hit, true);
  const clean = await screen({ fullName: "Aarav Mehta", dob: "1998-07-21" });
  assert.equal(clean.hit, false);
  assert.deepEqual(clean.sourcesUsed, ["local", "ofac"]);
});

test("different known DOB reduces false positives", async () => {
  const r = await screen({ fullName: "Viktor Mordant", dob: "2001-01-01" });
  assert.equal(r.hit, false);
});
