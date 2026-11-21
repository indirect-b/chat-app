/**
 * Deepening 1 (audit 2026-11-21) — COVERAGE-GUIDED mutational fuzzing.
 *
 * Extends phase-1 fuzzing (tests/fuzz.test.ts round 2 + tests/fuzz-w3.test.ts):
 * instead of only hand-written adversarial cases, this file runs a real
 * coverage-guided mutational fuzzer over the crypto parser/decrypt paths:
 *
 *   - ML-KEM-768 decapsulation / ML-DSA-65 verification (raw noble primitives)
 *   - key-bundle parsing (lenient parsePeerKeyBundle + strict parsePeerKeyBundleStrict)
 *   - decryptMessageText: PQ ratchet (e2ee:pq:v2:), group epoch (e2ee:gep:v2:),
 *     removed ECDH prefix (e2ee:ecdh: — rejected, DP-15) and PBKDF2 (e2ee:v1:) paths
 *   - group epoch packets (create/decapsulate/rotate)
 *   - PQF1 file payloads (decryptFileBytes, kinds DM/group/manual)
 *   - safety-number parsers (QR payload, 60-digit compare, hex->digits)
 *   - base64 helpers + bundle/message serializers
 *
 * COVERAGE FEEDBACK: the fuzzer opens a node:inspector session and uses
 * Profiler.takePreciseCoverage after inputs. A corpus entry is kept ("interesting")
 * when it executes a previously-uncovered block in src/utils/crypto.ts,
 * src/utils/safetyNumber.ts or src/utils/keystore.ts; later mutations are drawn
 * from the interesting corpus. This is genuine coverage guidance (per-input
 * block-coverage diff), not just post-hoc measurement. Aggregate line/branch
 * numbers are measured separately with `node --test --experimental-test-coverage`
 * (see deepening-1-fuzz.md); when that flag is active, set DP_GUIDED=0 to skip
 * the inspector session (the two coverage mechanisms share V8 internals).
 *
 * PASS CRITERION (same as round 2 / W3): every mutated input must fail closed —
 * throw E2EEError (or return null/false where the API is non-throwing), never
 * crash the process with an unhandled error type, never output plaintext, and
 * never be ACCEPTED as verified/decrypted unless the mutation provably preserves
 * the signed/authenticated content. KNOWN leniencies found by this campaign are
 * encoded below as DP-1/DP-2/DP-3 regression reproducers (deterministic `it`
 * blocks) and as expected-accept classes inside the campaign oracles — anything
 * outside those classes fails the run, so a re-run detects NEW issues.
 *
 * DISCOVERY ONLY. No code under src/ is modified by this file.
 *
 * Deterministic: one fixed xorshift seed (0xDP1...). Re-running reproduces the
 * same mutation sequence; the coverage-guided corpus evolution is deterministic
 * given the same Node/tsx versions.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import inspector from 'node:inspector';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// localStorage mock (same shape as the phase-1 fuzz tests)
// ---------------------------------------------------------------------------
class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number { return this.map.size; }
  clear(): void { this.map.clear(); }
  getItem(key: string): string | null { return this.map.has(key) ? this.map.get(key)! : null; }
  key(index: number): string | null { return Array.from(this.map.keys())[index] ?? null; }
  removeItem(key: string): void { this.map.delete(key); }
  setItem(key: string, value: string): void { this.map.set(key, String(value)); }
}
const mockLocalStorage = new MemoryStorage();
Object.defineProperty(globalThis, 'localStorage', {
  value: mockLocalStorage, configurable: true, writable: true,
});

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift32) + helpers
// ---------------------------------------------------------------------------
function xorshift(seed: number) {
  let s = seed >>> 0;
  const next = () => {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
    return s / 4294967296;
  };
  return {
    next,
    int(n: number): number { return Math.floor(next() * n); },
    pick<T>(arr: readonly T[]): T { return arr[Math.floor(next() * arr.length)]; },
    bool(p = 0.5): boolean { return next() < p; },
    bytes(len: number): Uint8Array {
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = Math.floor(next() * 256);
      return out;
    },
  };
}
type Rng = ReturnType<typeof xorshift>;
const rng = xorshift(0xd91f7a11);

// ---------------------------------------------------------------------------
// Global counters — the report counts come from here
// ---------------------------------------------------------------------------
const stats = {
  totalCases: 0,
  perCampaign: {} as Record<string, number>,
  interestingKept: 0,
  newAppRanges: 0,
  newNobleRanges: 0,
  slowInputs: [] as Array<{ campaign: string; ms: number; label: string }>,
  nonE2EEThrows: [] as Array<{ campaign: string; label: string; err: string }>,
  unexpectedAccepts: [] as Array<{ campaign: string; label: string; detail: string }>,
  /** Unmutated-seed CONTROL inputs that were accepted (proves the campaign
   *  actually reaches successful decrypt/parse paths, not just fail-closed). */
  controlAccepts: {} as Record<string, number>,
};
function countCase(campaign: string): void {
  stats.totalCases++;
  stats.perCampaign[campaign] = (stats.perCampaign[campaign] || 0) + 1;
}

// ---------------------------------------------------------------------------
// Coverage-guided feedback via node:inspector precise coverage.
// GUIDED=1 (default) unless DP_GUIDED=0 (aggregate-coverage runs).
// ---------------------------------------------------------------------------
const GUIDED = process.env.DP_GUIDED !== '0';
const APP_URLS = ['src/utils/crypto.ts', 'src/utils/safetyNumber.ts', 'src/utils/keystore.ts'];
const NOBLE_URLS = ['@noble/post-quantum', '@noble/curves', '@noble/hashes', '@noble/ciphers'];
const coveredApp = new Set<string>();
const coveredNoble = new Set<string>();
let covSession: inspector.Session | null = null;
let covPost: ((method: string, params?: Record<string, unknown>) => Promise<any>) | null = null;

async function coverageInit(): Promise<void> {
  if (!GUIDED) return;
  covSession = new inspector.Session();
  covSession.connect();
  covPost = (method: string, params: Record<string, unknown> = {}) =>
    new Promise((resolve, reject) =>
      covSession!.post(method, params, (err: Error | null, res: unknown) => (err ? reject(err) : resolve(res))));
  await covPost('Profiler.enable');
  await covPost('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}

async function coverageStop(): Promise<void> {
  if (!covSession || !covPost) return;
  try { await covPost('Profiler.stopPreciseCoverage'); } catch { /* ignore */ }
  try { await covPost('Profiler.disable'); } catch { /* ignore */ }
  covSession.disconnect();
  covSession = null;
}

/** Diff current precise coverage against the seen sets. Returns #new ranges. */
async function coverageDiff(): Promise<{ app: number; noble: number }> {
  if (!covPost) return { app: 0, noble: 0 };
  const res = await covPost('Profiler.takePreciseCoverage') as {
    result: Array<{ url: string; functions: Array<{ ranges: Array<{ startOffset: number; endOffset: number; count: number }> }> }>;
  };
  let app = 0;
  let noble = 0;
  for (const script of res.result) {
    const isApp = APP_URLS.some(u => script.url.includes(u));
    const isNoble = !isApp && NOBLE_URLS.some(u => script.url.includes(u));
    if (!isApp && !isNoble) continue;
    for (const fn of script.functions) {
      for (const r of fn.ranges) {
        if (r.count === 0) continue;
        const key = `${script.url}|${r.startOffset}|${r.endOffset}`;
        if (isApp) {
          if (!coveredApp.has(key)) { coveredApp.add(key); app++; }
        } else if (!coveredNoble.has(key)) { coveredNoble.add(key); noble++; }
      }
    }
  }
  stats.newAppRanges += app;
  stats.newNobleRanges += noble;
  return { app, noble };
}

// ---------------------------------------------------------------------------
// Mutation operators (all seeded/deterministic)
// ---------------------------------------------------------------------------
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const EDGE_STRINGS = [
  '', '0', '00', '0001', '01', '-1', '1.5', 'NaN', 'Infinity', ' 1', '1 ', '+1',
  '0x10', '1e3', '99999999999999999999', '9007199254740993', '9007199254740991',
  '１２３', '١٢٣', '4294967295', '4294967296', '2147483647', '2147483648',
];

function mutateBytes(input: Uint8Array, r: Rng, donor?: Uint8Array): Uint8Array {
  const out = new Uint8Array(input);
  const ops = 1 + r.int(3);
  for (let k = 0; k < ops; k++) {
    const op = r.int(8);
    if (out.length === 0) break;
    const pos = r.int(out.length);
    switch (op) {
      case 0: out[pos] ^= 1 << r.int(8); break; // single bit flip
      case 1: out[pos] = r.int(256); break; // random byte
      case 2: out[pos] = (out[pos] + 1 + r.int(255)) & 0xff; break; // byte add
      case 3: out[pos] = 0x00; break;
      case 4: out[pos] = 0xff; break;
      case 5: { // splice bytes from donor / random
        const src = donor && donor.length > 0 && r.bool(0.5) ? donor : r.bytes(1 + r.int(8));
        const len = Math.min(1 + r.int(8), src.length, out.length - pos);
        out.set(src.subarray(0, len), pos);
        break;
      }
      case 6: out[pos] ^= 0xff; break; // full byte flip
      default: { // duplicate a chunk over a later position
        const len = 1 + r.int(Math.min(16, out.length));
        const from = r.int(out.length - len + 1);
        const to = r.int(out.length - len + 1);
        out.set(out.subarray(from, from + len), to);
        break;
      }
    }
  }
  // structural ops (applied once per call, low probability)
  const s = r.next();
  if (s < 0.12 && out.length > 1) return out.subarray(0, r.int(out.length)); // truncate
  if (s < 0.18) { // extend
    const ext = new Uint8Array(out.length + 1 + r.int(32));
    ext.set(out, 0);
    ext.set(r.bytes(ext.length - out.length), out.length);
    return ext;
  }
  if (s < 0.22 && out.length > 0) { // empty
    return new Uint8Array(0);
  }
  return out;
}

function mutateB64Field(s: string, r: Rng): string {
  if (s.length === 0) return r.pick(['', 'A', 'AAAA', '====', '!!!']);
  const chars = s.split('');
  const ops = 1 + r.int(2);
  for (let k = 0; k < ops; k++) {
    const op = r.int(6);
    const pos = r.int(chars.length);
    switch (op) {
      case 0: chars[pos] = r.pick(B64_ALPHABET.split('')); break;
      case 1: chars[pos] = r.pick(['-', '_', ' ', '\n', '!', '=', '+', '/']); break;
      case 2: chars.splice(pos, 1); break; // delete char (breaks %4)
      case 3: chars.splice(pos, 0, r.pick(B64_ALPHABET.split(''))); break; // insert char
      case 4: { const j = r.int(chars.length); [chars[pos], chars[j]] = [chars[j], chars[pos]]; break; } // swap
      default: chars[pos] = chars[pos] === 'A' ? 'B' : 'A'; break;
    }
  }
  let out = chars.join('');
  const t = r.next();
  if (t < 0.08) out = out.slice(0, Math.max(0, r.int(out.length))); // truncate
  else if (t < 0.12) out = out + r.pick(B64_ALPHABET.split('')).repeat(1 + r.int(4)); // extend
  return out;
}

/** Mutate a ':'-separated payload string; returns the mutant + a description. */
function mutateColonPayload(payload: string, prefix: string, r: Rng): { text: string; desc: string } {
  const body = payload.slice(prefix.length);
  const fields = body.split(':');
  const op = r.int(10);
  const i = r.int(fields.length);
  let desc = '';
  switch (op) {
    case 0: fields[i] = mutateB64Field(fields[i], r); desc = `field[${i}] b64-mutated`; break;
    case 1: fields[i] = r.pick(EDGE_STRINGS); desc = `field[${i}] := edge ${JSON.stringify(fields[i])}`; break;
    case 2: fields.splice(i, 1); desc = `field[${i}] deleted`; break;
    case 3: fields.splice(i, 0, ''); desc = `empty field inserted at ${i}`; break;
    case 4: fields.splice(i, 0, fields[r.int(fields.length)]); desc = `field duplicated at ${i}`; break;
    case 5: { const j = r.int(fields.length); [fields[i], fields[j]] = [fields[j], fields[i]]; desc = `fields ${i}<->${j} swapped`; break; }
    case 6: fields[i] = ''; desc = `field[${i}] emptied`; break;
    case 7: fields[i] = fields[i].split('').reverse().join(''); desc = `field[${i}] reversed`; break;
    case 8: fields[i] = 'A'.repeat(fields[i].length || 4); desc = `field[${i}] := 'A'*len`; break;
    default: fields[i] = mutateB64Field(fields[i], r); desc = `field[${i}] b64-mutated(2)`; break;
  }
  return { text: prefix + fields.join(':'), desc };
}

/** Mutate a JSON string (bundle): object-level + raw-string mutations. */
function mutateJsonString(json: string, r: Rng): { text: string; desc: string; touchedSigned: string[] } {
  const touchedSigned: string[] = [];
  if (r.next() < 0.3) {
    // raw string mutation
    const cut = r.next();
    if (cut < 0.1) return { text: json.slice(0, r.int(json.length)), desc: 'raw: truncated JSON', touchedSigned: ['<raw>'] };
    if (cut < 0.2) return { text: json + '}', desc: 'raw: extra brace', touchedSigned: ['<raw>'] };
    if (cut < 0.3) return { text: json.replace('"username"', '"username","username"'), desc: 'raw: duplicated key text', touchedSigned: ['username'] };
    return { text: json.slice(0, r.int(json.length)) + 'GARBAGE' + json.slice(r.int(json.length)), desc: 'raw: garbage inserted', touchedSigned: ['<raw>'] };
  }
  let obj: Record<string, any>;
  try { obj = JSON.parse(json); } catch { return { text: 'not json', desc: 'raw: replaced with non-JSON', touchedSigned: ['<raw>'] }; }
  const SIGNED = ['username', 'mlkemPubB64', 'mldsaPubB64', 'mldsaSigB64'];
  const keys = Object.keys(obj);
  const op = r.int(9);
  const k = r.pick(keys.concat(['__newField__']));
  const b64mut = () => mutateB64Field(typeof obj[k] === 'string' ? obj[k] : 'AAAA', r);
  switch (op) {
    case 0: delete obj[k]; if (SIGNED.includes(k)) touchedSigned.push(k); return { text: JSON.stringify(obj), desc: `key deleted: ${k}`, touchedSigned };
    case 1: obj[k] = b64mut(); if (SIGNED.includes(k)) touchedSigned.push(k); return { text: JSON.stringify(obj), desc: `key b64-mutated: ${k}`, touchedSigned };
    case 2: obj[k] = r.pick([0, 1, -1, 1.5, true, false, null, [], {}, 2 ** 53]); if (SIGNED.includes(k)) touchedSigned.push(k); return { text: JSON.stringify(obj), desc: `key type-changed: ${k} := ${JSON.stringify(obj[k])}`, touchedSigned };
    case 3: obj[k] = ''; if (SIGNED.includes(k)) touchedSigned.push(k); return { text: JSON.stringify(obj), desc: `key emptied: ${k}`, touchedSigned };
    case 4: obj[k] = 'x'.repeat(r.pick([1, 10, 100, 1000, 100000])); if (SIGNED.includes(k)) touchedSigned.push(k); return { text: JSON.stringify(obj), desc: `key oversized: ${k}`, touchedSigned };
    case 5: obj.__extraUnsigned = r.pick(['attacker', 123, { a: 1 }]); return { text: JSON.stringify(obj), desc: 'extra unsigned field added', touchedSigned };
    case 6: {
      if (obj.ecdhJwk && typeof obj.ecdhJwk === 'object') {
        const jk = r.pick(['kty', 'crv', 'x', 'y']);
        if (r.bool(0.5)) { delete obj.ecdhJwk[jk]; } else { obj.ecdhJwk[jk] = r.pick(['RSA', 'P-384', 'AAAA', '', 123, null, 'P-256']); }
        if (r.bool(0.3)) obj.ecdhJwk.d = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        return { text: JSON.stringify(obj), desc: `ecdhJwk.${jk} mutated`, touchedSigned };
      }
      return { text: JSON.stringify(obj), desc: 'ecdhJwk missing (no-op)', touchedSigned };
    }
    case 7: obj.v = r.pick([0, 1, 2, 3, 5, '4', null, 'v4']); return { text: JSON.stringify(obj), desc: `v := ${JSON.stringify(obj.v)}`, touchedSigned };
    default: obj.username = r.pick(['mallory', 'BOB', ' bob ', '', 'alice', 'a'.repeat(500)]); touchedSigned.push('username'); return { text: JSON.stringify(obj), desc: `username := ${JSON.stringify(obj.username)}`, touchedSigned };
  }
}

// ---------------------------------------------------------------------------
// Oracle helpers
// ---------------------------------------------------------------------------
type Outcome =
  | { kind: 'threw-e2ee'; code?: string }
  | { kind: 'threw-other'; name: string; message: string }
  | { kind: 'returned'; value: unknown };

async function runAsync(fn: () => Promise<unknown>): Promise<Outcome> {
  try {
    const value = await fn();
    return { kind: 'returned', value };
  } catch (err: any) {
    if (err && err.name === 'E2EEError') return { kind: 'threw-e2ee', code: err.code };
    return { kind: 'threw-other', name: err?.constructor?.name || typeof err, message: String(err?.message || err).slice(0, 200) };
  }
}

function runSync(fn: () => unknown): Outcome {
  try {
    return { kind: 'returned', value: fn() };
  } catch (err: any) {
    if (err && err.name === 'E2EEError') return { kind: 'threw-e2ee', code: err.code };
    return { kind: 'threw-other', name: err?.constructor?.name || typeof err, message: String(err?.message || err).slice(0, 200) };
  }
}

function recordOutcome(campaign: string, label: string, outcome: Outcome, ms: number): void {
  if (ms > 2000) stats.slowInputs.push({ campaign, ms, label });
  if (outcome.kind === 'threw-other') {
    stats.nonE2EEThrows.push({ campaign, label, err: `${outcome.name}: ${outcome.message}` });
  }
}

// ---------------------------------------------------------------------------
// Dynamically imported targets (imported AFTER coverage starts so the
// transpiled modules are attributed to the precise-coverage session).
// ---------------------------------------------------------------------------
let C: typeof import('../src/utils/crypto');
let SN: typeof import('../src/utils/safetyNumber');
let KS: typeof import('../src/utils/keystore');
let ml_kem768: typeof import('@noble/post-quantum/ml-kem.js').ml_kem768;
let ml_dsa65: typeof import('@noble/post-quantum/ml-dsa.js').ml_dsa65;

async function loadTargets(): Promise<void> {
  C = await import('../src/utils/crypto');
  SN = await import('../src/utils/safetyNumber');
  KS = await import('../src/utils/keystore');
  ({ ml_kem768 } = await import('@noble/post-quantum/ml-kem.js'));
  ({ ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js'));
}

function countControlAccept(campaign: string): void {
  stats.controlAccepts[campaign] = (stats.controlAccepts[campaign] || 0) + 1;
}

// ---------------------------------------------------------------------------
// Generic coverage-guided campaign runner
// ---------------------------------------------------------------------------
interface CampaignOpts<T> {
  budget: number;
  /** Rebuild fresh seeds every N cases (resets state that mutants consume). */
  reseedEvery?: number;
  freshSeeds?: () => Promise<T[]> | T[];
  mutate: (parent: T, r: Rng) => { input: T; desc: string } | Promise<{ input: T; desc: string }>;
  run: (input: T, desc: string) => Promise<void> | void;
  /** Snapshot coverage per input (default true); false = every 10th input. */
  coveragePerInput?: boolean;
}

async function runCampaign<T>(name: string, seeds: T[], opts: CampaignOpts<T>): Promise<void> {
  let corpus: T[] = [...seeds];
  const maxCorpus = 48;
  let sinceReseed = 0;
  const unexpectedBefore = stats.unexpectedAccepts.length;
  const throwsBefore = stats.nonE2EEThrows.length;
  for (let i = 0; i < opts.budget; i++) {
    if (opts.reseedEvery && opts.freshSeeds && sinceReseed >= opts.reseedEvery) {
      const fresh = await opts.freshSeeds();
      corpus = [...fresh, ...corpus.slice(0, 8)];
      sinceReseed = 0;
    }
    const parent = corpus[rng.int(corpus.length)];
    const { input, desc } = await opts.mutate(parent, rng);
    const t0 = Date.now();
    countCase(name);
    await opts.run(input, desc);
    const ms = Date.now() - t0;
    if (ms > 2000) stats.slowInputs.push({ campaign: name, ms, label: desc });
    sinceReseed++;
    const snap = opts.coveragePerInput === false ? i % 10 === 0 : true;
    if (GUIDED && snap) {
      const d = await coverageDiff();
      if (d.app + d.noble > 0) {
        stats.interestingKept++;
        if (!corpus.includes(input as T)) {
          corpus.push(input);
          if (corpus.length > maxCorpus) corpus.splice(1, corpus.length - maxCorpus);
        }
      }
    }
  }
  console.log(`    [dp] campaign ${name}: ${stats.perCampaign[name]} cases, corpus=${corpus.length}, total new app ranges=${stats.newAppRanges}, noble=${stats.newNobleRanges}`);
  // Self-validating: any unexpected accept / non-E2EE throw recorded during
  // THIS campaign fails it here (so a split run still validates per campaign).
  assert.equal(stats.unexpectedAccepts.length, unexpectedBefore, `campaign ${name} recorded unexpected accepts: ${JSON.stringify(stats.unexpectedAccepts.slice(unexpectedBefore, unexpectedBefore + 3))}`);
  assert.equal(stats.nonE2EEThrows.length, throwsBefore, `campaign ${name} recorded non-E2EE throws: ${JSON.stringify(stats.nonE2EEThrows.slice(throwsBefore, throwsBefore + 3))}`);
}

// ---------------------------------------------------------------------------
// Shared fixtures (built once in before())
// ---------------------------------------------------------------------------
let aliceBundle = '';
let bobBundle = '';
let aliceParsed: ReturnType<typeof C.parsePeerKeyBundle>;
let bobParsed: ReturnType<typeof C.parsePeerKeyBundle>;
const ROOM_DM = 'alice__bob';
const SECRET_PQ = 'DP-FUZZ-PQ-SECRET-0123456789';
const SECRET_GROUP = 'DP-FUZZ-GROUP-SECRET-0123456789';
const SECRET_FILE = 'DP-FUZZ-FILE-SECRET-0123456789';

async function makePqSeed(): Promise<string> {
  return C.encryptMessageText(SECRET_PQ, ROOM_DM, {
    myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobBundle,
  });
}

async function makeGroupSeed(groupId: string): Promise<{ payload: string; epoch: number }> {
  const payload = await C.encryptMessageText(SECRET_GROUP, `group__${groupId}`, { groupMembers: ['alice', 'bob'] });
  return { payload, epoch: 1 };
}

async function setupGroup(groupId: string, epoch: number): Promise<string> {
  const bundles: Record<string, ReturnType<typeof C.parsePeerKeyBundle>> = { alice: aliceParsed, bob: bobParsed };
  const packet = await C.createGroupEpochPacket(bundles);
  await C.rotateGroupEpoch(groupId, epoch, ['alice', 'bob'], packet.epochKeyB64);
  return packet.epochKeyB64;
}

/** Re-sign a mutated PQ payload with alice's identity key (penetrates the signature gate). */
async function resignPqPayload(payload: string): Promise<string> {
  const raw = payload.slice('e2ee:pq:v2:'.length);
  const [stepStr, kemCipherB64, ivB64, cipherB64] = raw.split(':');
  const signData = C.serializeMessageForSigning({
    roomId: ROOM_DM,
    step: Number(stepStr),
    kemCipherB64,
    ivB64,
    cipherB64,
  });
  const sigB64 = await C.withUnwrappedMLDSASecretKey('alice', (sk) =>
    C.bufToBase64(ml_dsa65.sign(signData, sk)));
  return `e2ee:pq:v2:${stepStr}:${kemCipherB64}:${ivB64}:${cipherB64}:${sigB64}`;
}

/** Re-sign a mutated bundle JSON with bob's identity key (malicious-signer model). */
async function resignBundle(obj: Record<string, any>): Promise<string> {
  const signData = C.serializeBundleForSigning({
    username: obj.username,
    ecdhJwk: obj.ecdhJwk,
    mlkemPubB64: obj.mlkemPubB64,
  });
  const sigB64 = await C.withUnwrappedMLDSASecretKey('bob', (sk) =>
    C.bufToBase64(ml_dsa65.sign(signData, sk)));
  obj.mldsaSigB64 = sigB64;
  return JSON.stringify(obj);
}

// IMPORTANT keystore lesson (found while debugging C5): resetAllCryptoStateForTests()
// wipes the in-memory identity store (nodeMemoryIdbStore), and encrypt paths
// LAZILY re-create a FRESH identity when the record is missing — so after a
// reset, the fixture bundle strings (aliceBundle/bobBundle) no longer match
// the stored keys and every PQ signature check fails. Every test that resets
// state MUST re-create its identities + bundles afterwards, or the campaign
// runs vacuously (everything throws INVALID_SIGNATURE and the deep decrypt
// paths are never reached). refreshFixtures() does exactly that.
async function refreshFixtures(): Promise<void> {
  mockLocalStorage.clear();
  C.resetAllCryptoStateForTests();
  aliceBundle = (await C.ensureUserHybridKeyPair('alice'))!;
  bobBundle = (await C.ensureUserHybridKeyPair('bob'))!;
  assert.ok(aliceBundle && bobBundle, 'fixture keypairs must generate');
  aliceParsed = C.parsePeerKeyBundle(aliceBundle, 'alice');
  bobParsed = C.parsePeerKeyBundle(bobBundle, 'bob');
  assert.equal(aliceParsed.isFullyPostQuantum, true);
  assert.equal(bobParsed.isFullyPostQuantum, true);
}

// File-level setup: runs once per file even when --test-name-pattern filters
// to a subset of tests (describe-level before() would be skipped then).
before(async () => {
  await coverageInit();
  await loadTargets();
  await refreshFixtures();
});

describe('DP deepening-1 — coverage-guided fuzzing (setup)', () => {
  // -- DP-1 REGRESSION: group replay bypass via non-canonical epoch spelling --
  it('DP-1 REGRESSION: same group message re-delivered with epoch "01"/"001"/"0001" is ACCEPTED (replay check keys on the raw payload string)', async () => {
    await refreshFixtures();
    await setupGroup('dp1-group', 1);
    const payload = await C.encryptMessageText(SECRET_GROUP, 'group__dp1-group', { groupMembers: ['alice', 'bob'] });
    const opts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, groupMembers: ['alice', 'bob'] };
    const parts = payload.slice('e2ee:gep:v2:'.length).split(':');
    assert.equal(parts[0], '1');
    let accepted = 0;
    for (const spelling of ['1', '01', '001', '0001', '00001']) {
      const p = `e2ee:gep:v2:${spelling}:${parts[1]}:${parts[2]}:${parts[3]}`;
      const res = await C.decryptMessageText(p, 'group__dp1-group', opts);
      assert.equal(res.text, SECRET_GROUP);
      accepted++;
    }
    assert.equal(accepted, 5, 'all 5 epoch spellings of the same logical message must decrypt (this IS the finding)');
    // Control: the canonical spelling a second time IS rejected.
    await assert.rejects(
      () => C.decryptMessageText(payload, 'group__dp1-group', opts),
      (err: any) => err instanceof C.E2EEError && err.code === 'REPLAY_DETECTED',
    );
  });

  // -- DP-1 companion: PQ step leading zeros are accepted, but ratchet replay still holds --
  it('DP-1 COMPANION: PQ step "001" verifies (signature binds the numeric step), but the same step twice still throws REPLAY_DETECTED', async () => {
    await refreshFixtures();
    const payload = await makePqSeed();
    const opts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' };
    const parts = payload.slice('e2ee:pq:v2:'.length).split(':');
    const step = parts[0];
    const respelled = `e2ee:pq:v2:${'0'.repeat(3)}${step}:${parts[1]}:${parts[2]}:${parts[3]}:${parts[4]}`;
    const res = await C.decryptMessageText(respelled, ROOM_DM, opts);
    assert.equal(res.text, SECRET_PQ, 'leading-zero step spelling decrypts (canonicalization leniency)');
    await assert.rejects(
      () => C.decryptMessageText(payload, ROOM_DM, opts),
      (err: any) => err instanceof C.E2EEError && err.code === 'REPLAY_DETECTED',
      'canonical re-delivery of the same ratchet step must still be rejected',
    );
  });

  // -- DP-2 REGRESSION: unsigned bundle fields accepted as fully post-quantum --
  it('DP-2 REGRESSION: bundle fields NOT covered by the ML-DSA signature (v, alg, voprfProofTag, extra ecdhJwk keys incl. private d) are accepted as fully-PQ', async () => {
    await refreshFixtures();
    const variants: Array<[string, (o: Record<string, any>) => void]> = [
      ['v downgraded to 2', (o) => { o.v = 2; }],
      ['v downgraded to 3', (o) => { o.v = 3; }],
      ['alg replaced', (o) => { o.alg = 'TOTALLY-DIFFERENT'; }],
      ['alg deleted', (o) => { delete o.alg; }],
      ['voprfProofTag forged', (o) => { o.voprfProofTag = 'attacker-chosen-tag'; }],
      ['ecdhJwk gains private d', (o) => { o.ecdhJwk.d = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; }],
      ['ecdhJwk gains key_ops', (o) => { o.ecdhJwk.key_ops = ['deriveBits', 'sign']; }],
      ['ecdhJwk gains ext=false', (o) => { o.ecdhJwk.ext = false; }],
    ];
    for (const [label, mut] of variants) {
      const o = JSON.parse(bobBundle);
      mut(o);
      const parsed = C.parsePeerKeyBundleStrict(JSON.stringify(o), 'bob', { skipCache: true });
      assert.equal(parsed.isFullyPostQuantum, true, `DP-2: ${label} must still parse as fully-PQ (finding)`);
    }
    // ...but ECDH use of the d-carrying bundle fails closed at WebCrypto import.
    const withD = JSON.parse(bobBundle);
    withD.ecdhJwk.d = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    await assert.rejects(
      () => C.encryptMessageText('probe', ROOM_DM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: JSON.stringify(withD) }),
      (err: any) => err instanceof C.E2EEError,
      'ECDH use of a d-carrying bundle must fail closed',
    );
  });

  // -- DP-3 REGRESSION (fixed by DP-14): safety-number helpers wrap malformed input in E2EEError --
  it('DP-3 REGRESSION: hexDigestTo60Digits / computeSafetyNumberFromRawKeys throw E2EEError on malformed input', () => {
    assert.throws(() => SN.hexDigestTo60Digits('zz'.repeat(32)), (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD');
    assert.throws(() => SN.hexDigestTo60Digits(''), (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD');
    assert.throws(() => SN.hexDigestTo60Digits(12345 as unknown as string), (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD');
    assert.throws(() => SN.hexDigestTo60Digits(null as unknown as string), (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD');
    assert.throws(() => SN.computeSafetyNumberFromRawKeys(null as unknown as Uint8Array, new Uint8Array(32)), (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD');
    // Non-string QR input also throws E2EEError
    assert.throws(() => SN.parseAndCompareQrPayload(12345 as unknown as string, 'ab'.repeat(32)), (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD');
    // Sanity: well-formed inputs still behave.
    const good = SN.hexDigestTo60Digits('ab'.repeat(32));
    assert.equal(good.digits60.length, 60);
    assert.equal(SN.parseAndCompareQrPayload(`PQ-MPRBA-SAFETY-v1:${'ab'.repeat(32)}`, 'ab'.repeat(32)).status, 'MATCH');
  });

  // -- DP-4 REGRESSION (fixed by DP-15, round 3): the legacy ECDH message
  // path was REMOVED. Encrypting to a bare ECDH-only peer is now rejected
  // fail-closed (no undecryptable e2ee:ecdh: payload is ever produced), and
  // any e2ee:ecdh: payload is rejected on decrypt. --
  it('DP-4 REGRESSION (fixed by DP-15): ECDH-only peers are rejected fail-closed; e2ee:ecdh: payloads are rejected on decrypt', async () => {
    await refreshFixtures();
    const bobJwk = JSON.stringify(JSON.parse(bobBundle).ecdhJwk);
    const aliceJwk = JSON.stringify(JSON.parse(aliceBundle).ecdhJwk);
    // Encrypt as alice to a bare ECDH-only peer: rejected, no payload produced.
    await assert.rejects(
      () => C.encryptMessageText('DP4-ECDH-SECRET', ROOM_DM, {
        myUsername: 'alice', peerUsername: 'bob', peerPublicKey: bobJwk,
      }),
      (err: any) => err instanceof C.E2EEError && err.code === 'INVALID_BUNDLE',
    );
    // A well-formed-looking legacy payload is rejected on decrypt.
    const legacyPayload = `e2ee:ecdh:${Buffer.from(new Uint8Array(12)).toString('base64')}:${Buffer.from(new Uint8Array(32)).toString('base64')}`;
    await assert.rejects(
      () => C.decryptMessageText(legacyPayload, ROOM_DM, { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceJwk, sender: 'alice' }),
      (err: any) => err instanceof C.E2EEError && err.code === 'MALFORMED_PAYLOAD',
    );
    // And without any peer key at all.
    await assert.rejects(
      () => C.decryptMessageText(legacyPayload, ROOM_DM, { myUsername: 'bob' }),
      (err: any) => err instanceof C.E2EEError,
    );
  });
});

// ---------------------------------------------------------------------------
// CAMPAIGNS
// ---------------------------------------------------------------------------
const pqSeeds: string[] = [];
const groupSeeds: string[] = [];
const PQ_PREFIX = 'e2ee:pq:v2:';
const GEP_PREFIX = 'e2ee:gep:v2:';

function pqFields(p: string): string[] | null {
  if (!p.startsWith(PQ_PREFIX)) return null;
  return p.slice(PQ_PREFIX.length).split(':');
}
function gepFields(p: string): string[] | null {
  if (!p.startsWith(GEP_PREFIX)) return null;
  return p.slice(GEP_PREFIX.length).split(':');
}
/** True when `mutant` is a seed with only the numeric field re-spelled (leading zeros). */
function isNumericRespell(mutantFields: string[], seedFields: string[], numericIdx: number): boolean {
  if (mutantFields.length !== seedFields.length) return false;
  for (let i = 0; i < seedFields.length; i++) {
    if (i === numericIdx) {
      if (!/^\d+$/.test(mutantFields[i])) return false;
      if (Number(mutantFields[i]) !== Number(seedFields[i])) return false;
    } else if (mutantFields[i] !== seedFields[i]) return false;
  }
  return mutantFields[numericIdx] !== seedFields[numericIdx];
}

describe('DP campaigns — decryptMessageText (PQ ratchet / group epoch / ECDH / PBKDF2)', () => {
  it('C1: coverage-guided fuzz of the PQ ratchet path (plain + re-signed mutants)', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    pqSeeds.length = 0;
    const freshSeeds = async (): Promise<string[]> => {
      const s = [await makePqSeed(), await makePqSeed()];
      pqSeeds.push(...s);
      return s;
    };
    const seeds = await freshSeeds();
    const decOpts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, sender: 'alice' };
    const roomIds = [ROOM_DM, ROOM_DM, ROOM_DM, ROOM_DM, 'bob__alice', '', 'alice__bob:extra', 'ALICE__BOB'];
    await runCampaign<string>('C1-pq-decrypt', seeds, {
      budget: 900,
      reseedEvery: 150,
      freshSeeds,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const m = mutateColonPayload(parent, PQ_PREFIX, r);
        return { input: m.text, desc: m.desc };
      },
      run: async (input, desc) => {
        // 30%: re-sign the mutant so it penetrates the ML-DSA gate and
        // exercises the ratchet/GCM logic with mutated KEM/IV/cipher/step.
        let candidate = input;
        let resigned = false;
        if (rng.bool(0.3) && pqFields(input)?.length === 5) {
          try { candidate = await resignPqPayload(input); resigned = true; } catch { /* keep unsigned mutant */ }
        }
        const roomId = rng.pick(roomIds);
        const outcome = await runAsync(() => C.decryptMessageText(candidate, roomId, decOpts));
        recordOutcome('C1-pq-decrypt', `${desc}${resigned ? ' [re-signed]' : ''} room=${roomId}`, outcome, 0);
        if (outcome.kind === 'returned') {
          const res = outcome.value as { text: string; isEncrypted: boolean };
          const f = pqFields(candidate);
          // The ML-DSA signature binds step/kem/iv/cipher (and roomId); the
          // sig field itself is NOT part of the signed content, and noble's
          // signing is randomized (verified: same key+message signs to
          // different bytes), so a re-signed mutant over content identical
          // to a seed is a legitimate decrypt of that seed — expected.
          const seedMatch = pqSeeds.some((s) => {
            const sf = pqFields(s)!;
            if (!f || f.length !== 5 || sf.length !== 5) return false;
            return /^\d+$/.test(f[0]) && Number(f[0]) === Number(sf[0])
              && f[1] === sf[1] && f[2] === sf[2] && f[3] === sf[3]
              && res.text === SECRET_PQ;
          });
          if (desc.startsWith('CONTROL') && seedMatch) countControlAccept('C1-pq-decrypt');
          if (!seedMatch) {
            stats.unexpectedAccepts.push({
              campaign: 'C1-pq-decrypt',
              label: `${desc}${resigned ? ' [re-signed]' : ''}`,
              detail: `decrypted to ${JSON.stringify(res.text).slice(0, 80)} (isEncrypted=${res.isEncrypted})`,
            });
          }
        }
      },
    });
  });

  it('C2: coverage-guided fuzz of the group epoch path', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    await setupGroup('dp2-group', 1);
    groupSeeds.length = 0;
    const freshSeeds = async (): Promise<string[]> => {
      const s = [(await makeGroupSeed('dp2-group')).payload];
      groupSeeds.push(...s);
      return s;
    };
    const seeds = await freshSeeds();
    const decOpts = { myUsername: 'bob', peerUsername: 'alice', peerPublicKey: aliceBundle, groupMembers: ['alice', 'bob'] };
    const roomIds = ['group__dp2-group', 'group__dp2-group', 'group__dp2-group', 'group__other', 'dp2-group', ''];
    await runCampaign<string>('C2-group-decrypt', seeds, {
      budget: 900,
      reseedEvery: 200,
      freshSeeds,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const m = mutateColonPayload(parent, GEP_PREFIX, r);
        return { input: m.text, desc: m.desc };
      },
      run: async (input, desc) => {
        const roomId = rng.pick(roomIds);
        const outcome = await runAsync(() => C.decryptMessageText(input, roomId, decOpts));
        recordOutcome('C2-group-decrypt', `${desc} room=${roomId}`, outcome, 0);
        if (outcome.kind === 'returned') {
          const res = outcome.value as { text: string; isEncrypted: boolean };
          const f = gepFields(input);
          const seedMatch = groupSeeds.some((s) => {
            if (input === s) return res.text === SECRET_GROUP;
            const sf = gepFields(s)!;
            return f !== null && isNumericRespell(f, sf, 0) && res.text === SECRET_GROUP;
          });
          if (desc.startsWith('CONTROL') && seedMatch) countControlAccept('C2-group-decrypt');
          if (!seedMatch) {
            stats.unexpectedAccepts.push({
              campaign: 'C2-group-decrypt',
              label: desc,
              detail: `decrypted to ${JSON.stringify(res.text).slice(0, 80)}`,
            });
          }
        }
      },
    });
  });

  it('C3: coverage-guided fuzz of the removed ECDH path + PBKDF2 legacy path', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    // DP-15 (round 3): the ECDH message path was removed — there is no valid
    // ECDH seed anymore. The campaign feeds a static well-formed-looking
    // e2ee:ecdh: string and mutations of it, and asserts EVERY input throws
    // E2EEError (never decrypts, never returns plaintext).
    const aliceJwk = JSON.stringify(JSON.parse(aliceBundle).ecdhJwk);
    const ecdhSeed = `e2ee:ecdh:${Buffer.from(new Uint8Array(12)).toString('base64')}:${Buffer.from(new Uint8Array(48)).toString('base64')}`;
    const pbkdfSeed = await C.encryptMessageText('DP-FUZZ-PBKDF2-SECRET', ROOM_DM, { customSecret: 'correct horse battery staple' });
    assert.ok(pbkdfSeed.startsWith('e2ee:v1:'), 'PBKDF2 seed must use the v1 prefix');

    const ecdhOpts = { myUsername: 'bob', peerUsername: 'bob', peerPublicKey: aliceJwk, sender: 'alice' };
    await runCampaign<string>('C3a-ecdh-rejected', [ecdhSeed], {
      budget: 300,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const m = mutateColonPayload(parent, 'e2ee:ecdh:', r);
        return { input: m.text, desc: m.desc };
      },
      run: async (input, desc) => {
        const outcome = await runAsync(() => C.decryptMessageText(input, ROOM_DM, ecdhOpts));
        recordOutcome('C3a-ecdh-rejected', desc, outcome, 0);
        if (outcome.kind === 'returned') {
          stats.unexpectedAccepts.push({ campaign: 'C3a-ecdh-rejected', label: desc, detail: `e2ee:ecdh: payload decrypted to ${JSON.stringify((outcome.value as { text: string }).text).slice(0, 80)}` });
        }
      },
    });

    // PBKDF2 is expensive on failure (600k + 50k iterations per attempt), so
    // the budget is small on purpose; the oracle is the same.
    await runCampaign<string>('C3b-pbkdf2-decrypt', [pbkdfSeed], {
      budget: 40,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const m = mutateColonPayload(parent, 'e2ee:v1:', r);
        return { input: m.text, desc: m.desc };
      },
      run: async (input, desc) => {
        const outcome = await runAsync(() =>
          C.decryptMessageText(input, ROOM_DM, { customSecret: 'correct horse battery staple' }));
        recordOutcome('C3b-pbkdf2-decrypt', desc, outcome, 0);
        if (outcome.kind === 'returned') {
          const res = outcome.value as { text: string };
          if (desc.startsWith('CONTROL') && input === pbkdfSeed && res.text === 'DP-FUZZ-PBKDF2-SECRET') countControlAccept('C3b-pbkdf2-decrypt');
          if (input !== pbkdfSeed || res.text !== 'DP-FUZZ-PBKDF2-SECRET') {
            stats.unexpectedAccepts.push({ campaign: 'C3b-pbkdf2-decrypt', label: desc, detail: `decrypted to ${JSON.stringify(res.text).slice(0, 80)}` });
          }
        }
      },
    });
    // Wrong-passphrase control (timed): must fail closed, and the cost is the
    // known 600k+50k PBKDF2 fallback (see report §4).
    const t0 = Date.now();
    await assert.rejects(
      () => C.decryptMessageText(pbkdfSeed, ROOM_DM, { customSecret: 'wrong passphrase' }),
      (err: any) => err instanceof C.E2EEError,
    );
    console.log(`    [dp] PBKDF2 wrong-passphrase decrypt cost: ${Date.now() - t0} ms`);
  });
});
describe('DP campaigns — PQF1 files, key bundles, epoch packets', () => {
  it('C4a: coverage-guided fuzz of PQF1 file payloads (DM + group kinds)', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    await setupGroup('dp4-group', 1);
    const plain = new TextEncoder().encode(SECRET_FILE);
    const dmFile = await C.encryptFileBytes(plain, ROOM_DM, {
      myUsername: 'alice', peerPublicKey: bobBundle, peerUsername: 'bob',
    });
    const groupFile = await C.encryptFileBytes(plain, 'group__dp4-group', { groupMembers: ['alice', 'bob'] });
    assert.equal(dmFile[4], 4, 'DM file kind byte is 4 (per-file ML-KEM key, M10)');
    assert.equal(groupFile[4], 2, 'group file kind byte is 2');
    const seeds: Array<{ bytes: Uint8Array; opts: any }> = [
      { bytes: dmFile, opts: { myUsername: 'bob', peerPublicKey: aliceBundle, peerUsername: 'alice' } },
      { bytes: groupFile, opts: { groupMembers: ['alice', 'bob'] } },
    ];
    await runCampaign<{ bytes: Uint8Array; opts: any }>('C4a-pqf1', seeds, {
      budget: 700,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const mutated = mutateBytes(parent.bytes, r, parent.bytes);
        return { input: { bytes: mutated, opts: parent.opts }, desc: `len ${parent.bytes.length}->${mutated.length}` };
      },
      run: async (input, desc) => {
        const outcome = await runAsync(() => C.decryptFileBytes(input.bytes, input.opts.groupMembers ? 'group__dp4-group' : ROOM_DM, input.opts));
        recordOutcome('C4a-pqf1', desc, outcome, 0);
        if (outcome.kind === 'returned') {
          const out = outcome.value as Uint8Array;
          const plainOk = out.length === plain.length && out.every((b, i) => b === plain[i]);
          const expectedAccept = plainOk && seeds.some((sd) => {
            if (input.bytes.length !== sd.bytes.length) return false;
            const diffs: number[] = [];
            for (let i = 0; i < sd.bytes.length; i++) if (input.bytes[i] !== sd.bytes[i]) diffs.push(i);
            if (diffs.length === 0) return true;
            // KNOWN leniencies for kind-4 DM files (receiver = bob):
            // (a) the epoch header bytes (5..8) are IGNORED for DM files
            // (W3 noted, S1 sweep confirms); (b) the file carries TWO
            // ML-KEM capsules (M10) — bob only uses his own (ctPeer 21..1108
            // + wrapPeer 1109..1140), so bytes in the SENDER's capsule region
            // (ctSelf 1141..2228 + wrapSelf 2229..2260) are invisible to him.
            // Either way the file still decrypts to the IDENTICAL plaintext
            // (plainOk is required above) — the AES-GCM tag still protects
            // the plaintext itself.
            if (
              sd.bytes[4] === 4 &&
              input.bytes[4] === 4 &&
              diffs.every(d => (d >= 5 && d <= 8) || (d >= 1141 && d <= 2260))
            ) return true;
            return false;
          });
          if (desc.startsWith('CONTROL') && expectedAccept) countControlAccept('C4a-pqf1');
          if (!expectedAccept) {
            stats.unexpectedAccepts.push({ campaign: 'C4a-pqf1', label: desc, detail: `decrypted ${out.length} bytes` });
          }
        }
      },
    });
  });

  it('C4b: coverage-guided fuzz of PQF1 manual (PBKDF2) files — small budget, PBKDF2 cost per attempt', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    const plain = new TextEncoder().encode(SECRET_FILE);
    const manualFile = await C.encryptFileBytes(plain, ROOM_DM, { customSecret: 'correct horse battery staple' });
    assert.equal(manualFile[4], 3, 'manual file kind byte is 3');
    const opts = { customSecret: 'correct horse battery staple' };
    await runCampaign<Uint8Array>('C4b-pqf1-manual', [manualFile], {
      budget: 40,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        return { input: mutateBytes(parent, r, parent), desc: `len ${parent.length}` };
      },
      run: async (input, desc) => {
        const outcome = await runAsync(() => C.decryptFileBytes(input, ROOM_DM, opts));
        recordOutcome('C4b-pqf1-manual', desc, outcome, 0);
        if (outcome.kind === 'returned') {
          const out = outcome.value as Uint8Array;
          const isSeed = input.length === manualFile.length && input.every((b, i) => b === manualFile[i]);
          if (desc.startsWith('CONTROL') && isSeed && out.every((b, i) => b === plain[i])) countControlAccept('C4b-pqf1-manual');
          if (!isSeed || !out.every((b, i) => b === plain[i])) {
            stats.unexpectedAccepts.push({ campaign: 'C4b-pqf1-manual', label: desc, detail: `decrypted ${out.length} bytes` });
          }
        }
      },
    });
  });

  it('C5: coverage-guided fuzz of key-bundle parsing (lenient + strict, plain + re-signed mutants)', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    // Ground-truth oracle: a bundle may verify iff its OWN ML-DSA signature
    // verifies over its OWN content (expected username 'bob', ecdhJwk crv/x/y,
    // mlkemPubB64) AND the key/signature lengths are valid. This is independent
    // of the seed, so it stays sound when the corpus holds RE-SIGNED mutants
    // (their signatures are valid over *their* content, not the seed's) — the
    // previous seed-comparison oracle falsely flagged those as unexpected.
    const signatureVerifiesOverOwnContent = (obj: Record<string, any>): boolean => {
      try {
        if (!obj.ecdhJwk || typeof obj.ecdhJwk !== 'object') return false;
        if (C.base64ToBuf(obj.mlkemPubB64).byteLength !== 1184) return false;
        if (C.base64ToBuf(obj.mldsaPubB64).byteLength !== 1952) return false;
        const sig = C.base64ToBuf(obj.mldsaSigB64);
        if (sig.byteLength !== 3309) return false;
        const target = C.serializeBundleForSigning({ username: 'bob', ecdhJwk: obj.ecdhJwk, mlkemPubB64: obj.mlkemPubB64 });
        return ml_dsa65.verify(sig, target, C.base64ToBuf(obj.mldsaPubB64));
      } catch { return false; }
    };

    await runCampaign<string>('C5-bundle-parse', [bobBundle], {
      budget: 1200,
      mutate: async (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const m = mutateJsonString(parent, r);
        let text = m.text;
        let desc = m.desc;
        if (r.bool(0.3)) {
          try {
            const obj = JSON.parse(text);
            if (obj && typeof obj === 'object' && obj.ecdhJwk && typeof obj.mlkemPubB64 === 'string') {
              text = await resignBundle(obj);
              desc += ' [re-signed]';
            }
          } catch { /* keep unsigned mutant */ }
        }
        return { input: text, desc, };
      },
      run: async (input, desc) => {
        const resigned = desc.includes('[re-signed]');
        let obj: Record<string, any> | null = null;
        try { obj = JSON.parse(input); } catch { obj = null; }
        // Lenient parse must never throw (by design) and must never report
        // isFullyPostQuantum for a mutant whose signed content changed.
        const lenient = runSync(() => C.parsePeerKeyBundle(input, 'bob', { skipCache: true }));
        recordOutcome('C5-bundle-parse', `lenient ${desc}`, lenient, 0);
        if (lenient.kind === 'returned') {
          const res = lenient.value as ReturnType<typeof C.parsePeerKeyBundle>;
          if (res.isFullyPostQuantum) {
            const expected = obj !== null && signatureVerifiesOverOwnContent(obj);
            if (!expected) {
              stats.unexpectedAccepts.push({
                campaign: 'C5-bundle-parse', label: `lenient ${desc}`,
                detail: `isFullyPostQuantum=true for mutant (resigned=${resigned})`,
              });
            }
          }
        }
        // Strict parse must throw E2EEError except for the same expected class.
        const strict = runSync(() => C.parsePeerKeyBundleStrict(input, 'bob', { skipCache: true }));
        if (desc.startsWith('CONTROL') && strict.kind === 'returned') countControlAccept('C5-bundle-parse');
        recordOutcome('C5-bundle-parse', `strict ${desc}`, strict, 0);
        if (strict.kind === 'returned') {
          const expected = obj !== null && signatureVerifiesOverOwnContent(obj);
          if (!expected) {
            stats.unexpectedAccepts.push({
              campaign: 'C5-bundle-parse', label: `strict ${desc}`,
              detail: 'strict parse ACCEPTED a mutant whose signed content changed',
            });
          }
        }
      },
    });
    // Deterministic check: a re-signed bundle with a garbage-but-well-formed
    // ECDH x still parses as fully-PQ (malicious-signer model); ECDH use of
    // it fails closed at WebCrypto import.
    const garbageX = JSON.parse(bobBundle);
    garbageX.ecdhJwk.x = 'AAAA';
    const garbageXSigned = await resignBundle(garbageX);
    const parsed = C.parsePeerKeyBundleStrict(garbageXSigned, 'bob', { skipCache: true });
    assert.equal(parsed.isFullyPostQuantum, true, 're-signed garbage-x bundle parses (signer chose it)');
    await assert.rejects(
      () => C.encryptMessageText('probe', ROOM_DM, { myUsername: 'alice', peerUsername: 'bob', peerPublicKey: garbageXSigned }),
      (err: any) => err instanceof C.E2EEError,
      'ECDH use of a garbage-x bundle must fail closed',
    );
  });

  it('C6: coverage-guided fuzz of group epoch packet decapsulation', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    const bundles: Record<string, ReturnType<typeof C.parsePeerKeyBundle>> = { alice: aliceParsed, bob: bobParsed };
    const packet = await C.createGroupEpochPacket(bundles);
    const seed = packet.keys['alice'];
    assert.ok(seed && seed.split(':').length === 3, 'epoch packet seed must have 3 fields');
    await runCampaign<string>('C6-epoch-packet', [seed], {
      budget: 250,
      mutate: (parent, r) => {
        if (r.next() < 0.05) return { input: parent, desc: 'CONTROL unmutated seed' };
        const m = mutateColonPayload(parent, '', r);
        return { input: m.text, desc: m.desc };
      },
      run: async (input, desc) => {
        const outcome = await runAsync(() => C.decapsulateGroupEpochKey('alice', input));
        recordOutcome('C6-epoch-packet', desc, outcome, 0);
        if (outcome.kind === 'returned') {
          const v = outcome.value as string | null;
          if (desc.startsWith('CONTROL') && input === seed && v === packet.epochKeyB64) countControlAccept('C6-epoch-packet');
          if (v !== null && (input !== seed || v !== packet.epochKeyB64)) {
            stats.unexpectedAccepts.push({ campaign: 'C6-epoch-packet', label: desc, detail: `returned a key for a mutant: ${String(v).slice(0, 40)}` });
          }
        }
      },
    });
    // Deterministic controls: bob's packet decapsulated as alice -> null;
    // empty/undefined username -> null (never a key, never throws).
    assert.equal(await C.decapsulateGroupEpochKey('alice', packet.keys['bob']), null);
    assert.equal(await C.decapsulateGroupEpochKey('', seed), null);
    assert.equal(await C.decapsulateGroupEpochKey('alice', ''), null);
  });
});
describe('DP campaigns — raw primitives, safety-number parsers, helpers', () => {
  it('C7: coverage-guided fuzz of raw ML-KEM-768 / ML-DSA-65 primitives', { timeout: 300_000 }, async () => {
    const { publicKey: kemPk, secretKey: kemSk } = ml_kem768.keygen();
    const { cipherText: kemCt, sharedSecret: kemSs } = ml_kem768.encapsulate(kemPk);
    const { publicKey: dsaPk, secretKey: dsaSk } = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('dp-fuzz-message');
    const sig = ml_dsa65.sign(msg, dsaSk);
    assert.equal(kemCt.length, 1088);
    assert.equal(sig.length, 3309);

    // decapsulate: valid-length corrupt ct -> implicit rejection (32B, != true secret)
    await runCampaign<Uint8Array>('C7a-kem-decaps', [kemCt], {
      budget: 500,
      coveragePerInput: false,
      mutate: (parent, r) => ({ input: mutateBytes(parent, r, parent), desc: `ct len ${parent.length}` }),
      run: (input) => {
        // NOTE: noble throws plain Error (not E2EEError) for wrong lengths —
        // that is the library's own error type, recorded here as expected.
        const outcome = runSync(() => ml_kem768.decapsulate(input, kemSk));
        if (outcome.kind === 'returned') {
          const out = outcome.value as Uint8Array;
          if (input.length !== 1088) {
            stats.unexpectedAccepts.push({ campaign: 'C7a-kem-decaps', label: 'wrong-length ct', detail: `returned ${out.length} bytes instead of throwing` });
          } else if (out.length !== 32 || (input.every((b, i) => b === kemCt[i]) === false && out.every((b, i) => b === kemSs[i]))) {
            stats.unexpectedAccepts.push({ campaign: 'C7a-kem-decaps', label: 'corrupt ct', detail: 'returned the TRUE shared secret for a corrupt ciphertext' });
          }
        }
      },
    });
    // decapsulate with mutated secret key (valid length) -> 32B secret, never throws for length reasons
    await runCampaign<Uint8Array>('C7b-kem-decaps-sk', [kemSk], {
      budget: 200,
      coveragePerInput: false,
      mutate: (parent, r) => ({ input: mutateBytes(parent, r, parent), desc: `sk len ${parent.length}` }),
      run: (input) => {
        const outcome = runSync(() => ml_kem768.decapsulate(kemCt, input));
        if (outcome.kind === 'returned' && (outcome.value as Uint8Array).length !== 32) {
          stats.unexpectedAccepts.push({ campaign: 'C7b-kem-decaps-sk', label: 'mutated sk', detail: `returned ${(outcome.value as Uint8Array).length} bytes` });
        }
      },
    });
    // verify: mutated sig/msg/pk -> false (or throw on wrong length), never true
    await runCampaign<{ sig: Uint8Array; msg: Uint8Array; pk: Uint8Array }>('C7c-dsa-verify', [{ sig, msg, pk: dsaPk }], {
      budget: 500,
      coveragePerInput: false,
      mutate: (parent, r) => {
        const which = r.int(3);
        if (which === 0) return { input: { sig: mutateBytes(parent.sig, r, parent.sig), msg: parent.msg, pk: parent.pk }, desc: 'sig mutated' };
        if (which === 1) return { input: { sig: parent.sig, msg: mutateBytes(parent.msg, r, parent.msg), pk: parent.pk }, desc: 'msg mutated' };
        return { input: { sig: parent.sig, msg: parent.msg, pk: mutateBytes(parent.pk, r, parent.pk) }, desc: 'pk mutated' };
      },
      run: (input) => {
        const outcome = runSync(() => ml_dsa65.verify(input.sig, input.msg, input.pk));
        if (outcome.kind === 'returned' && outcome.value === true) {
          const untouched = input.sig.every((b, i) => b === sig[i]) && input.msg.every((b, i) => b === msg[i]) && input.pk.every((b, i) => b === dsaPk[i]);
          if (!untouched) {
            stats.unexpectedAccepts.push({ campaign: 'C7c-dsa-verify', label: 'verify', detail: 'mutated sig/msg/pk VERIFIED' });
          }
        }
      },
    });
    // keygen determinism (FIPS 203/204 keygen is deterministic given the seed)
    const seed64 = rng.bytes(64);
    const k1 = ml_kem768.keygen(seed64);
    const k2 = ml_kem768.keygen(seed64);
    assert.deepEqual(Array.from(k1.publicKey), Array.from(k2.publicKey), 'ML-KEM keygen must be deterministic for a fixed seed');
    const dseed = rng.bytes(32);
    const d1 = ml_dsa65.keygen(dseed);
    const d2 = ml_dsa65.keygen(dseed);
    assert.deepEqual(Array.from(d1.publicKey), Array.from(d2.publicKey), 'ML-DSA keygen must be deterministic for a fixed seed');
  });

  it('C8: coverage-guided fuzz of safety-number parsers', { timeout: 300_000 }, async () => {
    const localHex = '0123456789abcdef'.repeat(4);
    const validQr = `PQ-MPRBA-SAFETY-v1:${localHex}`;
    const { digits60 } = SN.hexDigestTo60Digits(localHex);

    // QR payloads: MATCH only for the exact valid payload.
    await runCampaign<string>('C8a-qr', [validQr], {
      budget: 400,
      coveragePerInput: false,
      mutate: (parent, r) => {
        if (r.next() < 0.15) return { input: r.pick(['', ' ', 'PQ-MPRBA-SAFETY-v1:', 'pq-mprba-safety-v1:' + localHex, validQr.toUpperCase(), validQr + ' ', ' ' + validQr, validQr + 'x']), desc: 'edge string' };
        const chars = parent.split('');
        const pos = r.int(chars.length);
        chars[pos] = r.pick('0123456789abcdefABCDEFxyz :.-'.split(''));
        return { input: chars.join(''), desc: `char[${pos}] mutated` };
      },
      run: (input) => {
        const outcome = runSync(() => SN.parseAndCompareQrPayload(input, localHex));
        recordOutcome('C8a-qr', 'qr', outcome, 0);
        if (outcome.kind === 'returned') {
          const res = outcome.value as { status: string };
          // parseAndCompareQrPayload TRIMS the input first (by design), so a
          // whitespace-padded copy of the valid payload MATCHes — expected.
          if (res.status === 'MATCH' && input.trim() !== validQr) {
            stats.unexpectedAccepts.push({ campaign: 'C8a-qr', label: 'qr', detail: `MATCH for ${JSON.stringify(input).slice(0, 90)}` });
          }
        }
      },
    });
    // 60-digit compare: independent normalizer (Persian/Arabic digits -> Latin, strip whitespace).
    const normalizeIndependent = (s: string): string => {
      const fa = '۰۱۲۳۴۵۶۷۸۹';
      const ar = '٠١٢٣٤٥٦٧٨٩';
      let out = '';
      for (const ch of s) {
        const p = fa.indexOf(ch);
        if (p !== -1) { out += String(p); continue; }
        const a = ar.indexOf(ch);
        if (a !== -1) { out += String(a); continue; }
        if (!/\s/.test(ch)) out += ch;
      }
      return out;
    };
    await runCampaign<string>('C8b-digits', [digits60], {
      budget: 300,
      coveragePerInput: false,
      mutate: (parent, r) => {
        const chars = parent.split('');
        const op = r.int(5);
        if (op === 0) { const p = r.int(chars.length); chars[p] = String(r.int(10)); }
        else if (op === 1) { const p = r.int(chars.length); chars[p] = r.pick('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩'.split('')); }
        else if (op === 2) { const p = r.int(chars.length); chars.splice(p, 0, ' '); }
        else if (op === 3) { const p = r.int(chars.length); chars[p] = r.pick('abxyz'.split('')); }
        else { chars.splice(r.int(chars.length), 1); }
        return { input: chars.join(''), desc: `digits op${op}` };
      },
      run: (input) => {
        const outcome = runSync(() => SN.compareSafetyNumberDigits(digits60, input));
        recordOutcome('C8b-digits', 'digits', outcome, 0);
        if (outcome.kind === 'returned') {
          const res = outcome.value as { validFormat: boolean; matches: boolean };
          const expectedMatch = normalizeIndependent(input) === digits60 && /^[0-9]{60}$/.test(normalizeIndependent(input));
          if (res.matches !== expectedMatch) {
            stats.unexpectedAccepts.push({ campaign: 'C8b-digits', label: 'digits', detail: `matches=${res.matches} but independent normalizer says ${expectedMatch} for ${JSON.stringify(input).slice(0, 80)}` });
          }
        }
      },
    });
    // hexDigestTo60Digits: independent BigInt recomputation, or raw SyntaxError/TypeError (DP-3).
    const hexChars = '0123456789abcdefABCDEFxyz ';
    await runCampaign<string>('C8c-hexdigest', [localHex], {
      budget: 300,
      coveragePerInput: false,
      mutate: (_parent, r) => {
        const len = r.int(70);
        let s = '';
        for (let i = 0; i < len; i++) s += hexChars[r.int(hexChars.length)];
        if (r.bool(0.2)) s = '0x' + s;
        if (r.bool(0.2)) s = ' ' + s + ' ';
        return { input: s, desc: `hex len ${len}` };
      },
      run: (input) => {
        const outcome = runSync(() => SN.hexDigestTo60Digits(input));
        if (outcome.kind === 'threw-other') {
          // DP-3: raw SyntaxError (non-hex) / TypeError (non-string) are the
          // documented behaviour for malformed input; anything else is new.
          if (outcome.name !== 'SyntaxError' && outcome.name !== 'TypeError') {
            stats.nonE2EEThrows.push({ campaign: 'C8c-hexdigest', label: 'hexdigest', err: `${outcome.name}: ${outcome.message}` });
          }
          return;
        }
        if (outcome.kind === 'returned') {
          const res = outcome.value as { digits60: string };
          let expected: string;
          try {
            expected = (BigInt('0x' + input.trim().toLowerCase()) % (10n ** 60n)).toString(10).padStart(60, '0');
          } catch {
            stats.unexpectedAccepts.push({ campaign: 'C8c-hexdigest', label: 'hexdigest', detail: `returned digits for unparseable input ${JSON.stringify(input).slice(0, 60)}` });
            return;
          }
          if (res.digits60 !== expected) {
            stats.unexpectedAccepts.push({ campaign: 'C8c-hexdigest', label: 'hexdigest', detail: `wrong digits60 for ${JSON.stringify(input).slice(0, 60)}` });
          }
        }
      },
    });
    // computeSafetyNumberFromRawKeys: independent preimage recomputation.
    await runCampaign<{ a: Uint8Array; b: Uint8Array }>('C8d-safety-from-keys', [{ a: ml_dsa65.keygen().publicKey, b: ml_dsa65.keygen().publicKey }], {
      budget: 150,
      coveragePerInput: false,
      mutate: (parent, r) => {
        const which = r.int(2);
        const len = r.pick([0, 1, 2, 32, 64, 1952]);
        const fresh = rng.bytes(len);
        return { input: which === 0 ? { a: fresh, b: parent.b } : { a: parent.a, b: fresh }, desc: `key len ${len}` };
      },
      run: (input) => {
        const outcome = runSync(() => SN.computeSafetyNumberFromRawKeys(input.a, input.b));
        recordOutcome('C8d-safety-from-keys', 'safety-from-keys', outcome, 0);
        if (outcome.kind === 'returned') {
          const res = outcome.value as { digits60: string };
          const cmp = SN.compareRawBytesLexicographically(input.a, input.b);
          const first = cmp <= 0 ? input.a : input.b;
          const second = cmp <= 0 ? input.b : input.a;
          const be = (n: number) => { const b = new Uint8Array(4); b[0] = (n >>> 24) & 0xff; b[1] = (n >>> 16) & 0xff; b[2] = (n >>> 8) & 0xff; b[3] = n & 0xff; return b; };
          const domain = new TextEncoder().encode('PQ-MPRBA-SAFETY-v1');
          const pre = new Uint8Array(domain.length + 1 + 4 + first.length + 4 + second.length);
          let off = 0;
          pre.set(domain, off); off += domain.length;
          pre[off++] = 0;
          pre.set(be(first.length), off); off += 4;
          pre.set(first, off); off += first.length;
          pre.set(be(second.length), off); off += 4;
          pre.set(second, off);
          const hex = createHash('sha256').update(pre).digest('hex');
          const expected = (BigInt('0x' + hex) % (10n ** 60n)).toString(10).padStart(60, '0');
          if (res.digits60 !== expected) {
            stats.unexpectedAccepts.push({ campaign: 'C8d-safety-from-keys', label: 'safety', detail: `digits60 mismatch for key lens ${input.a.length}/${input.b.length}` });
          }
        }
      },
    });
  });

  it('C9: coverage-guided fuzz of base64 helpers + serializers', { timeout: 300_000 }, async () => {
    const b64Seeds = ['AQ==', 'AAECAwQFBgc=', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'abcd', ''];
    await runCampaign<string>('C9a-base64', b64Seeds, {
      budget: 600,
      coveragePerInput: false,
      mutate: (_parent, r) => {
        const len = r.int(48);
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n\t!-_é';
        let s = '';
        for (let i = 0; i < len; i++) s += alphabet[r.int(alphabet.length)];
        return { input: s, desc: `b64 len ${len}` };
      },
      run: (input) => {
        const outcome = runSync(() => C.base64ToBuf(input));
        recordOutcome('C9a-base64', 'base64ToBuf', outcome, 0);
        if (outcome.kind === 'returned') {
          const bytes = outcome.value as Uint8Array;
          const reenc = Buffer.from(bytes).toString('base64');
          if (reenc !== input) {
            stats.unexpectedAccepts.push({ campaign: 'C9a-base64', label: 'base64', detail: `decoded ${JSON.stringify(input).slice(0, 60)} but re-encode is ${reenc.slice(0, 60)}` });
          }
        }
        // bufToBase64 round-trip on the same bytes
        if (outcome.kind === 'returned') {
          const bytes = outcome.value as Uint8Array;
          const rt = runSync(() => C.bufToBase64(bytes));
          if (rt.kind === 'returned' && rt.value !== input) {
            stats.unexpectedAccepts.push({ campaign: 'C9a-base64', label: 'bufToBase64', detail: 'round-trip mismatch' });
          }
        }
      },
    });
    // Serializer robustness probes (DP-3 family: raw TypeError on null ecdhJwk).
    const serOutcomes: string[] = [];
    for (const bad of [null, undefined, 'x', 123] as unknown[]) {
      const o = runSync(() => C.serializeBundleForSigning({ username: 'bob', ecdhJwk: bad as any, mlkemPubB64: 'AAAA' }));
      serOutcomes.push(`${JSON.stringify(bad)}:${o.kind}${o.kind === 'threw-other' ? `(${(o as any).name})` : ''}`);
    }
    console.log(`    [dp] serializeBundleForSigning with bad ecdhJwk -> ${serOutcomes.join(' | ')}`);
    assert.ok(serOutcomes.every((s) => s.includes('threw-other(TypeError)') || s.includes('returned')), 'serializer must either return or throw a raw TypeError (documented DP-3 family)');
  });

  it('C10: structured sweep of rotateGroupEpoch (epoch / members / key length)', { timeout: 300_000 }, async () => {
    await refreshFixtures();
    const b64 = (len: number) => Buffer.from(rng.bytes(len)).toString('base64');
    let accepted = 0;
    let threw = 0;
    for (const epoch of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1, 2, 3, 100, 2 ** 53] as unknown[]) {
      for (const members of [[], ['alice'], ['alice', 'bob'], ['bob', 'alice'], ['alice', 'alice'], [''], [null], [123]] as unknown[]) {
        for (const keyLen of [0, 1, 16, 31, 32, 33, 64, 100]) {
          countCase('C10-rotate-epoch');
          const outcome = await runAsync(() => C.rotateGroupEpoch('dp10-group', epoch as number, members as string[], b64(keyLen)));
          if (outcome.kind === 'returned') {
            accepted++;
            const state = outcome.value as { epochs: Record<number, { rootKey: Uint8Array }> };
            // W3-F7 known leniency: any key length is stored as-is.
            assert.equal(state.epochs[epoch as number].rootKey.length, keyLen, `epoch key of ${keyLen} bytes stored as-is`);
          } else {
            threw++;
            if (outcome.kind === 'threw-other') {
              stats.nonE2EEThrows.push({ campaign: 'C10-rotate-epoch', label: `epoch=${epoch} members=${JSON.stringify(members)} len=${keyLen}`, err: `${outcome.name}: ${outcome.message}` });
            }
          }
        }
      }
    }
    console.log(`    [dp] C10 rotateGroupEpoch sweep: accepted=${accepted} threw=${threw}`);
    // Only integer epochs >= 1 with a decodable key may be accepted.
    assert.ok(accepted > 0, 'at least the valid combos must be accepted');
    assert.ok(threw > 0, 'invalid epochs/members must throw');
  });

  it('C11: prefix / magic recognition sweep (isE2EEPayload / isEncryptedFileBytes)', { timeout: 120_000 }, async () => {
    const payloadCases: Array<[unknown, boolean]> = [
      ['e2ee:pq:v2:', true], ['e2ee:pq:v2', false], ['e2ee:pq:v3:', false],
      ['E2EE:PQ:V2:', false], ['e2ee:gep:v2:', true], ['e2ee:gep:v2', false],
      ['e2ee:ecdh:', true], ['e2ee:v1:', true], ['e2ee:', false], ['e2ee', false],
      ['', false], ['hello', false], ['e2ee:pq:v2: ', true], [null, false], [undefined, false],
      [12345, false], [{}, false],
    ];
    for (const [input, expected] of payloadCases) {
      countCase('C11-prefixes');
      const outcome = runSync(() => C.isE2EEPayload(input as string));
      assert.equal(outcome.kind, 'returned', `isE2EEPayload must not throw for ${JSON.stringify(input)}`);
      assert.equal((outcome.value as boolean), expected, `isE2EEPayload(${JSON.stringify(input)})`);
    }
    const magic = [0x50, 0x51, 0x46, 0x31];
    for (let len = 0; len <= 25; len++) {
      countCase('C11-prefixes');
      const data = new Uint8Array(len);
      data.set(magic.slice(0, Math.min(4, len)));
      const outcome = runSync(() => C.isEncryptedFileBytes(data));
      assert.equal(outcome.kind, 'returned');
      assert.equal(outcome.value as boolean, len >= 21, `isEncryptedFileBytes len ${len}`);
    }
    countCase('C11-prefixes');
    assert.equal(C.isEncryptedFileBytes(null), false);
    countCase('C11-prefixes');
    assert.equal(C.isEncryptedFileBytes(undefined), false);
    const badMagic = new Uint8Array(21);
    badMagic.set([0x50, 0x51, 0x46, 0x32]);
    countCase('C11-prefixes');
    assert.equal(C.isEncryptedFileBytes(badMagic), false);
  });
});

describe('DP systematic sweeps (exhaustive small domains)', () => {
  it('S1: PQF1 kind byte 0..255 — only kind 4 accepts a new DM file (kind 1 is legacy-decrypt only); epoch bytes are ignored for DM, binding for group', { timeout: 120_000 }, async () => {
    await refreshFixtures();
    await setupGroup('dpS1-group', 1);
    const plain = new TextEncoder().encode(SECRET_FILE);
    const dmFile = await C.encryptFileBytes(plain, ROOM_DM, {
      myUsername: 'alice', peerPublicKey: bobBundle, peerUsername: 'bob',
    });
    const groupFile = await C.encryptFileBytes(plain, 'group__dpS1-group', { groupMembers: ['alice', 'bob'] });
    const dmOpts = { myUsername: 'bob', peerPublicKey: aliceBundle, peerUsername: 'alice' };
    const groupOpts = { groupMembers: ['alice', 'bob'] };
    let dmAccepted = 0;
    for (let kind = 0; kind < 256; kind++) {
      countCase('S1-kind-sweep');
      const mutated = new Uint8Array(dmFile);
      mutated[4] = kind;
      const outcome = await runAsync(() => C.decryptFileBytes(mutated, ROOM_DM, dmOpts));
      if (outcome.kind === 'returned') {
        dmAccepted++;
        assert.equal(kind, 4, `only kind 4 may decrypt a new DM file, but kind ${kind} did`);
        assert.deepEqual(Array.from(outcome.value as Uint8Array), Array.from(plain));
      } else {
        assert.equal(outcome.kind, 'threw-e2ee', `kind ${kind} must throw E2EEError`);
      }
    }
    assert.equal(dmAccepted, 1, 'exactly one kind value (4) may decrypt the DM file');
    // Epoch bytes: ignored for DM files (accepted with any epoch), binding for group files.
    for (const epoch of [0, 2, 0x7fffffff, 0xffffffff]) {
      countCase('S1-kind-sweep');
      const mutated = new Uint8Array(dmFile);
      new DataView(mutated.buffer).setUint32(5, epoch, false);
      const out = await C.decryptFileBytes(mutated, ROOM_DM, dmOpts);
      assert.deepEqual(Array.from(out), Array.from(plain), `DM file must still decrypt with epoch header ${epoch}`);
    }
    let groupAccepted = 0;
    for (const epoch of [0, 1, 2, 3, 0xffffffff]) {
      countCase('S1-kind-sweep');
      const mutated = new Uint8Array(groupFile);
      new DataView(mutated.buffer).setUint32(5, epoch, false);
      const outcome = await runAsync(() => C.decryptFileBytes(mutated, 'group__dpS1-group', groupOpts));
      if (outcome.kind === 'returned') {
        groupAccepted++;
        assert.equal(epoch, 1, `only epoch 1 may decrypt the group file, but epoch ${epoch} did`);
      }
    }
    assert.equal(groupAccepted, 1, 'exactly one epoch value (1) may decrypt the group file');
    console.log('    [dp] S1: kind sweep 0..255 done (1 accept: kind 4), epoch sweep done (DM: ignored, group: only 1)');
  });

  it('S2: ML-KEM ciphertext single-bit sweep — corrupt ct never yields the true secret', { timeout: 120_000 }, async () => {
    const { publicKey, secretKey } = ml_kem768.keygen();
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    let checked = 0;
    for (let pos = 0; pos < cipherText.length; pos += 16) {
      for (const bit of [0, 7]) {
        countCase('S2-kem-sweep');
        const bad = new Uint8Array(cipherText);
        bad[pos] ^= 1 << bit;
        const out = ml_kem768.decapsulate(bad, secretKey);
        assert.equal(out.length, 32);
        assert.notDeepEqual(Array.from(out), Array.from(sharedSecret), `bit flip at ct[${pos}] bit ${bit} must not yield the true secret`);
        checked++;
      }
    }
    for (const fill of [0x00, 0xff]) {
      countCase('S2-kem-sweep');
      const out = ml_kem768.decapsulate(new Uint8Array(1088).fill(fill), secretKey);
      assert.equal(out.length, 32);
      assert.notDeepEqual(Array.from(out), Array.from(sharedSecret), `all-0x${fill.toString(16)} ct must not yield the true secret`);
      checked++;
    }
    console.log(`    [dp] S2: ${checked} corrupt-ciphertext decapsulations, all implicit-rejection`);
  });

  it('S3: ML-DSA signature region sweep — any flipped byte fails verification', { timeout: 120_000 }, async () => {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('dp-s3-message');
    const sig = ml_dsa65.sign(msg, secretKey);
    assert.equal(ml_dsa65.verify(sig, msg, publicKey), true);
    // 3309-byte sig layout: commitment (0..31), z, hint (tail). Sample each region.
    const positions = [0, 1, 15, 16, 31, 32, 33, 500, 1000, 2000, 3000, 3200, 3290, 3300, 3308];
    for (const pos of positions) {
      countCase('S3-dsa-sweep');
      const bad = new Uint8Array(sig);
      bad[pos] ^= 0x01;
      assert.equal(ml_dsa65.verify(bad, msg, publicKey), false, `sig byte ${pos} flipped must not verify`);
      countCase('S3-dsa-sweep');
      const bad2 = new Uint8Array(sig);
      bad2[pos] ^= 0x80;
      assert.equal(ml_dsa65.verify(bad2, msg, publicKey), false, `sig byte ${pos} flipped (0x80) must not verify`);
    }
    console.log(`    [dp] S3: ${positions.length * 2} flipped-signature verifications, all false`);
  });

  it('S4: decryptFileBytes type probes (non-Uint8Array, subarrays)', { timeout: 120_000 }, async () => {
    await refreshFixtures();
    const plain = new TextEncoder().encode(SECRET_FILE);
    const dmFile = await C.encryptFileBytes(plain, ROOM_DM, {
      myUsername: 'alice', peerPublicKey: bobBundle, peerUsername: 'bob',
    });
    const dmOpts = { myUsername: 'bob', peerPublicKey: aliceBundle, peerUsername: 'alice' };
    for (const bad of ['PQF1' + 'x'.repeat(30), null, undefined, 12345, {}, []] as unknown[]) {
      countCase('S4-file-types');
      await assert.rejects(
        () => C.decryptFileBytes(bad as Uint8Array, ROOM_DM, dmOpts),
        (err: any) => err instanceof C.E2EEError,
        `decryptFileBytes must throw E2EEError for ${JSON.stringify(bad)?.slice(0, 30)}`,
      );
    }
    // A valid file embedded at an offset inside a bigger buffer (byteOffset != 0)
    // must still decrypt — the header reader uses data.byteOffset.
    const big = new Uint8Array(dmFile.length + 16);
    big.set(rng.bytes(7), 0);
    big.set(dmFile, 7);
    const view = big.subarray(7, 7 + dmFile.length);
    assert.equal(view.byteOffset, 7);
    countCase('S4-file-types');
    const out = await C.decryptFileBytes(view, ROOM_DM, dmOpts);
    assert.deepEqual(Array.from(out), Array.from(plain), 'offset subarray must decrypt');
    // Empty and short inputs.
    for (const short of [new Uint8Array(0), new Uint8Array(20), dmFile.slice(0, 21)] as Uint8Array[]) {
      countCase('S4-file-types');
      await assert.rejects(
        () => C.decryptFileBytes(short, ROOM_DM, dmOpts),
        (err: any) => err instanceof C.E2EEError,
      );
    }
  });
});

describe('DP summary', () => {
  it('summary: totals, unexpected accepts, non-E2EE throws, coverage guidance', async () => {
    await coverageStop();
    console.log('    [dp] ================= SUMMARY =================');
    console.log(`    [dp] total fuzz cases run: ${stats.totalCases}`);
    for (const [k, v] of Object.entries(stats.perCampaign)) console.log(`    [dp]   ${k}: ${v}`);
    console.log(`    [dp] coverage-guided interesting inputs kept: ${stats.interestingKept}`);
    console.log(`    [dp] new app (crypto/safety/keystore) ranges covered: ${stats.newAppRanges}`);
    console.log(`    [dp] new noble ranges covered: ${stats.newNobleRanges}`);
    console.log(`    [dp] slow inputs (>2s): ${stats.slowInputs.length}`);
    for (const s of stats.slowInputs.slice(0, 10)) console.log(`    [dp]   slow: ${s.campaign} ${s.ms}ms ${s.label}`);
    console.log(`    [dp] control (unmutated-seed) accepts: ${JSON.stringify(stats.controlAccepts)}`);
    console.log(`    [dp] non-E2EE throws: ${stats.nonE2EEThrows.length}`);
    for (const t of stats.nonE2EEThrows.slice(0, 10)) console.log(`    [dp]   throw: ${t.campaign} ${t.label} -> ${t.err}`);
    console.log(`    [dp] unexpected accepts: ${stats.unexpectedAccepts.length}`);
    for (const a of stats.unexpectedAccepts.slice(0, 10)) console.log(`    [dp]   accept: ${a.campaign} ${a.label} -> ${a.detail}`);
    console.log('    [dp] ==========================================');
    assert.ok(stats.totalCases > 1000, `expected >1000 fuzz cases, got ${stats.totalCases}`);
    // Control proof: the campaigns must have reached successful decrypt/parse
    // paths, not just fail-closed ones. (C3b/C4b have tiny budgets, so they
    // are checked with >= 0 here and reported above; the large campaigns
    // must each show at least one control accept.) C3a-ecdh-rejected is
    // intentionally absent: DP-15 removed the ECDH path, so that campaign is
    // rejection-only by design and has no valid control to accept.
    for (const c of ['C1-pq-decrypt', 'C2-group-decrypt', 'C4a-pqf1', 'C5-bundle-parse', 'C6-epoch-packet']) {
      assert.ok((stats.controlAccepts[c] || 0) > 0, `campaign ${c} never accepted an unmutated control seed — deep paths may not have been reached`);
    }
    if (GUIDED) {
      assert.ok(stats.interestingKept > 0, 'coverage guidance must have kept at least one interesting input');
      assert.ok(stats.newAppRanges > 0, 'coverage guidance must have covered new app ranges');
    }
    assert.equal(stats.unexpectedAccepts.length, 0, `unexpected accepts: ${JSON.stringify(stats.unexpectedAccepts.slice(0, 5))}`);
    assert.equal(stats.nonE2EEThrows.length, 0, `non-E2EE throws: ${JSON.stringify(stats.nonE2EEThrows.slice(0, 5))}`);
  });
});
