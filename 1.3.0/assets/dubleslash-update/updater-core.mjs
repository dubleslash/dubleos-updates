// updater-core.mjs — the deterministic spine of the Duble//OS updater.
// Zero-dependency (Node built-ins only). Pure, testable functions that build.mjs uses to
// sign/verify, and that the dubleslash-update skill's runtime procedure mirrors.
import {
  generateKeyPairSync, createPrivateKey, createPublicKey, sign as _sign, verify as _verify,
  createHash,
} from 'node:crypto';

// ---- semantic version helpers ----

const parse = (v) => {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(v).trim());
  if (!m) throw new Error(`not a semver: ${v}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
};

/** compareVersions(a, b) → -1 | 0 | 1 (numeric per-field, not lexical). */
export function compareVersions(a, b) {
  const pa = parse(a), pb = parse(b);
  for (let i = 0; i < 3; i++) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }
  return 0;
}

/** updateKind(base, next) → 'none' | 'patch' | 'minor' | 'major' | 'downgrade'. */
export function updateKind(base, next) {
  const [bMaj, bMin] = parse(base), [nMaj, nMin, nPatch] = parse(next);
  const cmp = compareVersions(next, base);
  if (cmp === 0) return 'none';
  if (cmp < 0) return 'downgrade';
  if (nMaj > bMaj) return 'major';
  if (nMin > bMin) return 'minor';
  return 'patch';
}

// ---- canonical serialization (deterministic bytes for signing) ----

/** canonicalize(value) → a stable JSON string with object keys sorted recursively. */
export function canonicalize(value) {
  const norm = (v) => {
    if (Array.isArray(v)) return v.map(norm);
    if (v && typeof v === 'object') {
      return Object.keys(v).sort().reduce((o, k) => { o[k] = norm(v[k]); return o; }, {});
    }
    return v;
  };
  return JSON.stringify(norm(value));
}

// ---- signing (one domain-separated ed25519 keypair, per the spec) ----

// The signed message is `<domain>:<canonical(payload)>`, so a signature minted for the
// "update" domain can never be replayed as a "license" signature or vice-versa.
const message = (domain, payload) => Buffer.from(`${domain}:${canonicalize(payload)}`, 'utf8');

/** generateKeypair() → { privatePem (PKCS8 PEM), publicB64 (base64 SPKI DER) }. */
export function generateKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicB64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

/** sign(privatePem, domain, payload) → base64 signature. */
export function sign(privatePem, domain, payload) {
  const key = createPrivateKey(privatePem);
  return _sign(null, message(domain, payload), key).toString('base64');
}

/** verify(publicB64, domain, payload, sigB64) → boolean (never throws on bad input). */
export function verify(publicB64, domain, payload, sigB64) {
  try {
    const key = createPublicKey({
      key: Buffer.from(publicB64, 'base64'), format: 'der', type: 'spki',
    });
    return _verify(null, message(domain, payload), key, Buffer.from(sigB64, 'base64'));
  } catch {
    return false;
  }
}

// ---- capability envelope (ground truth = manifest owner: flags) ----

// The only intent types an update may carry. Anything else (e.g. shell, hook edits) is refused.
const ALLOWED_TYPES = new Set([
  'skill-enhance', 'skill-add', 'skill-remove', 'doc-refresh', 'toolkit-note', 'key-rotate',
]);

// A skill this OS copy shipped with is in ownerMap; a skill an update *introduces* cannot be
// (it did not exist when this copy was built). So skill-add is judged by the reserved
// `dubleslash-` namespace — the same partition the updater already owns — and nothing else.
// The pattern is deliberately strict: a bare skill name, no slashes, no dots, no traversal.
const RESERVED_SKILL = /^dubleslash-[a-z0-9]+(-[a-z0-9]+)*$/;

// ---- assets: the only channel that carries file content ----
// Intents are prose an LLM reconciles, which cannot deliver a file that must arrive byte-exact
// (a wireframe shell, a template). An asset does: the intent pins the file's sha256, the bundle
// signature covers that hash, and the reconciler fetches from the pinned feed and verifies the
// bytes before writing. The hash is the trust; everything else here is blast-radius control.
//
// Only skill-shaped intents may carry assets, and an asset may only land inside its own skill's
// folder — never in user memory, never in settings, never outside the OS.
const ASSET_TYPES = new Set(['skill-add', 'skill-enhance']);
const SHA256_HEX = /^[0-9a-f]{64}$/;

// A url is a relative path *under this version's folder on the pinned feed*. No scheme, no host,
// no absolute path, no traversal — the feed origin is baked into the install and a bundle may
// never redirect a fetch somewhere else.
const SAFE_REL_URL = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
const hasTraversal = (s) => s.split('/').includes('..') || s.includes('\\');

function checkAsset(a, targets) {
  if (!a || typeof a !== 'object') return 'asset is not an object';
  const { path, url, sha256 } = a;
  if (typeof path !== 'string' || !path) return 'asset has no path';
  if (typeof url !== 'string' || !url) return `asset ${path} has no url`;
  if (typeof sha256 !== 'string' || !SHA256_HEX.test(sha256)) {
    return `asset ${path} has no valid sha256 (64 lowercase hex chars)`;
  }
  if (!SAFE_REL_URL.test(url) || hasTraversal(url)) {
    return `asset ${path} has a url that is not a relative path under the feed: ${url}`;
  }
  if (hasTraversal(path) || path.startsWith('/')) return `asset path escapes the OS: ${path}`;
  // must sit inside one of this intent's own skill folders
  const ok = targets.some((t) => RESERVED_SKILL.test(t) && path.startsWith(`.claude/skills/${t}/`));
  if (!ok) return `asset path is outside its skill's folder: ${path}`;
  return null;
}

/**
 * verifyAsset(bytes, sha256) → { ok: true } | { ok: false, reason }.
 * The mechanical gate before an asset is written: hash the fetched bytes and compare against the
 * hash the signed bundle pinned. Empty or absent bodies are refused rather than hashed — a failed
 * fetch must never look like a match.
 */
export function verifyAsset(bytes, sha256) {
  if (!bytes || bytes.length === 0) return { ok: false, reason: 'asset body is empty or missing' };
  if (typeof sha256 !== 'string' || !SHA256_HEX.test(sha256)) {
    return { ok: false, reason: 'pinned sha256 is missing or malformed' };
  }
  const actual = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  if (actual !== sha256) {
    return { ok: false, reason: `sha256 mismatch: got ${actual}, expected ${sha256}` };
  }
  return { ok: true };
}

/**
 * checkEnvelope(intent, ownerMap) → { ok: true } | { ok: false, reason }.
 * An intent is in-envelope iff its type is known AND every target is permitted:
 * - `skill-add` — the target must be a well-formed name in the reserved `dubleslash-`
 *   namespace, and must not already be user-seeded in this install. A target absent from
 *   ownerMap is expected here (that is what "new skill" means) and is allowed.
 * - every other type — the target must resolve, via ownerMap, to a system-owned file.
 *   Unknown or user-seeded targets are refused.
 */
export function checkEnvelope(intent, ownerMap) {
  if (!ALLOWED_TYPES.has(intent.type)) return { ok: false, reason: `unknown intent type: ${intent.type}` };
  const targets = intent.targets || [];
  if (targets.length === 0) return { ok: false, reason: `intent ${intent.id} has no targets` };
  for (const t of targets) {
    const owner = ownerMap[t];
    if (intent.type === 'skill-add') {
      if (!RESERVED_SKILL.test(t)) {
        return { ok: false, reason: `skill-add target ${t} is not a name in the reserved dubleslash- namespace` };
      }
      if (owner !== undefined && owner !== 'system') {
        return { ok: false, reason: `target ${t} is ${owner}, not system-owned` };
      }
      continue;
    }
    if (owner === undefined) return { ok: false, reason: `unknown target: ${t}` };
    if (owner !== 'system') return { ok: false, reason: `target ${t} is ${owner}, not system-owned` };
  }
  const assets = intent.assets;
  if (assets !== undefined) {
    if (!Array.isArray(assets)) return { ok: false, reason: `intent ${intent.id}: assets must be a list` };
    if (!ASSET_TYPES.has(intent.type)) {
      return { ok: false, reason: `intent type ${intent.type} may not carry assets` };
    }
    for (const a of assets) {
      const bad = checkAsset(a, targets);
      if (bad) return { ok: false, reason: bad };
    }
  }
  return { ok: true };
}

// ---- idempotency ----

/** filterUnapplied(intents, appliedIds) → intents whose id is not in appliedIds. */
export function filterUnapplied(intents, appliedIds) {
  const done = new Set(appliedIds);
  return intents.filter((i) => !done.has(i.id));
}

// ---- composite verifiers ----

/**
 * verifyBundle(bundle, publicB64, ownerMap) → { ok: true } | { ok: false, reason }.
 * The whole bundle is rejected (never partially applied) if the `update:` signature is invalid
 * or ANY intent falls outside the capability envelope.
 */
export function verifyBundle(bundle, publicB64, ownerMap) {
  const { sig, version, kind, base, intents } = bundle;
  if (!sig) return { ok: false, reason: 'bundle has no signature' };
  if (!verify(publicB64, 'update', { version, kind, base, intents }, sig))
    return { ok: false, reason: 'bundle signature does not verify' };
  for (const intent of intents || []) {
    const env = checkEnvelope(intent, ownerMap);
    if (!env.ok) return { ok: false, reason: `envelope violation: ${env.reason}` };
  }
  return { ok: true };
}

/**
 * verifyLicense(license, publicB64) → { ok, buyer, license, reason }.
 * A license file is `{ token, sig }`; the `license:` signature must cover the token verbatim.
 */
export function verifyLicense(license, publicB64) {
  const { token, sig } = license || {};
  if (!token || !sig) return { ok: false, reason: 'license missing token or signature' };
  if (!verify(publicB64, 'license', token, sig)) return { ok: false, reason: 'license signature does not verify' };
  return { ok: true, buyer: token.buyer, license: token.license };
}

// ---- version ledger (00-09-system/07-version.md frontmatter) ----

/** parseVersionLedger(mdText) → { installed_version, channel, last_checked, applied: [] }. */
export function parseVersionLedger(mdText) {
  const fm = /^---\n([\s\S]*?)\n---/.exec(mdText);
  const body = fm ? fm[1] : mdText;
  const scalar = (k) => (new RegExp(`^${k}:\\s*(.+)$`, 'm').exec(body) || [])[1]?.trim();
  const applied = [];
  const am = /^applied:[ \t]*\n([\s\S]*?)(?=^[^\s-]|$(?![\s\S]))/m.exec(body + '\n');
  if (am) for (const line of am[1].split('\n')) {
    const m = /^\s*-\s*(.+?)\s*$/.exec(line);
    if (m) applied.push(m[1]);
  }
  return {
    installed_version: scalar('installed_version'),
    channel: scalar('channel'),
    last_checked: scalar('last_checked'),
    applied,
  };
}

// ---- CLI (the dubleslash-update skill shells out to these; import users are unaffected) ----
if (import.meta.url === `file://${process.argv[1]}`) {
  const { readFileSync } = await import('node:fs');
  const [verb, ...a] = process.argv.slice(2);
  const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
  // owners.json ships beside this file — the pre-expanded { path|skill-name → owner } map
  const ownerMapFrom = (ownersPath) => readJson(ownersPath);
  const out = (o) => { console.log(JSON.stringify(o, null, 2)); };
  try {
    if (verb === 'verify-bundle') {
      // verify-bundle <bundle.json> <pubKeyFile> <owners.json>
      out(verifyBundle(readJson(a[0]), readFileSync(a[1], 'utf8').trim(), ownerMapFrom(a[2])));
    } else if (verb === 'verify-license') {
      // verify-license <license.json> <pubKeyFile>
      out(verifyLicense(readJson(a[0]), readFileSync(a[1], 'utf8').trim()));
    } else if (verb === 'verify-asset') {
      // verify-asset <downloadedFile> <sha256FromTheSignedBundle>
      out(verifyAsset(readFileSync(a[0]), a[1]));
    } else if (verb === 'plan') {
      // plan <bundle.json> <pubKeyFile> <owners.json> <07-version.md>
      const bundle = readJson(a[0]);
      const pub = readFileSync(a[1], 'utf8').trim();
      const check = verifyBundle(bundle, pub, ownerMapFrom(a[2]));
      const ledger = parseVersionLedger(readFileSync(a[3], 'utf8'));
      const unapplied = filterUnapplied(bundle.intents || [], ledger.applied);
      out({ verify: check, kind: bundle.kind, version: bundle.version,
            installed: ledger.installed_version, unapplied });
    } else {
      console.error('usage: updater-core.mjs <verify-bundle|verify-license|verify-asset|plan> ...');
      process.exit(2);
    }
  } catch (e) { console.error(`ERROR: ${e.message}`); process.exit(1); }
}
