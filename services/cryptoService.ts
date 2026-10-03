/**
 * ARBOR MESSAGE CRYPTO (V5 envelope + V8 hardening).
 *
 * What actually protects a message (this header was corrected in the V8 review —
 * the old text described an ECDSA envelope signature that V5 never implemented):
 *   - Content is sealed ONCE per message with a fresh random Content Encryption Key
 *     (CEK, AES-256-GCM). The sender id, message id, timestamp and TTL are bound as
 *     additional authenticated data (AAD).
 *   - The CEK is delivered to each recipient through that recipient's pairwise
 *     Signal Double Ratchet session (services/signal.ts, vetted libsignal port).
 *     The ratchet authenticates WHO delivered the key slot.
 *   - V8 H-1 — CONTENT BINDING. A CEK alone is shared by every recipient of a
 *     group/broadcast message, so a co-recipient holding it (with a colluding
 *     server) could mint a DIFFERENT ciphertext under the same AAD and have it
 *     accepted as the original sender's. Every ratchet slot therefore now carries
 *     CEK ‖ SHA-256(binding transcript), where the transcript covers the AAD
 *     fields AND the exact iv+ct. Only the real sender can write a slot, so a
 *     recipient that recomputes the digest and compares it knows the ciphertext
 *     is the one the SENDER sealed. Slots without a digest (clients older than
 *     V8) are still readable but are shown as unverified.
 *   - V8 M-9 — the display metadata a client shows (conversation type, circle,
 *     group, ack request, announcer level) travels INSIDE the sealed content
 *     (`meta`), so it is covered by the binding too; the server's plaintext copies
 *     are routing hints only and are never trusted for display.
 *   - The ECDH/ECDSA P-256 node key pairs below are legacy identity material kept
 *     for fingerprints/pinning; they are not used to authenticate messages.
 *
 * Password-derived keys (V8 H-3): the auth value sent to the server and the wrap
 * key that encrypts every server-held private blob are derived with SCRYPT
 * (memory-hard, via the audited @noble/hashes implementation vendored in
 * services/vendor) instead of PBKDF2 alone, so an offline guess costs ~64 MiB of
 * memory rather than being GPU-cheap. Legacy (PBKDF2) accounts are migrated on
 * their next login (see api.ts upgradeKdf).
 *
 * Anti-MITM: confidentiality against a malicious server still depends on TOFU
 * identity pinning plus out-of-band safety-number verification, as in Signal.
 */
import { scryptAsync } from './vendor/noble-hashes/scrypt.js';

export interface PublicBundle { encPub: JsonWebKey; sigPub: JsonWebKey; }
export interface NodeKeyPair { enc: CryptoKeyPair; sig: CryptoKeyPair; }
export interface NodePrivateKeys { encPriv: CryptoKey; sigPriv: CryptoKey; }
/**
 * V5 envelope. Content is sealed once with a random CEK (AES-GCM, with the message
 * metadata bound as additional authenticated data). The CEK is delivered to each
 * recipient through the Signal Double Ratchet (see services/signal.ts) — each
 * `recips` slot is a Signal ciphertext of the CEK, not an ECDH-wrapped key.
 */
export interface Envelope {
  v: 5;
  mid: string;          // unique per-message id (replay defence)
  ts: number;           // sender timestamp (ms)
  exp: number | null;   // sender-intended expiry (ms) or null; bound as AAD
  iv: string;
  ct: string;
  recips: { id: string; kt: number; kb: string }[]; // kt = Signal msg type, kb = b64 body
  sigBy: string;        // sender node public id (bound as AAD + authenticated by the ratchet)
  targetGroup?: string; // inviter descendants group-chat scope (metadata, not secret)
}
/** Display metadata sealed INSIDE the content (V8 M-9) so it is authenticated by
 *  the sender and bound by H-1; the server's plaintext copies are routing hints. */
export interface ContentMeta {
  t: 'PEER' | 'BROADCAST' | 'GLOBAL';      // conversation type
  c?: 'UP' | 'DOWN' | null;                // circle
  g?: string | null;                       // group / link scope
  a?: boolean;                             // acknowledgment requested
  l?: number | null;                       // announcer's level (BROADCAST label)
}
export interface PlainContent {
  meta?: ContentMeta;
  text?: string | null;
  imageUrl?: string | null;   // legacy inline media (still decoded for old messages)
  audioUrl?: string | null;
  videoUrl?: string | null;
  attachments?: import('../types').AttachmentRef[] | null; // Signal-style out-of-band media
}

const te = new TextEncoder();
const td = new TextDecoder();
const enc = (s: string): Uint8Array<ArrayBuffer> => te.encode(s) as unknown as Uint8Array<ArrayBuffer>;

function subtle(): SubtleCrypto {
  if (!(globalThis as any).isSecureContext || !globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('Secure context unavailable: refusing to perform cryptographic operations over an insecure connection. Use HTTPS.');
  }
  return globalThis.crypto.subtle;
}

const b64 = (buf: ArrayBuffer | Uint8Array): string => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  // Chunked conversion: building the binary string in 32 KB blocks turns the old
  // O(n) per-byte concatenation (which froze the UI for seconds on multi-MB media)
  // into a handful of native String.fromCharCode.apply calls.
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return btoa(out);
};
const ub64 = (s: string): Uint8Array<ArrayBuffer> => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const rand = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));

const PBKDF2_ITERS = 650000; // OWASP 2024 guidance for PBKDF2-HMAC-SHA256

// V8 H-3: memory-hard KDF parameters. N=2^16, r=8 → 64 MiB per guess; ~0.25 s on a
// desktop in JS, ~1 s on a mid-range phone. (2^17 / 128 MiB is OWASP's preferred
// floor but risks out-of-memory on older iOS WebKit in pure JS.)
export type KdfVersion = 1 | 2;
export const CURRENT_KDF: KdfVersion = 2;
const SCRYPT = { N: 1 << 16, r: 8, p: 1, dkLen: 64, maxmem: 80 * 1024 * 1024 } as const;

/**
 * Derive (a) an authentication value sent to the server and (b) a wrapping key
 * that NEVER leaves the device. Both come from ONE memory-hard stretch of the
 * password (kdf 2: scrypt over username + the account's random wrap salt), split
 * into two independent 32-byte halves — so the value the server sees at login and
 * the key protecting server-held blobs each cost a full scrypt per offline guess.
 * kdf 1 is the legacy PBKDF2 derivation, kept ONLY to log in and migrate old
 * accounts (api.ts upgradeKdf).
 */
export async function deriveAuthMaterial(
  username: string,
  password: string,
  wrapSalt: string,
  kdf: KdfVersion = CURRENT_KDF,
  withRaw = false,
): Promise<{ authHash: string; wrapKey: CryptoKey; wrapRaw?: Uint8Array }> {
  // withRaw (v70 H5): also hand back the wrap key's raw bytes, ONLY so the
  // biometric unlock can seal them under the authenticator's PRF secret. The
  // caller must zero them right after.
  if (kdf === 2) {
    const out = await scryptAsync(enc(password), enc('arbor-kdf-v2|' + username.toLowerCase() + '|' + wrapSalt), SCRYPT);
    try {
      const authHash = b64(out.slice(0, 32));
      const wrapKey = await subtle().importKey('raw', out.slice(32, 64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
      return { authHash, wrapKey, ...(withRaw ? { wrapRaw: out.slice(32, 64) } : {}) };
    } finally { out.fill(0); }
  }
  const u = username.toLowerCase();
  const base = await subtle().importKey('raw', enc(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  const authBits = await subtle().deriveBits(
    { name: 'PBKDF2', salt: enc('arbor-auth-v4:' + u), iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base, 256);
  const wrapParams = { name: 'PBKDF2', salt: enc('arbor-wrap-v4:' + wrapSalt), iterations: PBKDF2_ITERS, hash: 'SHA-256' };
  if (withRaw) {
    const raw = new Uint8Array(await subtle().deriveBits(wrapParams, base, 256));
    const wrapKey = await subtle().importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { authHash: b64(authBits), wrapKey, wrapRaw: raw };
  }
  const wrapKey = await subtle().deriveKey(wrapParams, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { authHash: b64(authBits), wrapKey };
}

export async function generateNodeKeys(): Promise<NodeKeyPair> {
  const e = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair;
  const s = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
  return { enc: e, sig: s };
}

export async function exportPublicBundle(keys: NodeKeyPair): Promise<PublicBundle> {
  return {
    encPub: await subtle().exportKey('jwk', keys.enc.publicKey),
    sigPub: await subtle().exportKey('jwk', keys.sig.publicKey),
  };
}

export async function wrapPrivateKeys(keys: NodeKeyPair, wrapKey: CryptoKey): Promise<string> {
  const payload = JSON.stringify({
    enc: await subtle().exportKey('jwk', keys.enc.privateKey),
    sig: await subtle().exportKey('jwk', keys.sig.privateKey),
  });
  const iv = rand(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, wrapKey, enc(payload));
  return JSON.stringify({ iv: b64(iv), ct: b64(ct) });
}

/** Re-encrypt an {iv,ct} wrap-key blob (node keys, Signal identity, state backup,
 *  local sealed records all share this format) from whichever of `fromKeys` opens
 *  it to `toKey`. Used by the password-KDF migration (V8 H-3). */
export async function rewrapBlob(blob: string, fromKeys: CryptoKey[], toKey: CryptoKey): Promise<string> {
  const { iv, ct } = JSON.parse(blob);
  let pt: ArrayBuffer | null = null;
  for (const k of fromKeys) {
    try { pt = await subtle().decrypt({ name: 'AES-GCM', iv: ub64(iv) }, k, ub64(ct)); break; } catch { /* try next */ }
  }
  if (!pt) throw new Error('rewrap: blob opens with none of the given keys');
  const niv = rand(12);
  const nct = await subtle().encrypt({ name: 'AES-GCM', iv: niv }, toKey, pt);
  return JSON.stringify({ iv: b64(niv), ct: b64(nct) });
}

export async function unwrapPrivateKeys(blob: string, wrapKey: CryptoKey | CryptoKey[]): Promise<NodePrivateKeys> {
  const { iv, ct } = JSON.parse(blob);
  const candidates = Array.isArray(wrapKey) ? wrapKey : [wrapKey];
  let pt: ArrayBuffer | null = null;
  let lastErr: unknown;
  for (const k of candidates) {
    try { pt = await subtle().decrypt({ name: 'AES-GCM', iv: ub64(iv) }, k, ub64(ct)); break; } catch (e) { lastErr = e; }
  }
  if (!pt) throw lastErr || new Error('unwrap failed');
  const j = JSON.parse(td.decode(pt));
  const encPriv = await subtle().importKey('jwk', j.enc, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const sigPriv = await subtle().importKey('jwk', j.sig, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return { encPriv, sigPriv };
}

function aad(sigBy: string, mid: string, ts: number, exp: number | null): Uint8Array<ArrayBuffer> {
  return enc(['arbor-v5', sigBy, mid, String(ts), String(exp)].join('|'));
}

// Fixed-size plaintext buckets. AES-GCM ciphertext length == plaintext length +
// tag, so padding the plaintext to one of these sizes means the ct length the
// relay stores no longer reveals a message's true size (e.g. "ok" vs a long
// paragraph become indistinguishable). Buckets grow geometrically so large text
// still fits with bounded overhead. (Out-of-band media already rides as separate
// fixed-fetched blobs, so content here is text + small attachment refs.)
const PAD_BUCKETS = [256, 1024, 4096, 16384, 65536];

/** Serialize content padded up to a fixed bucket via a `_pad` field of spaces.
 *  Recipients ignore the unknown field, so this is backward/forward compatible:
 *  old clients parse padded messages fine, new clients parse unpadded ones fine.
 *  Each added space is exactly one JSON byte (no escaping), so the final length
 *  lands on the bucket exactly. */
function padContentJson(content: PlainContent): string {
  const withPad: Record<string, unknown> = { ...content, _pad: '' };
  const base = JSON.stringify(withPad).length; // includes the empty "_pad":""
  const bucket = PAD_BUCKETS.find(b => b >= base) ?? Math.ceil(base / 65536) * 65536;
  withPad._pad = ' '.repeat(Math.max(0, bucket - base));
  return JSON.stringify(withPad);
}

/** Seal content with a fresh random CEK. Returns the raw CEK (to be delivered to
 *  recipients via the ratchet) plus the iv/ct. The message metadata is bound as AAD
 *  so a server cannot alter mid/ts/exp/sender without breaking decryption. The
 *  plaintext is size-padded (see padContentJson) so the ct length leaks no size. */
export async function sealContent(
  content: PlainContent, sigBy: string, mid: string, ts: number, exp: number | null,
): Promise<{ cek: ArrayBuffer; iv: string; ct: string }> {
  const key = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = rand(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: aad(sigBy, mid, ts, exp) }, key, enc(padContentJson(content)));
  const cek = await subtle().exportKey('raw', key);
  return { cek, iv: b64(iv), ct: b64(ct) };
}

// ---- V8 H-1: bind the ciphertext into every ratchet key slot -----------------
// The transcript is length-prefixed (no delimiter ambiguity) and covers the AAD
// fields plus the exact iv and ct bytes. SHA-256 of it is appended to the CEK
// inside each pairwise-ratcheted slot. A co-recipient knows the CEK but cannot
// write a slot as the sender, so it cannot make a DIFFERENT ciphertext verify.
const BIND_TAG = 'arbor-bind-v1';
async function bindingDigest(env: Pick<Envelope, 'sigBy' | 'mid' | 'ts' | 'exp' | 'iv' | 'ct'>): Promise<Uint8Array> {
  const parts: Uint8Array[] = [enc(BIND_TAG), enc(env.sigBy), enc(env.mid), enc(String(env.ts)), enc(String(env.exp)), ub64(env.iv), ub64(env.ct)];
  const total = parts.reduce((n, p) => n + 4 + p.length, 0);
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  let o = 0;
  for (const p of parts) { dv.setUint32(o, p.length); o += 4; buf.set(p, o); o += p.length; }
  return new Uint8Array(await subtle().digest('SHA-256', buf));
}
/** Slot plaintext for a V8 sender: CEK (32 bytes) ‖ SHA-256(binding transcript). */
export async function bindCekToEnvelope(cek: ArrayBuffer, env: Pick<Envelope, 'sigBy' | 'mid' | 'ts' | 'exp' | 'iv' | 'ct'>): Promise<ArrayBuffer> {
  const d = await bindingDigest(env);
  const out = new Uint8Array(64);
  out.set(new Uint8Array(cek), 0); out.set(d, 32);
  return out.buffer;
}
/** Split a decrypted slot. 64 bytes → verify the digest against THIS envelope
 *  (throws on mismatch: the ciphertext is not the one the sender sealed).
 *  32 bytes → a pre-V8 sender: usable, but `bound: false` (shown as unverified). */
export async function unbindCek(slotPlain: ArrayBuffer, env: Pick<Envelope, 'sigBy' | 'mid' | 'ts' | 'exp' | 'iv' | 'ct'>): Promise<{ cek: ArrayBuffer; bound: boolean }> {
  const u = new Uint8Array(slotPlain);
  if (u.length === 32) return { cek: u.slice().buffer, bound: false };
  if (u.length !== 64) throw new Error('bad key slot length');
  const want = await bindingDigest(env);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= want[i] ^ u[32 + i];
  if (diff !== 0) throw new Error('content binding mismatch: ciphertext was not sealed by the sender');
  return { cek: u.slice(0, 32).buffer, bound: true };
}

/** Open content given the CEK recovered from the ratchet. */
export async function openContent(env: Envelope, cekRaw: ArrayBuffer): Promise<PlainContent> {
  const key = await subtle().importKey('raw', cekRaw, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle().decrypt(
    { name: 'AES-GCM', iv: ub64(env.iv), additionalData: aad(env.sigBy, env.mid, env.ts, env.exp) },
    key, ub64(env.ct));
  return JSON.parse(td.decode(pt)) as PlainContent;
}

export function newMessageId(): string { return b64(rand(16)); }

// ---- Seed-phrase recovery ---------------------------------------------------
// A recovery seed is 12 words drawn from a fixed wordlist. From it we derive
// (a) a lookup id the server stores to find the right blob, and (b) an AES key
// that encrypts the account's {username, password}. The server only ever holds
// the ciphertext + lookup id, so it can never learn credentials. Losing the
// seed just means recovery is unavailable — the account still works normally.
const RECOVERY_WORDS = ('abandon ability able about above absorb abstract absurd access accident account accuse achieve acid acoustic acquire across action actor actress actual adapt address adjust admit adult advance advice aerobic affair afford afraid again agent agree ahead aim air airport aisle alarm album alcohol alert alien allow almost alone alpha already also alter always amateur amazing among amount amused anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety apart apology appear apple approve april arch arctic area arena argue armed armor army around arrange arrest arrive arrow artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo').split(' ');

export function generateSeedPhrase(wordCount = 12): string {
  const words: string[] = [];
  const N = RECOVERY_WORDS.length;
  // Rejection sampling: discard raw values in the final short interval so every
  // word is exactly equiprobable (removes the ~2^32 % N modulo bias).
  const limit = Math.floor(0x100000000 / N) * N;
  const buf = new Uint32Array(1);
  while (words.length < wordCount) {
    crypto.getRandomValues(buf);
    if (buf[0] >= limit) continue;
    words.push(RECOVERY_WORDS[buf[0] % N]);
  }
  return words.join(' ');
}

const normalizeSeed = (seed: string) => seed.trim().toLowerCase().split(/\s+/).join(' ');

/**
 * Derive the recovery lookup id + encryption key from the seed phrase.
 * v2 binds the derivation to the (lowercased) username, so the same phrase maps
 * to a DIFFERENT id/key per account — an attacker cannot precompute one
 * phrase→id table and reuse it against every user. v1 (static salt) is retained
 * for READ only, so blobs enrolled before v2 still recover.
 */
async function deriveRecovery(seed: string, username: string, version: 1 | 2 = 2): Promise<{ recoveryId: string; key: CryptoKey }> {
  const norm = normalizeSeed(seed);
  const u = (username || '').trim().toLowerCase();
  const base = await subtle().importKey('raw', enc(norm), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
  const idSalt  = version === 2 ? 'arbor-recovery-id-v2:'  + u : 'arbor-recovery-id-v1';
  const keySalt = version === 2 ? 'arbor-recovery-key-v2:' + u : 'arbor-recovery-key-v1';
  const idBits = await subtle().deriveBits(
    { name: 'PBKDF2', salt: enc(idSalt), iterations: PBKDF2_ITERS, hash: 'SHA-256' }, base, 256);
  const key = await subtle().deriveKey(
    { name: 'PBKDF2', salt: enc(keySalt), iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { recoveryId: b64(idBits), key };
}

/** Encrypt {username,password} under a seed phrase. Returns the server payload. */
/** v72: recovery plaintext is padded to this many bytes, so every stored blob is the
 *  same size as the server's decoy for an unknown phrase (server.js, recovery/fetch).
 *  v71 blobs varied with the username/password length, which told real from decoy. */
export const RECOVERY_PT_BYTES = 512;
export async function buildRecoveryBlob(seed: string, username: string, password: string): Promise<{ recoveryId: string; blob: string }> {
  const { recoveryId, key } = await deriveRecovery(seed, username, 2);
  const iv = rand(12);
  const base = enc(JSON.stringify({ username, password })).length;
  const pt = base + 7 <= RECOVERY_PT_BYTES                  // 7 = the added `,"p":""`
    ? enc(JSON.stringify({ username, password, p: '_'.repeat(RECOVERY_PT_BYTES - base - 7) }))
    : enc(JSON.stringify({ username, password }));
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, pt);
  return { recoveryId, blob: JSON.stringify({ v: 2, iv: b64(iv), ct: b64(ct) }) };
}

/** Compute the recoveryId (to fetch the blob) for a given derivation version. */
export async function recoveryIdFor(seed: string, username: string, version: 1 | 2 = 2): Promise<string> {
  return (await deriveRecovery(seed, username, version)).recoveryId;
}
export async function openRecoveryBlob(seed: string, username: string, blob: string): Promise<{ username: string; password: string }> {
  const parsed = JSON.parse(blob);
  if (!parsed || (parsed.v !== 1 && parsed.v !== 2) || !parsed.iv || !parsed.ct) throw new Error('Malformed recovery data.');
  // The blob carries its own version, so we decrypt with the matching salt scheme.
  const { key } = await deriveRecovery(seed, username, parsed.v);
  const pt = await subtle().decrypt({ name: 'AES-GCM', iv: ub64(parsed.iv) }, key, ub64(parsed.ct));
  const { username: u, password } = JSON.parse(td.decode(pt));   // (v72 blobs also carry padding `p`)
  return { username: u, password };
}


/** Allow-list validation for decrypted media data URLs.
 *  Parser-based (not one brittle regex): mobile browsers emit MIME strings with
 *  parameters, aliases and odd casing. We parse the header, canonicalise the
 *  type, and check it against a strict allowlist. SVG, HTML, and any non-media
 *  type remain rejected (script-bearing formats are the XSS surface here). */
/** Cheap header-only check: validates the MIME + that a payload exists, WITHOUT
 *  scanning the (possibly multi-MB) base64 body. Safe to call on every render. */
export function isSafeMediaHeader(s: string | null | undefined, kind: 'image' | 'audio' | 'video'): boolean {
  if (!s || typeof s !== 'string' || !s.startsWith('data:')) return false;
  const comma = s.indexOf(',');
  if (comma < 0) return false;
  const header = s.slice(5, comma);
  const parts = header.split(';');
  if (parts[parts.length - 1].trim().toLowerCase() !== 'base64') return false;
  const [top, subRaw] = (parts[0] || '').trim().toLowerCase().split('/');
  if (top !== kind || !subRaw) return false;
  const sub = subRaw === 'jpg' ? 'jpeg' : subRaw === 'mp3' ? 'mpeg' : subRaw;
  const allow: Record<string, string[]> = {
    image: ['png', 'jpeg', 'gif', 'webp'],
    audio: ['webm', 'ogg', 'mpeg', 'mp4', 'wav', 'x-m4a', 'aac', 'x-wav', '3gpp'],
    video: ['mp4', 'webm', 'ogg', 'quicktime', '3gpp'],
  };
  return allow[kind].includes(sub) && comma + 1 < s.length;
}

/** FULL check: header + a character scan of the whole base64 body. Use on INGEST
 *  only (never per-render). Scans by charCode so a multi-MB payload never builds a
 *  giant regex match. */
export function isSafeMediaDataUrl(s: string | null | undefined, kind: 'image' | 'audio' | 'video'): boolean {
  if (!isSafeMediaHeader(s, kind)) return false;
  const payload = s!.slice(s!.indexOf(',') + 1);
  let seenPad = false;
  for (let i = 0; i < payload.length; i++) {
    const c = payload.charCodeAt(i);
    if (c === 61) { seenPad = true; continue; }                 // '='
    if (c === 9 || c === 10 || c === 13 || c === 32) continue;   // whitespace (wrapped base64)
    if (seenPad) return false;                                   // data after padding
    const ok = (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47;
    if (!ok) return false;
  }
  return payload.trimEnd().length > 0;
}

// ---------------------------------------------------------------------------
// Identity fingerprints / safety numbers (anti-MITM verification, Signal-style)
// ---------------------------------------------------------------------------

/** Stable per-identity fingerprint over both public keys (order-independent JWK). */
export async function identityFingerprint(bundle: PublicBundle): Promise<string> {
  const canon = (j: JsonWebKey) => `${j.kty}:${(j as any).crv || ''}:${(j as any).x || ''}:${(j as any).y || ''}`;
  const data = enc('arbor-id-v4|' + canon(bundle.encPub) + '|' + canon(bundle.sigPub));
  const digest = new Uint8Array(await subtle().digest('SHA-256', data));
  let hex = '';
  for (let i = 0; i < digest.length; i++) hex += digest[i].toString(16).padStart(2, '0');
  return hex;
}

/** A 60-digit pairwise safety number two parties can compare out-of-band. */
export async function safetyNumber(a: PublicBundle, b: PublicBundle): Promise<string> {
  const fa = await identityFingerprint(a);
  const fb = await identityFingerprint(b);
  const [x, y] = [fa, fb].sort();
  const data = enc('arbor-sn-v4|' + x + '|' + y);
  const digest = new Uint8Array(await subtle().digest('SHA-256', data));
  // 30 digits from each half -> render as 12 groups of 5.
  let out = '';
  for (let i = 0; i < 30; i++) out += (digest[i] % 10).toString();
  return out.match(/.{1,5}/g)!.join(' ');
}

// ---------------------------------------------------------------------------
// Signup proof-of-work (anti-spam). The server issues a MAC'd challenge token;
// we find a nonce whose SHA-256(token '.' nonce) has >= `difficulty` leading zero
// bits. No PII, no third party — just a bounded, tunable CPU cost per account.
// Batched so the async WebCrypto digests run concurrently instead of one-at-a-time.
// ---------------------------------------------------------------------------
function leadingZeroBitsBuf(buf: Uint8Array): number {
  let bits = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0) { bits += 8; continue; }
    let x = b, c = 0;
    while ((x & 0x80) === 0) { c++; x <<= 1; }
    return bits + c;
  }
  return bits;
}

/** Solve the signup PoW. Returns the winning nonce (as a string). `onProgress`
 *  (optional) is called with the number of hashes tried, for a UI spinner. */
export async function solvePow(token: string, difficulty: number, onProgress?: (tried: number) => void): Promise<string> {
  if (!difficulty || difficulty <= 0) return '0';
  const s = subtle();
  const BATCH = 256;
  let n = 0;
  for (;;) {
    const jobs: Promise<{ nonce: number; bits: number }>[] = [];
    for (let i = 0; i < BATCH; i++, n++) {
      const nonce = n;
      jobs.push(s.digest('SHA-256', enc(token + '.' + nonce))
        .then(d => ({ nonce, bits: leadingZeroBitsBuf(new Uint8Array(d)) })));
    }
    const results = await Promise.all(jobs);
    let best = -1;
    for (const r of results) if (r.bits >= difficulty && (best < 0 || r.nonce < best)) best = r.nonce;
    if (best >= 0) return String(best);
    onProgress?.(n);
  }
}

// ---------------------------------------------------------------------------
// Passphrase strength (client-side; the server never sees the password by design,
// so it cannot enforce this — which is exactly why the floor must be high here).
//
// V8 H-3: the old floor (8 chars, tiny common-list) accepted "Sunshine2024!", which
// the review cracked offline in under a second. The passphrase is the ONLY thing
// protecting the identity key + backups against a server/DB thief, so the policy
// now targets guess resistance, not character classes:
//   - at least 12 characters;
//   - rejects the classic "Word + digits/year + symbol" shape (the pattern every
//     cracking rule-set tries first) unless the passphrase is long (16+);
//   - rejects common passwords/words (after stripping those decorations),
//     keyboard walks, sequences and heavy repetition;
//   - requires a rough entropy estimate of at least 50 bits.
// Several random words ("maple orbit velvet crane") pass easily and are the
// recommended form — the UI says so.
// ---------------------------------------------------------------------------
const COMMON = new Set([
  'password', 'passwort', 'passw0rd', 'qwerty', 'qwertz', 'azerty', 'abc123', 'letmein', 'iloveyou', 'admin', 'welcome',
  'monkey', 'dragon', 'football', 'baseball', 'soccer', 'hockey', 'basketball', 'changeme', 'secret', 'arbor',
  'sunshine', 'princess', 'shadow', 'master', 'superman', 'batman', 'trustno1', 'freedom', 'whatever', 'computer',
  'starwars', 'pokemon', 'michael', 'jennifer', 'jordan', 'charlie', 'thomas', 'daniel', 'jessica', 'ashley',
  'summer', 'winter', 'spring', 'autumn', 'flower', 'butterfly', 'chocolate', 'cookie', 'cheese', 'pepper',
  'mustang', 'ferrari', 'harley', 'yankees', 'liverpool', 'chelsea', 'arsenal', 'hello', 'hellokitty', 'love',
  'lovely', 'loveyou', 'angel', 'angels', 'forever', 'family', 'friends', 'heaven', 'blessed', 'jesus', 'god',
  'money', 'killer', 'hunter', 'ranger', 'tigger', 'ginger', 'buster', 'maggie', 'bailey', 'mickey', 'minecraft',
  'fortnite', 'google', 'facebook', 'instagram', 'samsung', 'iphone', 'apple', 'banana', 'orange', 'purple',
  'matrix', 'access', 'login', 'default', 'guest', 'test', 'testing', 'internet', 'security', 'private', 'signal',
]);
const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '01234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qwertzuiop', 'azertyuiop'];
function hasLongSequence(v: string, run = 5): boolean {
  const s = v.toLowerCase();
  for (const seq of SEQUENCES) {
    for (const src of [seq, [...seq].reverse().join('')]) {
      for (let i = 0; i + run <= src.length; i++) if (s.includes(src.slice(i, i + run))) return true;
    }
  }
  return false;
}
function entropyBits(v: string): number {
  let pool = 0;
  if (/[a-z]/.test(v)) pool += 26;
  if (/[A-Z]/.test(v)) pool += 26;
  if (/[0-9]/.test(v)) pool += 10;
  if (/[^A-Za-z0-9]/.test(v)) pool += 33;
  // Discount repeated characters: count distinct chars fully, repeats at a third.
  const uniq = new Set(v).size;
  const effLen = uniq + (v.length - uniq) / 3;
  return effLen * Math.log2(Math.max(pool, 2));
}

export function assessPassphrase(pw: string): { ok: boolean; score: number; reason?: string } {
  const v = pw || '';
  const words = v.trim().split(/[\s\-_.]+/).filter(w => w.length >= 3);
  if (v.length < 12) return { ok: false, score: 0, reason: 'Use at least 12 characters — several random words (e.g. "maple orbit velvet crane") work best.' };
  const core = v.toLowerCase().replace(/[^a-z]/g, '');
  if (COMMON.has(v.toLowerCase()) || COMMON.has(core)) return { ok: false, score: 0, reason: 'That passphrase is too common.' };
  // "Word" + year/digits + symbol(s): the first shape every cracking rule-set tries.
  if (v.length < 16 && /^[A-Za-z]+[0-9]{0,6}[^A-Za-z0-9]{0,3}[0-9]{0,4}$/.test(v) && words.length <= 1) {
    return { ok: false, score: 1, reason: 'A single word with numbers or symbols added is easy to crack. Use several random words instead.' };
  }
  if (hasLongSequence(v)) return { ok: false, score: 1, reason: 'Avoid keyboard patterns and sequences (like "qwerty" or "12345").' };
  if (new Set(v).size < 6) return { ok: false, score: 1, reason: 'Too repetitive — use a more varied passphrase.' };
  const bits = entropyBits(v);
  if (bits < 50) return { ok: false, score: 1, reason: 'Too easy to guess — add another random word or two.' };
  let score = 2;
  if (v.length >= 16 || words.length >= 3) score++;
  if (bits >= 80 || words.length >= 4) score++;
  return { ok: true, score: Math.min(score, 4) };
}
