/**
 * Media handling: normalization + metadata scrubbing.
 *
 * NORMALIZATION — every capture/attachment is converted to a data URL that we
 * construct OURSELVES from raw bytes, with a lowercased, parameter-free MIME type
 * from a known allowlist. Mobile browsers report wildly inconsistent MIME strings
 * (`audio/mp4;codecs=mp4a.40.2`, empty types, uppercase, vendor aliases); trusting
 * `FileReader.readAsDataURL` output verbatim is what made phone voice notes get
 * rejected by the receive-side validator. Building the URL ourselves guarantees a
 * canonical form on every platform.
 *
 * SCRUBBING — honest capability statement:
 *  - Images: re-encoded through a canvas. This drops ALL container metadata
 *    (EXIF, GPS, timestamps, camera serials, ICC, XMP) because only pixels survive.
 *  - MP4/QuickTime/3GP video (security review V8 H-7 / M-4 / M-5): the box tree
 *    is rebuilt at EVERY level. Removed: `udta`/`meta` (GPS ©xyz, Apple
 *    ISO6709 location, make/model), `uuid` (XMP), `free`/`skip`/`wide` slack,
 *    whole timed-metadata tracks (GoPro/DJI telemetry, iPhone `mebx`, timecode,
 *    text/subtitle telemetry) — including zeroing those tracks' sample bytes
 *    inside `mdat` — plus `mfra`. Capture times in `mvhd`/`tkhd`/`mdhd` are zeroed
 *    and `hdlr` names blanked. Chunk offsets (`stco`/`co64`) are rewritten so the
 *    result plays, 64-bit box sizes are supported, and the OUTPUT is re-audited:
 *    it is only reported scrubbed if that audit finds nothing left.
 *  - Anything else (WebM, MKV, AVI, unknown structure) cannot be scrubbed without
 *    a re-encode and is reported as NOT scrubbed — callers must refuse to send it
 *    while scrubbing is on (fail closed), never pass it through silently.
 *  - Encoder fingerprints (V8 phase 2): the sample entries' compressor name and
 *    QuickTime vendor, and H.264/H.265 SEI "user data unregistered" messages
 *    (x264/x265 & co. write their version + full settings there — in the video
 *    samples, and for HEVC also in hvcC) are blanked IN PLACE at equal length:
 *    no re-encode, no offset changes. The audit fails the scrub if any remain.
 *  - Voice notes recorded in-app are generated fresh by MediaRecorder and contain
 *    no location/EXIF metadata to begin with.
 */

// ---- byte helpers (chunked; safe for multi-MB) ----
export const bytesToB64 = (buf: ArrayBuffer | Uint8Array): string => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = ''; const C = 0x8000;
  for (let i = 0; i < bytes.length; i += C) out += String.fromCharCode.apply(null, bytes.subarray(i, i + C) as unknown as number[]);
  return btoa(out);
};
export const b64ToBytes = (s: string): Uint8Array => {
  const bin = atob(s); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
};

const AUDIO_DEFAULT = 'audio/mp4';
const CANON: Record<'image' | 'audio' | 'video', { allow: string[]; fallback: string }> = {
  image: { allow: ['png', 'jpeg', 'gif', 'webp'], fallback: 'image/jpeg' },
  audio: { allow: ['mp4', 'webm', 'ogg', 'mpeg', 'wav', 'aac', '3gpp', 'x-m4a', 'x-wav'], fallback: AUDIO_DEFAULT },
  video: { allow: ['mp4', 'webm', 'ogg', 'quicktime', '3gpp'], fallback: 'video/mp4' },
};

/** Lowercase, strip parameters, map aliases, and force into the allowlist. */
export function sanitizeMime(raw: string | undefined | null, kind: 'image' | 'audio' | 'video'): string {
  const base = (raw || '').split(';')[0].trim().toLowerCase();
  const [top, sub] = base.split('/');
  const table = CANON[kind];
  if (top === kind && sub) {
    let mapped = sub === 'jpg' ? 'jpeg' : sub === 'x-m4a' ? 'mp4' : sub === 'mp3' ? 'mpeg' : sub;
    // QuickTime (.mov) and 3GPP are the same ISO-BMFF container family as MP4, but
    // desktop browsers refuse the label itself — relabel so iPhone videos play on PCs.
    if (kind === 'video' && (mapped === 'quicktime' || mapped === '3gpp')) mapped = 'mp4';
    if (table.allow.includes(mapped)) return `${kind}/${mapped}`;
  }
  return table.fallback;
}

/** Canonical data URL from a Blob: our own base64 + a sanitized MIME. */
export async function blobToCleanDataUrl(blob: Blob, kind: 'image' | 'audio' | 'video'): Promise<string> {
  const buf = await blob.arrayBuffer();
  return `data:${sanitizeMime(blob.type, kind)};base64,${bytesToB64(buf)}`;
}

export interface ScrubResult { url: string; scrubbed: boolean; note?: string }

const MAX_EDGE = 2560;

/**
 * Prepare an image FILE for sending: decode it off the main thread with
 * createImageBitmap (never building a giant base64 intermediate), downscale the
 * longest edge to CHAT_MAX_EDGE, and re-encode as a modest JPEG. This is the
 * single most important perf fix — a 12MP / 4-8MB phone photo becomes a
 * ~150-400KB payload BEFORE it ever enters React state, so it can't lag the
 * chat, and metadata is stripped as a side effect of the re-encode. Returns a
 * compact `data:image/jpeg` URL. Throws only if the file can't be decoded at all.
 */
const CHAT_MAX_EDGE = 1600;   // plenty for any phone/desktop chat bubble
export async function prepareImageForSend(file: Blob): Promise<string> {
  // Prefer createImageBitmap (decodes on a background thread in modern browsers).
  let bitmap: ImageBitmap | null = null;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    bitmap = null;
  }

  const draw = (w: number, h: number, drawTo: (ctx: CanvasRenderingContext2D) => void): string => {
    const canvas = document.createElement('canvas');
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('canvas unavailable');
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    drawTo(ctx);
    // JPEG q0.82 is visually indistinguishable in a chat bubble and tiny.
    return canvas.toDataURL('image/jpeg', 0.82);
  };

  if (bitmap) {
    const scale = Math.min(1, CHAT_MAX_EDGE / Math.max(bitmap.width, bitmap.height));
    const w = Math.max(1, Math.round(bitmap.width * scale));
    const h = Math.max(1, Math.round(bitmap.height * scale));
    const out = draw(w, h, (ctx) => ctx.drawImage(bitmap!, 0, 0, w, h));
    bitmap.close();
    return out;
  }

  // Fallback path: decode via an <img> from an object URL (still off the base64
  // path; the object URL points at the original bytes, not a copy in a string).
  const objUrl = URL.createObjectURL(file);
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const im = new Image();
      im.onload = () => resolve(im);
      im.onerror = () => reject(new Error('decode failed'));
      im.src = objUrl;
    });
    const scale = Math.min(1, CHAT_MAX_EDGE / Math.max(img.naturalWidth, img.naturalHeight));
    const w = Math.max(1, Math.round(img.naturalWidth * scale));
    const h = Math.max(1, Math.round(img.naturalHeight * scale));
    return draw(w, h, (ctx) => ctx.drawImage(img, 0, 0, w, h));
  } finally {
    URL.revokeObjectURL(objUrl);
  }
}

/**
 * Prepare a metadata-free AVATAR: decode the file and RE-ENCODE it through a
 * canvas, centre-cropped to a 256px square. Only pixels survive, so EXIF/GPS/device
 * metadata is stripped 100% of the time (the original bytes never leave the device),
 * and the result is a small JPEG well under the profile-photo size cap. Shared by
 * the per-network profile editor, the account default-profile editor and signup.
 */
export async function prepareAvatar(file: Blob): Promise<string> {
  const S = 256;
  const render = (w: number, h: number, paint: (ctx: CanvasRenderingContext2D, sx: number, sy: number, side: number) => void): string => {
    const side = Math.min(w, h);
    const canvas = document.createElement('canvas');
    canvas.width = S; canvas.height = S;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('canvas unavailable');
    ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = 'high';
    paint(ctx, (w - side) / 2, (h - side) / 2, side);
    return canvas.toDataURL('image/jpeg', 0.85);
  };
  try {
    const bmp = await createImageBitmap(file);
    const out = render(bmp.width, bmp.height, (ctx, sx, sy, side) => ctx.drawImage(bmp, sx, sy, side, side, 0, 0, S, S));
    bmp.close();
    return out;
  } catch {
    const objUrl = URL.createObjectURL(file);
    try {
      const img = await new Promise<HTMLImageElement>((resolve, reject) => { const im = new Image(); im.onload = () => resolve(im); im.onerror = () => reject(new Error('decode failed')); im.src = objUrl; });
      return render(img.naturalWidth, img.naturalHeight, (ctx, sx, sy, side) => ctx.drawImage(img, sx, sy, side, side, 0, 0, S, S));
    } finally { URL.revokeObjectURL(objUrl); }
  }
}

/** Re-encode an image via canvas: only pixels survive, so all metadata is gone.
 *  PNG stays PNG (keeps transparency); everything else becomes JPEG q=0.9.
 *  Also caps the longest edge at 2560px — a 12MP phone photo is ~4x the pixels
 *  any chat bubble will ever show, and shrinking it is what turns a 7MB payload
 *  into a few hundred KB (fixing send/receive lag) without visible quality loss. */
export function scrubImage(dataUrl: string): Promise<ScrubResult> {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => {
      try {
        const scale = Math.min(1, MAX_EDGE / Math.max(img.naturalWidth, img.naturalHeight));
        const canvas = document.createElement('canvas');
        canvas.width = Math.max(1, Math.round(img.naturalWidth * scale));
        canvas.height = Math.max(1, Math.round(img.naturalHeight * scale));
        const ctx = canvas.getContext('2d');
        if (!ctx) return resolve({ url: dataUrl, scrubbed: false, note: 'canvas unavailable' });
        ctx.imageSmoothingQuality = 'high';
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const isPng = dataUrl.startsWith('data:image/png');
        const out = isPng ? canvas.toDataURL('image/png') : canvas.toDataURL('image/jpeg', 0.9);
        // A downscaled re-encode should be smaller; if it somehow isn't, keep it
        // anyway when scaling happened (metadata removal is the contract).
        resolve({ url: out, scrubbed: true, note: scale < 1 ? 'resized' : undefined });
      } catch {
        resolve({ url: dataUrl, scrubbed: false, note: 'decode failed' });
      }
    };
    img.onerror = () => resolve({ url: dataUrl, scrubbed: false, note: 'decode failed' });
    img.src = dataUrl;
  });
}

// ---- ISO-BMFF (MP4 / QuickTime / 3GP) metadata scrubbing -------------------
// V8 H-7 / M-4 / M-5. See the header comment for the full capability statement.
const FOURCC = (b: Uint8Array, off: number) => String.fromCharCode(b[off], b[off + 1], b[off + 2], b[off + 3]);
const readU32 = (b: Uint8Array, off: number) => ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
const writeU32 = (b: Uint8Array, off: number, v: number) => { b[off] = (v >>> 24) & 255; b[off + 1] = (v >>> 16) & 255; b[off + 2] = (v >>> 8) & 255; b[off + 3] = v & 255; };
const readU64 = (b: Uint8Array, off: number) => readU32(b, off) * 0x100000000 + readU32(b, off + 4);
const writeU64 = (b: Uint8Array, off: number, v: number) => { writeU32(b, off, Math.floor(v / 0x100000000)); writeU32(b, off + 4, v >>> 0); };

interface Box { type: string; start: number; size: number; headerLen: number }

/** Enumerate boxes in [start,end). Supports 32-bit, 64-bit (size==1) and
 *  to-end (size==0) sizes. Returns null on any structure we can't trust. */
function listBoxes(b: Uint8Array, start: number, end: number): Box[] | null {
  const out: Box[] = [];
  let off = start;
  while (off + 8 <= end) {
    let size = readU32(b, off);
    const type = FOURCC(b, off + 4);
    let headerLen = 8;
    if (!/^[\x20-\x7e\xa9]{4}$/.test(type)) return null;            // not a box type
    if (size === 1) { if (off + 16 > end) return null; size = readU64(b, off + 8); headerLen = 16; }
    else if (size === 0) size = end - off;
    if (size < headerLen || off + size > end) return null;
    out.push({ type, start: off, size, headerLen });
    off += size;
  }
  if (off !== end) {                                                   // trailing bytes: tolerate only zero padding
    for (let i = off; i < end; i++) if (b[i] !== 0) return null;
  }
  return out;
}

const DROP_EVERYWHERE = new Set(['udta', 'meta', 'uuid', 'free', 'skip', 'wide', 'pnot', 'PICT', 'XMP_', 'mfra', 'Xtra', 'tref']);
const CONTAINERS = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl', 'edts', 'dinf', 'mvex']);
// Handler types of tracks that are metadata rather than picture/sound: timed
// metadata (GoPro GPMF / DJI / iPhone mebx), timecode (capture clock), text and
// subtitle tracks (DJI & dashcams write GPS telemetry as subtitles), hint, camera motion.
const METADATA_HANDLERS = new Set(['meta', 'mdta', 'text', 'sbtl', 'subt', 'tmcd', 'hint', 'camm', 'gpmd', 'data']);
const TIME_BOXES = new Set(['mvhd', 'tkhd', 'mdhd']);

const child = (b: Uint8Array, box: Box, type: string): Box | null => {
  const kids = listBoxes(b, box.start + box.headerLen, box.start + box.size);
  return kids ? kids.find(k => k.type === type) || null : null;
};
const findPath = (b: Uint8Array, box: Box, path: string[]): Box | null => {
  let cur: Box | null = box;
  for (const t of path) { cur = cur && child(b, cur, t); if (!cur) return null; }
  return cur;
};
const handlerOf = (b: Uint8Array, trak: Box): string | null => {
  const h = findPath(b, trak, ['mdia', 'hdlr']);
  if (!h || h.size < h.headerLen + 12) return null;
  return FOURCC(b, h.start + h.headerLen + 8);
};

/** Byte ranges (absolute, in the INPUT) of every sample of a track. */
function trackSampleRanges(b: Uint8Array, trak: Box): [number, number][] | null {
  const stbl = findPath(b, trak, ['mdia', 'minf', 'stbl']);
  if (!stbl) return [];
  const kids = listBoxes(b, stbl.start + stbl.headerLen, stbl.start + stbl.size);
  if (!kids) return null;
  const stco = kids.find(k => k.type === 'stco'), co64 = kids.find(k => k.type === 'co64');
  const stsz = kids.find(k => k.type === 'stsz'), stsc = kids.find(k => k.type === 'stsc');
  if (kids.some(k => k.type === 'stz2')) return null;                    // compact sizes: not handled → fail closed
  if (!stsz || !stsc || (!stco && !co64)) return [];
  const p = (x: Box) => x.start + x.headerLen + 4;                       // after version/flags
  const chunkOffsets: number[] = [];
  if (stco) { const n = readU32(b, p(stco)); for (let i = 0; i < n; i++) chunkOffsets.push(readU32(b, p(stco) + 4 + 4 * i)); }
  else { const n = readU32(b, p(co64!)); for (let i = 0; i < n; i++) chunkOffsets.push(readU64(b, p(co64!) + 4 + 8 * i)); }
  const fixed = readU32(b, p(stsz)), count = readU32(b, p(stsz) + 4);
  const sizeOf = (i: number) => (fixed ? fixed : readU32(b, p(stsz) + 8 + 4 * i));
  const nsc = readU32(b, p(stsc));
  const sc: { first: number; per: number }[] = [];
  for (let i = 0; i < nsc; i++) sc.push({ first: readU32(b, p(stsc) + 4 + 12 * i), per: readU32(b, p(stsc) + 8 + 12 * i) });
  const ranges: [number, number][] = [];
  let sample = 0;
  for (let c = 0; c < chunkOffsets.length && sample < count; c++) {
    let per = 0;
    for (const e of sc) if (e.first <= c + 1) per = e.per;
    let off = chunkOffsets[c];
    for (let k = 0; k < per && sample < count; k++, sample++) { const s = sizeOf(sample); ranges.push([off, off + s]); off += s; }
  }
  return ranges;
}

// ---- Encoder fingerprints (V8 phase 2) ----------------------------------------
// Encoders stamp their name/version/settings into the file: the sample entry's
// `compressorname` (+ QuickTime `vendor`), and H.264/H.265 SEI "user data
// unregistered" messages — in the video samples and in HEVC's hvcC arrays (where
// x265 writes its full command line). All of it is blanked IN PLACE with byte-
// for-byte equal lengths, so no offset or sample size changes and nothing is
// re-encoded. Other SEI (HDR metadata, recovery points, timing) is left alone.
const AVC_ENTRIES = new Set(['avc1', 'avc3']);
const HEVC_ENTRIES = new Set(['hvc1', 'hev1']);
interface VideoCodec { hevc: boolean; lenSize: number }
const VISUAL_ENTRY_HEADER = 86;                                           // size..pre_defined of a VisualSampleEntry

/** RBSP of an escaped NAL payload (drops emulation-prevention 0x03 bytes). */
function unescapeRbsp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length); let n = 0, zeros = 0;
  for (let i = 0; i < b.length; i++) {
    if (zeros >= 2 && b[i] === 3) { zeros = 0; continue; }
    out[n++] = b[i]; zeros = b[i] === 0 ? zeros + 1 : 0;
  }
  return out.subarray(0, n);
}
/** SEI messages of one SEI NAL: 'user' if it carries user_data_unregistered with
 *  any content, 'blank' if only already-blanked user data, 'none', or 'bad'. */
function seiUserData(nal: Uint8Array, hdrLen: number): 'user' | 'blank' | 'none' | 'bad' {
  const r = unescapeRbsp(nal.subarray(hdrLen));
  let i = 0, found: 'blank' | 'none' = 'none';
  while (i < r.length) {
    if (r[i] === 0x80 && r.subarray(i + 1).every(x => x === 0)) return found;   // rbsp trailing bits
    let type = 0, size = 0;
    while (r[i] === 0xff) { type += 255; i++; } if (i >= r.length) return 'bad'; type += r[i++];
    while (r[i] === 0xff) { size += 255; i++; } if (i >= r.length) return 'bad'; size += r[i++];
    if (i + size > r.length) return 'bad';
    if (type === 5) { if (r.subarray(i, i + size).some(x => x !== 0xff)) return 'user'; found = 'blank'; }
    i += size;
  }
  return found;
}
/** Overwrite an SEI NAL (in place, same length) with blank user-data message(s):
 *  payload bytes are 0xFF, so no emulation-prevention byte is ever needed. */
function blankSei(nal: Uint8Array, hdrLen: number): boolean {
  const msg = (P: number) => 1 + Math.floor(P / 255) + 1 + P;              // type + size bytes + payload
  const write = (at: number, P: number) => {
    nal[at++] = 5;
    let s = P; while (s >= 255) { nal[at++] = 0xff; s -= 255; } nal[at++] = s;
    nal.fill(0xff, at, at + P); return at + P;
  };
  const room = nal.length - hdrLen - 1;                                     // minus the 0x80 stop byte
  // One message fits every length but one in 256; the second message covers those.
  for (const P2 of [0, 16, 17, 18]) {
    const rest = room - (P2 ? msg(P2) : 0);
    for (let P = rest - 2; P >= 16 && P >= rest - 3 - Math.ceil(rest / 255); P--) {
      if (msg(P) !== rest) continue;
      let at = write(hdrLen, P);
      if (P2) at = write(at, P2);
      nal[at] = 0x80;
      return true;
    }
  }
  return false;
}
const nalHdr = (hevc: boolean) => (hevc ? 2 : 1);
const isSeiNal = (nal: Uint8Array, hevc: boolean) => nal.length > 0 && (hevc ? [39, 40].includes((nal[0] >> 1) & 0x3f) : (nal[0] & 0x1f) === 6);

/** Walk the length-prefixed NAL units of one sample; blank (or, with fix=false,
 *  just count) SEI user data. Returns false if the sample isn't well formed. */
function scrubSampleSei(b: Uint8Array, start: number, end: number, c: VideoCodec, fix: boolean, found: { n: number }): boolean {
  let p = start;
  while (p < end) {
    if (p + c.lenSize > end) return false;
    let n = 0; for (let i = 0; i < c.lenSize; i++) n = n * 256 + b[p + i];
    p += c.lenSize;
    if (n === 0 || p + n > end) return false;
    const nal = b.subarray(p, p + n);
    if (isSeiNal(nal, c.hevc)) {
      const u = seiUserData(nal, nalHdr(c.hevc));
      if (u === 'user' || u === 'bad') { if (!fix || !blankSei(nal, nalHdr(c.hevc))) found.n++; }
    }
    p += n;
  }
  return true;
}
/** Sample entries of a video track's stsd (a standalone copy of the box):
 *  blank vendor + compressorname, and SEI user data inside hvcC arrays. Returns
 *  the codec of the first H.264/H.265 entry so in-band SEI can be handled too.
 *  `found` counts fingerprints left (with fix=false, everything present). */
function scrubVideoStsd(stsd: Uint8Array, headerLen: number, fix: boolean, found: { n: number }): VideoCodec | null {
  const kids = listBoxes(stsd, headerLen + 8, stsd.length);
  if (!kids) { found.n++; return null; }
  let codec: VideoCodec | null = null;
  for (const e of kids) {
    if (e.headerLen !== 8 || e.size < VISUAL_ENTRY_HEADER) continue;
    const vendor = e.start + 20, cname = e.start + 50;
    if (fix) { stsd.fill(0, vendor, vendor + 4); stsd.fill(0, cname, cname + 32); }
    else if (stsd.subarray(vendor, vendor + 4).some(x => x) || stsd.subarray(cname, cname + 32).some(x => x)) found.n++;
    const inner = listBoxes(stsd, e.start + VISUAL_ENTRY_HEADER, e.start + e.size) || [];
    const avcC = inner.find(k => k.type === 'avcC'), hvcC = inner.find(k => k.type === 'hvcC');
    if (AVC_ENTRIES.has(e.type) && avcC && avcC.size > avcC.headerLen + 4) codec = codec || { hevc: false, lenSize: (stsd[avcC.start + avcC.headerLen + 4] & 3) + 1 };
    if (HEVC_ENTRIES.has(e.type) && hvcC && hvcC.size > hvcC.headerLen + 22) {
      const base = hvcC.start + hvcC.headerLen, endC = hvcC.start + hvcC.size;
      codec = codec || { hevc: true, lenSize: (stsd[base + 21] & 3) + 1 };
      let p = base + 23;
      for (let a = 0, na = stsd[base + 22]; a < na; a++) {
        if (p + 3 > endC) { found.n++; break; }
        const t = stsd[p] & 0x3f, cnt = (stsd[p + 1] << 8) | stsd[p + 2]; p += 3;
        for (let k = 0; k < cnt; k++) {
          if (p + 2 > endC) { found.n++; break; }
          const n = (stsd[p] << 8) | stsd[p + 1]; p += 2;
          if (p + n > endC) { found.n++; break; }
          const nal = stsd.subarray(p, p + n);
          if ((t === 39 || t === 40) && isSeiNal(nal, true)) {
            const u = seiUserData(nal, 2);
            if (u === 'user' || u === 'bad') { if (!fix || !blankSei(nal, 2)) found.n++; }
          }
          p += n;
        }
      }
    }
  }
  return codec;
}
/** Absolute sample ranges of every fragment run, keyed by track id. */
function fragmentSampleRanges(b: Uint8Array, top: Box[], defaults: Map<number, number>): Map<number, [number, number][]> | null {
  const out = new Map<number, [number, number][]>();
  for (const moof of top.filter(x => x.type === 'moof')) {
    const trafs = (listBoxes(b, moof.start + moof.headerLen, moof.start + moof.size) || []).filter(k => k.type === 'traf');
    for (const traf of trafs) {
      const kids = listBoxes(b, traf.start + traf.headerLen, traf.start + traf.size);
      const tfhd = kids && kids.find(k => k.type === 'tfhd');
      if (!kids || !tfhd) return null;
      let q = tfhd.start + tfhd.headerLen;
      const tf = readU32(b, q) & 0xffffff, trackId = readU32(b, q + 4); q += 8;
      let base = moof.start;
      if (tf & 0x01) { base = readU64(b, q); q += 8; }
      if (tf & 0x02) q += 4;
      if (tf & 0x08) q += 4;
      let defSize = defaults.get(trackId) || 0;
      if (tf & 0x10) defSize = readU32(b, q);
      const list = out.get(trackId) || [];
      for (const trun of kids.filter(k => k.type === 'trun')) {
        let r = trun.start + trun.headerLen;
        const f = readU32(b, r) & 0xffffff, count = readU32(b, r + 4); r += 8;
        let off = base;
        if (f & 0x01) { off = base + (readU32(b, r) | 0); r += 4; }
        if (f & 0x04) r += 4;
        for (let i = 0; i < count; i++) {
          if (f & 0x100) r += 4;
          let size = defSize;
          if (f & 0x200) { size = readU32(b, r); r += 4; }
          if (f & 0x400) r += 4;
          if (f & 0x800) r += 4;
          if (!size || off + size > b.length) return null;
          list.push([off, off + size]); off += size;
        }
      }
      out.set(trackId, list);
    }
  }
  return out;
}
/** Every (codec, sample range) of the H.264/H.265 video in a file, from both the
 *  moov sample tables and fragment runs. null = can't locate them (fail closed). */
function videoSamples(b: Uint8Array, top: Box[]): { codec: VideoCodec; ranges: [number, number][] }[] | null {
  const moov = top.find(x => x.type === 'moov');
  if (!moov) return [];
  const traks = (listBoxes(b, moov.start + moov.headerLen, moov.start + moov.size) || []).filter(k => k.type === 'trak');
  const defaults = new Map<number, number>();
  const mvex = child(b, moov, 'mvex');
  for (const trex of ((mvex && listBoxes(b, mvex.start + mvex.headerLen, mvex.start + mvex.size)) || []).filter(k => k.type === 'trex')) {
    defaults.set(readU32(b, trex.start + trex.headerLen + 4), readU32(b, trex.start + trex.headerLen + 16));
  }
  const frags = top.some(x => x.type === 'moof') ? fragmentSampleRanges(b, top, defaults) : new Map<number, [number, number][]>();
  if (!frags) return null;
  const out: { codec: VideoCodec; ranges: [number, number][] }[] = [];
  for (const trak of traks) {
    if (handlerOf(b, trak) !== 'vide') continue;
    const stsd = findPath(b, trak, ['mdia', 'minf', 'stbl', 'stsd']);
    if (!stsd) continue;
    const codec = scrubVideoStsd(new Uint8Array(b.subarray(stsd.start, stsd.start + stsd.size)), stsd.headerLen, false, { n: 0 });
    if (!codec) continue;
    const ranges = trackSampleRanges(b, trak);
    if (!ranges) return null;
    const tkhd = child(b, trak, 'tkhd');
    const id = tkhd ? readU32(b, tkhd.start + tkhd.headerLen + (b[tkhd.start + tkhd.headerLen] === 1 ? 20 : 12)) : -1;
    out.push({ codec, ranges: [...ranges, ...(frags.get(id) || [])] });
  }
  return out;
}

interface Rebuilt { bytes: Uint8Array; chunkTables: { pos: number; wide: boolean }[] }

/** Rebuild one container, dropping metadata at every depth. Records where the
 *  kept stco/co64 tables land in the output so offsets can be patched later. */
function rebuildContainer(b: Uint8Array, box: Box, dropped: [number, number][], handler: string | null = null): Rebuilt | null {
  const kids = listBoxes(b, box.start + box.headerLen, box.start + box.size);
  if (!kids) return null;
  const parts: Uint8Array[] = [];
  const tables: { pos: number; wide: boolean }[] = [];
  let len = box.headerLen;
  for (const k of kids) {
    if (DROP_EVERYWHERE.has(k.type)) continue;
    if (k.type === 'trak') {
      const h = handlerOf(b, k);
      if (h && METADATA_HANDLERS.has(h)) {
        const r = trackSampleRanges(b, k);
        if (!r) return null;
        dropped.push(...r);                                              // zero its samples in mdat
        continue;
      }
    }
    if (CONTAINERS.has(k.type)) {
      const inner = rebuildContainer(b, k, dropped, k.type === 'trak' ? handlerOf(b, k) : handler);
      if (!inner) return null;
      for (const t of inner.chunkTables) tables.push({ pos: len + t.pos, wide: t.wide });
      parts.push(inner.bytes); len += inner.bytes.length;
      continue;
    }
    const copy = new Uint8Array(b.subarray(k.start, k.start + k.size));
    if (TIME_BOXES.has(k.type) && k.size >= k.headerLen + 12) {
      const v = copy[k.headerLen];                                       // version
      if (v === 1 && k.size >= k.headerLen + 20) { writeU64(copy, k.headerLen + 4, 0); writeU64(copy, k.headerLen + 12, 0); }
      else { writeU32(copy, k.headerLen + 4, 0); writeU32(copy, k.headerLen + 8, 0); }
    }
    if (k.type === 'hdlr' && k.size > k.headerLen + 24) copy.fill(0, k.headerLen + 24); // blank the handler name
    if (k.type === 'stsd' && handler === 'vide') scrubVideoStsd(copy, k.headerLen, true, { n: 0 }); // encoder name + hvcC SEI (V8 phase 2)
    if (k.type === 'stco' || k.type === 'co64') tables.push({ pos: len, wide: k.type === 'co64' });
    parts.push(copy); len += copy.length;
  }
  const out = new Uint8Array(len);
  out.set(b.subarray(box.start, box.start + box.headerLen), 0);
  if (box.headerLen === 16) { writeU32(out, 0, 1); writeU64(out, 8, len); } else writeU32(out, 0, len);
  let w = box.headerLen;
  for (const p of parts) { out.set(p, w); w += p.length; }
  return { bytes: out, chunkTables: tables };
}

/**
 * Full metadata scrub of an ISO-BMFF file. Returns scrubbed:false (with the
 * INPUT unchanged) whenever the structure can't be rewritten safely — the caller
 * must then refuse to send it rather than pass it through.
 */
export function deepScrubMp4Bytes(input: Uint8Array): { bytes: Uint8Array; scrubbed: boolean } {
  const top = listBoxes(input, 0, input.length);
  if (!top || !top.some(x => x.type === 'moov')) return { bytes: input, scrubbed: false };
  const fragmented = top.some(x => x.type === 'moof');
  const dropped: [number, number][] = [];
  // Phase 1: rebuild; lay out kept top-level boxes and remember where each lands.
  const kept: { box: Box; out: Uint8Array; newStart: number; tables: { pos: number; wide: boolean }[] }[] = [];
  let cursor = 0;
  for (const bx of top) {
    if (DROP_EVERYWHERE.has(bx.type)) continue;
    let out: Uint8Array, tables: { pos: number; wide: boolean }[] = [];
    if (bx.type === 'moov') {
      const r = rebuildContainer(input, bx, dropped);
      if (!r) return { bytes: input, scrubbed: false };
      out = r.bytes; tables = r.chunkTables;
    } else if (bx.type === 'moof') {
      // Fragments are copied verbatim (their data offsets are moof-relative), but
      // a fragment carrying its own metadata can't be rewritten safely → fail closed.
      const kids = listBoxes(input, bx.start + bx.headerLen, bx.start + bx.size);
      if (!kids || kids.some(k => DROP_EVERYWHERE.has(k.type))) return { bytes: input, scrubbed: false };
      out = input.subarray(bx.start, bx.start + bx.size);
    } else {
      out = input.subarray(bx.start, bx.start + bx.size);
    }
    kept.push({ box: bx, out, newStart: cursor, tables });
    cursor += out.length;
  }
  // Fragmented files: absolute offsets (tfhd base-data-offset, sidx) would break
  // if anything before a fragment moved. Allow only a layout where every moof
  // keeps its position.
  if (fragmented && kept.some(k => k.box.type === 'moof' && k.newStart !== k.box.start)) return { bytes: input, scrubbed: false };
  // Phase 2: map an old absolute offset to its new position.
  const remap = (off: number): number | null => {
    for (const k of kept) if (off >= k.box.start && off < k.box.start + k.box.size) return off - k.box.start + k.newStart;
    return null;
  };
  const out = new Uint8Array(cursor);
  for (const k of kept) out.set(k.out, k.newStart);
  for (const k of kept) {
    for (const t of k.tables) {
      const base = k.newStart + t.pos;
      const hl = readU32(out, base) === 1 ? 16 : 8;
      const n = readU32(out, base + hl + 4);
      for (let i = 0; i < n; i++) {
        const at = base + hl + 8 + (t.wide ? 8 : 4) * i;
        const old = t.wide ? readU64(out, at) : readU32(out, at);
        const nw = remap(old);
        if (nw === null || (!t.wide && nw > 0xffffffff)) return { bytes: input, scrubbed: false };
        if (t.wide) writeU64(out, at, nw); else writeU32(out, at, nw);
      }
    }
  }
  // Encoder fingerprints inside the H.264/H.265 bitstream (SEI user data), blanked
  // in place — equal lengths, so the offsets fixed above stay valid (V8 phase 2).
  const vids = videoSamples(input, top);
  if (!vids) return { bytes: input, scrubbed: false };
  for (const v of vids) {
    for (const [a, z] of v.ranges) {
      const na = remap(a);
      if (na === null || !scrubSampleSei(out, na, na + (z - a), v.codec, true, { n: 0 })) return { bytes: input, scrubbed: false };
    }
  }
  // Zero the sample bytes of every dropped metadata track (GPS telemetry lives in mdat).
  for (const [a, z] of dropped) {
    const na = remap(a);
    if (na === null) continue;
    out.fill(0, na, Math.min(out.length, na + (z - a)));
  }
  const audit = auditMp4(out);
  return audit.clean ? { bytes: out, scrubbed: true } : { bytes: input, scrubbed: false };
}
/** Kept for API compatibility: there is no weaker "standard" mode any more —
 *  V8 H-7 showed it left GPS behind while claiming removal. */
export function scrubMp4Bytes(input: Uint8Array): { bytes: Uint8Array; scrubbed: boolean } { return deepScrubMp4Bytes(input); }

/**
 * Independent re-scan of a (scrubbed) file: walks every box and reports anything
 * still identifying — metadata boxes at any depth, metadata-handler tracks,
 * non-zero capture times, handler names. Used to VERIFY a scrub before the UI
 * may claim metadata was removed.
 */
export function auditMp4(b: Uint8Array): { clean: boolean; findings: string[] } {
  const findings: string[] = [];
  const walk = (start: number, end: number, depth: number, path: string) => {
    const boxes = listBoxes(b, start, end);
    if (!boxes) { findings.push(`${path}: unparseable`); return; }
    for (const k of boxes) {
      const here = path + '/' + k.type;
      if (DROP_EVERYWHERE.has(k.type)) findings.push(`${here}: metadata box present`);
      if (k.type === 'trak') { const h = handlerOf(b, k); if (h && METADATA_HANDLERS.has(h)) findings.push(`${here}: metadata track (${h})`); }
      if (TIME_BOXES.has(k.type) && k.size >= k.headerLen + 12) {
        const v = b[k.start + k.headerLen];
        const t = v === 1 ? readU64(b, k.start + k.headerLen + 4) + readU64(b, k.start + k.headerLen + 12) : readU32(b, k.start + k.headerLen + 4) + readU32(b, k.start + k.headerLen + 8);
        if (t !== 0) findings.push(`${here}: capture time present`);
      }
      if (k.type === 'hdlr') { for (let i = k.start + k.headerLen + 24; i < k.start + k.size; i++) if (b[i] !== 0) { findings.push(`${here}: handler name present`); break; } }
      if ((CONTAINERS.has(k.type) || k.type === 'moof' || k.type === 'traf') && depth < 12) walk(k.start + k.headerLen, k.start + k.size, depth + 1, here);
    }
  };
  walk(0, b.length, 0, '');
  // Encoder fingerprints (V8 phase 2): compressor name / vendor in video sample
  // entries, SEI user data in hvcC and in the video samples themselves.
  const top = listBoxes(b, 0, b.length);
  if (top) {
    const left = { n: 0 };
    const moov = top.find(x => x.type === 'moov');
    for (const trak of ((moov && listBoxes(b, moov.start + moov.headerLen, moov.start + moov.size)) || []).filter(k => k.type === 'trak')) {
      const stsd = handlerOf(b, trak) === 'vide' ? findPath(b, trak, ['mdia', 'minf', 'stbl', 'stsd']) : null;
      if (stsd) scrubVideoStsd(new Uint8Array(b.subarray(stsd.start, stsd.start + stsd.size)), stsd.headerLen, false, left);
    }
    const vids = videoSamples(b, top);
    if (!vids) findings.push('video samples: cannot be located');
    else for (const v of vids) for (const [a, z] of v.ranges) if (!scrubSampleSei(b, a, z, v.codec, false, left)) { findings.push('video sample: malformed NAL units'); break; }
    if (left.n) findings.push(`${left.n} encoder fingerprint(s): compressor name / vendor / SEI user data`);
  }
  return { clean: findings.length === 0, findings };
}

/** Scrub a video data URL. ISO-BMFF (mp4/mov/3gp — the container every phone
 *  camera writes) → full scrub, verified by re-audit. Everything else → NOT
 *  scrubbed; the caller must block the send while scrubbing is on. The `deep`
 *  argument is accepted for compatibility; every scrub is now the full one. */
export function scrubVideo(dataUrl: string, _deep = true): ScrubResult {
  const m = /^data:(video\/[a-z0-9.+-]+);base64,(.*)$/is.exec(dataUrl);
  if (!m) return { url: dataUrl, scrubbed: false, note: 'unrecognized' };
  const mime = m[1].toLowerCase();
  if (mime !== 'video/mp4' && mime !== 'video/quicktime' && mime !== 'video/3gpp') {
    return { url: dataUrl, scrubbed: false, note: 'this video format can’t be scrubbed without re-encoding' };
  }
  try {
    const raw = b64ToBytes(m[2]);
    const { bytes, scrubbed } = deepScrubMp4Bytes(raw);
    if (!scrubbed) return { url: dataUrl, scrubbed: false, note: 'unsupported or non-MP4 file structure' };
    return { url: `data:${mime};base64,${bytesToB64(bytes)}`, scrubbed: true };
  } catch {
    return { url: dataUrl, scrubbed: false, note: 'parse failed' };
  }
}

// ---- Deep audio scrub ------------------------------------------------------
/** Minimal, dependency-free 16-bit PCM WAV encoder (mono). Pure function. */
export function encodeWav(samples: Float32Array, sampleRate: number): Uint8Array {
  const n = samples.length;
  const out = new Uint8Array(44 + n * 2);
  const dv = new DataView(out.buffer);
  const w4 = (off: number, str: string) => { for (let i = 0; i < 4; i++) out[off + i] = str.charCodeAt(i); };
  w4(0, 'RIFF'); dv.setUint32(4, 36 + n * 2, true); w4(8, 'WAVE');
  w4(12, 'fmt '); dv.setUint32(16, 16, true); dv.setUint16(20, 1, true); dv.setUint16(22, 1, true);
  dv.setUint32(24, sampleRate, true); dv.setUint32(28, sampleRate * 2, true);
  dv.setUint16(32, 2, true); dv.setUint16(34, 16, true);
  w4(36, 'data'); dv.setUint32(40, n * 2, true);
  for (let i = 0; i < n; i++) {
    const v = Math.max(-1, Math.min(1, samples[i]));
    dv.setInt16(44 + i * 2, v < 0 ? v * 0x8000 : v * 0x7fff, true);
  }
  return out;
}

/**
 * DEEP scrub for voice notes: decode to raw PCM and re-synthesize as a fresh
 * mono 24 kHz WAV. Nothing from the original container survives — only sound.
 * (In-app recordings are already metadata-free; this is belt-and-braces, and it
 * also normalises playback to a format every platform decodes.)
 */
export async function reencodeAudioDeep(dataUrl: string): Promise<ScrubResult> {
  try {
    const comma = dataUrl.indexOf(',');
    const raw = b64ToBytes(dataUrl.slice(comma + 1));
    const AC: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
    const probe = new AC();
    const decoded = await probe.decodeAudioData(raw.buffer.slice(0) as ArrayBuffer);
    probe.close().catch(() => {});
    const rate = 24000;
    const frames = Math.max(1, Math.ceil(decoded.duration * rate));
    const off = new OfflineAudioContext(1, frames, rate);
    const src = off.createBufferSource();
    src.buffer = decoded;
    src.connect(off.destination);
    src.start();
    const rendered = await off.startRendering();
    const wav = encodeWav(rendered.getChannelData(0), rate);
    return { url: `data:audio/wav;base64,${bytesToB64(wav)}`, scrubbed: true };
  } catch {
    return { url: dataUrl, scrubbed: false, note: 'decode failed' };
  }
}


// ---- Render-side blob URLs -------------------------------------------------
// Convert a decrypted data: URL to a Blob URL. Callers own the returned URL and
// must revoke it (the useBlobUrl hook does this on unmount). Keeping the base64
// out of the DOM is the single biggest chat-perf win for image/video-heavy views.
//
// Robustness: some encoders and some platforms emit base64 with embedded
// whitespace/newlines, or a MIME type carrying parameters (e.g.
// "image/jpeg;charset=..."). We strip whitespace before decoding and pass the
// full media type (minus the ;base64 marker) to the Blob so the browser decodes
// exactly what was sent. QuickTime/3GPP video is relabeled to mp4 so desktop
// browsers will play iPhone recordings.

// ---- attachment blob crypto (Signal-style out-of-band media) ----------------
// Each media file gets its own random AES-GCM key. We encrypt the raw bytes
// client-side, hand the ciphertext to the server as an opaque blob, and keep the
// key inside the (E2E-encrypted) message. The server never sees key or plaintext.

const _subtle = () => (globalThis.crypto || (globalThis as any).msCrypto).subtle;

function dataUrlParts(dataUrl: string): { mime: string; bytes: Uint8Array } {
  const comma = dataUrl.indexOf(',');
  if (!dataUrl.startsWith('data:') || comma < 0) throw new Error('not a data url');
  const header = dataUrl.slice(5, comma);
  const mime = (header.split(';')[0] || 'application/octet-stream').trim().toLowerCase();
  const payload = dataUrl.slice(comma + 1).replace(/\s/g, '');
  const bin = atob(payload);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return { mime, bytes };
}

export interface EncryptedAttachment {
  cipher: Uint8Array;   // uploaded blob (opaque to the server)
  key: string;          // base64 raw AES-GCM key (stays in the E2E message)
  iv: string;           // base64 IV
  mime: string;
}

/** Encrypt a data: URL into an opaque ciphertext blob + the key to read it. */
export async function encryptAttachment(dataUrl: string): Promise<EncryptedAttachment> {
  const { mime, bytes } = dataUrlParts(dataUrl);
  const key = await _subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await _subtle().encrypt({ name: 'AES-GCM', iv }, key, bytes.buffer as ArrayBuffer);
  const raw = await _subtle().exportKey('raw', key);
  return { cipher: new Uint8Array(ct), key: bytesToB64(raw), iv: bytesToB64(iv), mime };
}

/** Decrypt fetched ciphertext bytes back into a usable data: URL. */
export async function decryptAttachment(cipher: ArrayBuffer, keyB64: string, ivB64: string, mime: string): Promise<string> {
  const key = await _subtle().importKey('raw', b64ToBytes(keyB64).buffer as ArrayBuffer, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await _subtle().decrypt({ name: 'AES-GCM', iv: b64ToBytes(ivB64).buffer as ArrayBuffer }, key, cipher);
  return `data:${mime};base64,${bytesToB64(pt)}`;
}

export function dataUrlToBlobUrl(dataUrl: string): string {
  const comma = dataUrl.indexOf(',');
  if (!dataUrl.startsWith('data:') || comma < 0) throw new Error('not a data url');
  const header = dataUrl.slice(5, comma);                 // e.g. "image/jpeg;base64"
  const segs = header.split(';').map(x => x.trim());
  let mime = segs[0] || 'application/octet-stream';
  if (mime === 'video/quicktime' || mime === 'video/3gpp') mime = 'video/mp4';
  const payload = dataUrl.slice(comma + 1).replace(/\s/g, '');  // tolerate wrapped base64
  const bin = atob(payload);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return URL.createObjectURL(new Blob([bytes.buffer as ArrayBuffer], { type: mime }));
}

