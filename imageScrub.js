// ---------------------------------------------------------------------------
// Server-side image metadata stripping (security review V8, finding M-3).
//
// The client already re-encodes every profile photo through a canvas (only
// pixels survive), but the SERVER used to store and serve whatever bytes arrived
// after a bare `data:image/...` prefix check — so a modified, older, or
// third-party client could publish a photo carrying EXIF GPS, camera serials, an
// embedded thumbnail, XMP, IPTC, comments or trailing data, and every viewer
// would receive it verbatim. This module makes the guarantee server-enforced.
//
// Approach: a strict STRUCTURAL rewrite, no decoding and no dependencies. For each
// accepted format we walk the container, keep ONLY the structures needed to
// render pixels, and drop everything else — metadata segments/chunks, unknown or
// private chunks, and any bytes after the end-of-image marker. Anything we can't
// parse is REJECTED (fail closed), and the magic bytes must match the declared
// MIME type. Pure functions; exported for tests.
// ---------------------------------------------------------------------------

export class ImageRejected extends Error {}
const fail = (msg) => { throw new ImageRejected(msg); };

// ---- JPEG ------------------------------------------------------------------
// Keep: SOI, DQT, DHT, DRI, SOFn, SOS + entropy-coded data, EOI, a bare JFIF
// APP0 (no embedded thumbnail), and a bare 12-byte "Adobe" APP14 (colour-
// transform flag needed to decode CMYK/YCCK correctly — no user data). Drop:
// APP1 (EXIF incl. GPS + IFD1 thumbnail, XMP), APP2 (ICC / FlashPix), APP3–APP13
// (incl. IPTC in APP13), APP15, COM, and anything after EOI.
function stripJpeg(b) {
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) fail('not a JPEG');
  const out = [Buffer.from([0xff, 0xd8])];
  let i = 2;
  let sawSof = false, sawSos = false;
  for (;;) {
    // Marker: one or more 0xFF fill bytes then a non-FF code.
    if (i >= b.length) fail('truncated JPEG');
    if (b[i] !== 0xff) fail('bad JPEG marker');
    while (i < b.length && b[i] === 0xff) i++;
    if (i >= b.length) fail('truncated JPEG');
    const m = b[i++];
    if (m === 0xd9) { out.push(Buffer.from([0xff, 0xd9])); break; }       // EOI — drop any trailer
    if (m === 0xd8 || (m >= 0xd0 && m <= 0xd7) || m === 0x01) fail('unexpected JPEG marker');
    if (i + 2 > b.length) fail('truncated JPEG');
    const len = b.readUInt16BE(i);
    if (len < 2 || i + len > b.length) fail('bad JPEG segment length');
    const seg = b.subarray(i - 2, i + len);                              // FF xx + length + payload
    const payload = b.subarray(i + 2, i + len);
    i += len;
    const isApp = m >= 0xe0 && m <= 0xef;
    let keep;
    if (m === 0xe0) keep = len === 16 && payload.subarray(0, 5).toString('latin1') === 'JFIF\0'; // no thumbnail
    else if (m === 0xee) keep = len === 14 && payload.subarray(0, 5).toString('latin1') === 'Adobe';
    else if (isApp || m === 0xfe) keep = false;                           // metadata / comments
    else keep = true;                                                     // DQT, DHT, DRI, SOFn, SOS, DNL…
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) sawSof = true;
    if (keep) out.push(seg);
    if (m === 0xda) {
      sawSos = true;
      // Entropy-coded data runs until the next real marker (FF followed by a
      // byte that is neither a 0x00 stuffing byte nor an RSTn).
      const start = i;
      while (i < b.length) {
        if (b[i] === 0xff && i + 1 < b.length) {
          const n = b[i + 1];
          if (n === 0x00 || (n >= 0xd0 && n <= 0xd7)) { i += 2; continue; }
          if (n === 0xff) { i += 1; continue; }                           // fill byte before a marker
          break;
        }
        i++;
      }
      if (i >= b.length) fail('JPEG scan not terminated');
      out.push(b.subarray(start, i));
    }
  }
  if (!sawSof || !sawSos) fail('JPEG has no image data');
  return Buffer.concat(out);
}

// ---- PNG -------------------------------------------------------------------
// Keep critical chunks + animation + a few pure-rendering hints; drop text
// (tEXt/zTXt/iTXt), eXIf, tIME, iCCP, pHYs, and every unknown/private chunk.
// Everything after IEND is dropped. Chunk CRCs are preserved byte-for-byte.
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_KEEP = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'sBIT', 'bKGD', 'acTL', 'fcTL', 'fdAT']);
function stripPng(b) {
  if (b.length < 8 || !b.subarray(0, 8).equals(PNG_SIG)) fail('not a PNG');
  const out = [PNG_SIG];
  let i = 8, sawIhdr = false, sawIdat = false;
  for (;;) {
    if (i + 12 > b.length) fail('truncated PNG');
    const len = b.readUInt32BE(i);
    const type = b.subarray(i + 4, i + 8).toString('latin1');
    if (!/^[A-Za-z]{4}$/.test(type)) fail('bad PNG chunk type');
    const end = i + 12 + len;
    if (len > 0x7fffffff || end > b.length) fail('bad PNG chunk length');
    if (type === 'IHDR') sawIhdr = true;
    if (type === 'IDAT') sawIdat = true;
    if (PNG_KEEP.has(type)) out.push(b.subarray(i, end));
    i = end;
    if (type === 'IEND') break;
  }
  if (!sawIhdr || !sawIdat) fail('PNG has no image data');
  return Buffer.concat(out);
}

// ---- WebP ------------------------------------------------------------------
// RIFF container. Keep VP8/VP8L/VP8X/ALPH/ANIM/ANMF; drop ICCP, EXIF, XMP and
// unknown chunks, clear the matching VP8X flag bits, and recompute RIFF size.
const WEBP_KEEP = new Set(['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANIM', 'ANMF']);
function stripWebp(b) {
  if (b.length < 12 || b.subarray(0, 4).toString('latin1') !== 'RIFF' || b.subarray(8, 12).toString('latin1') !== 'WEBP') fail('not a WebP');
  const riffEnd = Math.min(b.length, 8 + b.readUInt32LE(4));
  const chunks = [];
  let i = 12, sawImage = false;
  while (i + 8 <= riffEnd) {
    const type = b.subarray(i, i + 4).toString('latin1');
    const len = b.readUInt32LE(i + 4);
    const padded = len + (len & 1);
    if (i + 8 + len > riffEnd) fail('bad WebP chunk length');
    if (WEBP_KEEP.has(type)) {
      const c = Buffer.alloc(8 + padded);
      b.copy(c, 0, i, Math.min(i + 8 + padded, riffEnd));
      if (type === 'VP8X' && len >= 1) c[8] &= ~(0x20 | 0x08 | 0x04);    // clear ICC, EXIF, XMP flags
      chunks.push(c);
      if (type === 'VP8 ' || type === 'VP8L' || type === 'ANMF') sawImage = true;
    }
    i += 8 + padded;
  }
  if (!sawImage) fail('WebP has no image data');
  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'latin1'); header.writeUInt32LE(4 + body.length, 4); header.write('WEBP', 8, 'latin1');
  return Buffer.concat([header, body]);
}

// ---- GIF -------------------------------------------------------------------
// Keep header, screen descriptor, colour tables, image descriptors + LZW data,
// Graphic Control extensions, and the NETSCAPE2.0/ANIMEXTS1.0 loop extension.
// Drop Comment (FE), Plain Text (01) and every other Application extension
// (XMP "XMP DataXMP", ICC, vendor blobs), and anything after the trailer.
function readSubBlocks(b, i) {
  for (;;) {
    if (i >= b.length) fail('truncated GIF');
    const n = b[i];
    i += 1 + n;
    if (n === 0) return i;
  }
}
function stripGif(b) {
  const sig = b.subarray(0, 6).toString('latin1');
  if (b.length < 13 || (sig !== 'GIF87a' && sig !== 'GIF89a')) fail('not a GIF');
  const out = [];
  let i = 13;
  const flags = b[10];
  if (flags & 0x80) i += 3 * (1 << ((flags & 7) + 1));                   // global colour table
  if (i > b.length) fail('truncated GIF');
  out.push(b.subarray(0, i));
  let sawImage = false;
  for (;;) {
    if (i >= b.length) fail('truncated GIF');
    const t = b[i];
    if (t === 0x3b) { out.push(Buffer.from([0x3b])); break; }            // trailer — drop anything after
    if (t === 0x2c) {                                                     // image descriptor
      if (i + 10 > b.length) fail('truncated GIF');
      const lf = b[i + 9];
      let j = i + 10;
      if (lf & 0x80) j += 3 * (1 << ((lf & 7) + 1));                      // local colour table
      j += 1;                                                             // LZW minimum code size
      const end = readSubBlocks(b, j);
      out.push(b.subarray(i, end));
      i = end; sawImage = true;
      continue;
    }
    if (t === 0x21) {                                                     // extension
      if (i + 2 > b.length) fail('truncated GIF');
      const label = b[i + 1];
      const end = readSubBlocks(b, i + 2);
      let keep = label === 0xf9;                                          // graphic control
      if (label === 0xff && b[i + 2] === 11) {
        const app = b.subarray(i + 3, i + 14).toString('latin1');
        keep = app === 'NETSCAPE2.0' || app === 'ANIMEXTS1.0';            // looping only
      }
      if (keep) out.push(b.subarray(i, end));
      i = end;
      continue;
    }
    fail('bad GIF block');
  }
  if (!sawImage) fail('GIF has no image data');
  return Buffer.concat(out);
}

const STRIPPERS = { png: stripPng, jpeg: stripJpeg, webp: stripWebp, gif: stripGif };
const DATA_URL_RE = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/;

/** Strip every metadata structure from an image data URL. Returns a canonical
 *  data URL (same MIME) or throws ImageRejected if the bytes aren't a well-formed
 *  image of the declared type. */
export function scrubImageDataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') fail('not a string');
  const m = DATA_URL_RE.exec(dataUrl);
  if (!m) fail('unsupported image data URL');
  const kind = m[1];
  const bytes = Buffer.from(m[2], 'base64');
  if (!bytes.length) fail('empty image');
  const clean = STRIPPERS[kind](bytes);
  return `data:image/${kind};base64,${clean.toString('base64')}`;
}

export const _internal = { stripJpeg, stripPng, stripWebp, stripGif };
