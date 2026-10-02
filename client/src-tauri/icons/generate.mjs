/**
 * Write the shell's placeholder PNG icons.
 *
 *     node client/src-tauri/icons/generate.mjs
 *
 * Uses only `node:zlib` — no image library and no npm dependency. The icons are a
 * deliberate solid colour with a lighter border, not artwork: they exist so that
 * `tauri.conf.json` does not reference a file that is absent. That was upstream's
 * failure (`desktop/src-tauri/tauri.conf.json:34-35` required `icons/icon.icns`
 * and `icons/icon.ico`, both `.gitignore`d and missing, so `tauri build` could
 * never succeed). Replace these with real artwork before shipping.
 *
 * The PNG encoder here is split across chunk boundaries exactly as spec requires:
 * IHDR first, then IDAT, then IEND, each with a CRC-32 over its type and data.
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/** PNG signature. */
const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** CRC-32 table, built once. */
const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

/**
 * @param {Buffer} buffer
 * @returns {number} CRC-32, as an unsigned 32-bit integer
 */
function crc32(buffer) {
  let c = -1;
  for (const byte of buffer) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

/**
 * One PNG chunk.
 * @param {string} type four ASCII characters
 * @param {Buffer} data
 * @returns {Buffer}
 */
function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeAndData = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData), 0);
  return Buffer.concat([length, typeAndData, crc]);
}

/**
 * Encode an 8-bit RGBA PNG.
 *
 * @param {number} width
 * @param {number} height
 * @param {(x: number, y: number) => [number, number, number, number]} pixel
 * @returns {Buffer}
 */
export function encodePng(width, height, pixel) {
  const raw = Buffer.alloc(height * (1 + width * 4));
  let offset = 0;
  for (let y = 0; y < height; y += 1) {
    raw[offset] = 0; // filter type: none
    offset += 1;
    for (let x = 0; x < width; x += 1) {
      const [r, g, b, a] = pixel(x, y);
      raw[offset] = r;
      raw[offset + 1] = g;
      raw[offset + 2] = b;
      raw[offset + 3] = a;
      offset += 4;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace
  return Buffer.concat([
    SIGNATURE,
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** The icon: a dark slate field with a lighter border and a small accent square. */
function aPixel(x, y, size) {
  const border = 2;
  const onBorder = x < border || y < border || x >= size - border || y >= size - border;
  if (onBorder) return [127, 182, 221, 255];
  const inset = Math.floor(size * 0.3);
  const inAccent = x >= inset && y >= inset && x < size - inset && y < size - inset;
  if (inAccent) return [31, 95, 139, 255];
  return [20, 24, 29, 255];
}

const SIZES = [
  ['32x32.png', 32],
  ['128x128.png', 128],
  ['128x128@2x.png', 256],
];

const here = dirname(fileURLToPath(import.meta.url));
for (const [name, size] of SIZES) {
  const png = encodePng(size, size, (x, y) => aPixel(x, y, size));
  writeFileSync(join(here, name), png);
  console.log(`wrote ${name} (${size}×${size}, ${png.length} bytes)`);
}
