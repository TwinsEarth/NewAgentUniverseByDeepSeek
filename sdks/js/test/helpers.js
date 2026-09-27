/**
 * Shared test helpers. No test framework beyond `node:test`/`node:assert`.
 */

import crypto from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const SDK_ROOT = path.resolve(HERE, '..');

/** Walk up from this file to the directory that holds `conformance/`. */
export function findRepoRoot(start = SDK_ROOT) {
  let dir = path.resolve(start);
  for (;;) {
    if (existsSync(path.join(dir, 'conformance', 'vectors.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error('could not locate the repository root (conformance/vectors.json)');
    dir = parent;
  }
}

export const REPO_ROOT = findRepoRoot();
export const VECTORS_PATH = path.join(REPO_ROOT, 'conformance', 'vectors.json');

/** The shared conformance fixture. */
export const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));

/** Every payload in the fixture, in file order. */
export const allPayloads = vectors.payloads;

/** Payload ids that the fixture marks as unreproducible from a JS parse. */
export function isJsUnsupported(payload) {
  return payload.languages?.javascript === 'unsupported-by-json-parse';
}

/** The fixture's Ed25519 seed. */
export const SEED = Buffer.from(vectors.seed_hex, 'hex');

/**
 * Rebuild a fixture canonical string for a value whose JSON text JavaScript
 * cannot parse exactly (the two wide-integer entries).
 *
 * The fixture stores the input as *text* precisely so that 64-bit integers
 * survive; `JSON.parse` would turn `2^63 - 1` into `9223372036854776000`. The
 * only honest way for JavaScript to reproduce those bytes is to splice the
 * original integer token back in, which is what this does: the canonical form
 * differs from the input only by key order and by the dropped `signature` key,
 * so the token appears verbatim in the input text.
 *
 * @param {string} inputJson
 * @param {string} canonical
 * @returns {string}
 */
export function spliceWideIntegers(inputJson, canonical) {
  const tokens = inputJson.match(/(?<=[:,])\s*(-?\d{16,})\s*(?=[,}])/g)?.map((t) => t.trim()) ?? [];
  if (tokens.length === 0) throw new Error('no wide integer token found in the fixture input');
  let out = canonical;
  for (const token of tokens) {
    const rounded = String(Number(token));
    if (out.includes(rounded)) {
      out = out.replace(rounded, token);
    } else if (!out.includes(token)) {
      throw new Error(`cannot splice wide integer ${token}: it appears in no form in ${canonical}`);
    }
  }
  return out;
}

/** Sign `text` with the fixture seed, as `generate.mjs` does. */
export function fixtureSign(text) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), SEED]),
    format: 'der',
    type: 'pkcs8',
  });
  return crypto.sign(null, Buffer.from(text, 'utf8'), privateKey).toString('hex');
}

/** All source files of the SDK, for drift checks. */
export function sdkFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else out.push(full);
    }
  };
  walk(SDK_ROOT);
  return out;
}

/**
 * Start a `node:http` stub server on port 0.
 *
 * @param {(req: http.IncomingMessage, res: http.ServerResponse, body: string) => void} handler
 * @returns {Promise<{url: string, port: number, requests: any[], close: () => Promise<void>}>}
 */
export function startStubServer(handler) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      try {
        handler(req, res, body);
      } catch (err) {
        res.statusCode = 500;
        res.end(String(err && err.stack ? err.stack : err));
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        port: address.port,
        requests,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

/** Write JSON with a status code. */
export function sendJson(res, status, payload) {
  const text = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(text);
}

/** Write a non-JSON body with a status code (HTML from a proxy, say). */
export function sendText(res, status, text, contentType = 'text/html') {
  res.statusCode = status;
  res.setHeader('content-type', contentType);
  res.end(text);
}

export default { vectors, REPO_ROOT, startStubServer, sendJson, sendText };
