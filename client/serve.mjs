#!/usr/bin/env node
/**
 * A zero-dependency static file server for `client/`, with a reverse proxy for
 * the daemon's HTTP API.
 *
 *     node client/serve.mjs [--port 8080] [--daemon http://127.0.0.1:4002]
 *                           [--host 127.0.0.1] [--root <dir>] [--quiet]
 *
 * # Why a proxy and not just CORS
 *
 * The daemon sends no CORS headers — deliberately, since it is not a public web
 * service. Proxying `/api/*` onto the daemon means the page and every request it
 * makes share one origin, so CORS never enters the picture, there is no
 * preflight, and no `Access-Control-Allow-Origin: *` is ever required. The
 * server also sends `text/javascript` for `.js`/`.mjs`, without which a browser
 * refuses the ES module, and `text/html` for `.html` with `charset=utf-8`.
 *
 * This file uses only `node:http`, `node:fs` and `node:path` — no npm packages,
 * so there is nothing to install and nothing to audit.
 */

import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Extension → content type. An unknown extension is served as octet-stream. */
const CONTENT_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
});

/**
 * The real `fetch`, captured at module load.
 *
 * `client/test/e2e.mjs` replaces `globalThis.fetch` with a wrapper that resolves
 * the page's relative `/api/...` URLs, so that `app.js` can be executed under a
 * DOM stub. If this module looked `fetch` up lazily it would pick up that
 * wrapper and try to resolve an already-absolute URL — so the reference is
 * captured once, here, before any test can replace it.
 */
const upstreamFetch = globalThis.fetch;

/** The URL prefix that is proxied to the daemon and stripped before forwarding. */
export const API_PREFIX = '/api';

/**
 * Parse `--flag value` pairs out of `argv`.
 *
 * @param {string[]} argv
 * @returns {{port: number, host: string, daemon: string, root: string, quiet: boolean}}
 */
export function parseArgs(argv) {
  const options = {
    port: 8080,
    host: '127.0.0.1',
    daemon: 'http://127.0.0.1:4002',
    root: fileURLToPath(new URL('.', import.meta.url)),
    quiet: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = argv[i + 1];
    switch (arg) {
      case '--port':
      case '-p':
        options.port = Number.parseInt(value, 10);
        i += 1;
        break;
      case '--host':
        options.host = String(value);
        i += 1;
        break;
      case '--daemon':
      case '-d':
        options.daemon = String(value).replace(/\/+$/, '');
        i += 1;
        break;
      case '--root':
        options.root = resolve(String(value));
        i += 1;
        break;
      case '--quiet':
      case '-q':
        options.quiet = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        throw new Error(`unknown argument \`${arg}\` (try --help)`);
    }
  }
  if (!Number.isInteger(options.port) || options.port <= 0 || options.port > 65535) {
    throw new Error(`--port must be an integer in 1..65535, got ${options.port}`);
  }
  return options;
}

const HELP = `nau client static server

USAGE:
    node client/serve.mjs [OPTIONS]

OPTIONS:
    -p, --port <PORT>        listen port (default 8080; use 0 for an ephemeral one)
        --host <HOST>        bind address (default 127.0.0.1)
    -d, --daemon <URL>       daemon base URL to proxy /api/* to
                             (default http://127.0.0.1:4002)
        --root <DIR>         directory to serve (default: this file's directory)
    -q, --quiet              do not log requests
    -h, --help               print this help

Routes:
    /api/*   proxied to the daemon with the prefix stripped
    /*       served from --root, with index.html for a directory or a bare /
`;

/**
 * Resolve a request path to a file inside `root`, or `null` when it escapes.
 *
 * A leading `/` plus `path.normalize` is not enough on its own: a request target
 * of `/../../etc/passwd` normalizes outside the root, so the resolved path is
 * compared against the root prefix with a trailing separator.
 *
 * @param {string} root
 * @param {string} urlPath
 * @returns {string|null}
 */
export function resolveStaticPath(root, urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath.split('?')[0]);
  } catch {
    return null;
  }
  if (decoded.includes('\0')) return null;
  const relative = normalize(decoded).replace(/^([/\\])+/, '');
  const candidate = resolve(root, relative);
  const rootWithSep = root.endsWith(sep) ? root : root + sep;
  if (candidate !== root && !candidate.startsWith(rootWithSep)) return null;
  return candidate;
}

/**
 * Forward one request to the daemon.
 *
 * The daemon's server handles exactly one request per connection and closes it,
 * so a fresh `fetch` per proxied request is both correct and the simplest thing
 * that works; there is no connection pool to get wrong.
 *
 * @param {string} daemon base URL, no trailing slash
 * @param {import('node:http').IncomingMessage} req the original request
 * @param {string} forwarded the path to forward, prefix already stripped
 * @returns {Promise<{status: number, body: string, contentType: string}>}
 */
async function proxyToDaemon(daemon, req, forwarded) {
  const target = new URL(forwarded, `${daemon}/`);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const hasBody = chunks.length > 0;
  const headers = { accept: 'application/json' };
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  const init = { method: req.method, headers };
  // `fetch` rejects a GET with a body object at all, so the property is only
  // present when there is something to send.
  if (hasBody) init.body = Buffer.concat(chunks);
  try {
    const response = await upstreamFetch(target, init);
    const text = await response.text();
    return {
      status: response.status,
      body: text,
      contentType: response.headers.get('content-type') ?? 'application/json; charset=utf-8',
    };
  } catch (cause) {
    return {
      status: 502,
      body: JSON.stringify({
        error: 'bad_gateway',
        message: `the static server could not reach the daemon at ${daemon} (${
          cause && cause.message ? cause.message : cause
        })`,
      }),
      contentType: 'application/json; charset=utf-8',
    };
  }
}

/**
 * Build the request handler. Exported so the test can drive it without a socket.
 *
 * @param {{daemon: string, root: string, quiet?: boolean}} options
 * @returns {import('node:http').RequestListener}
 */
export function createHandler(options) {
  const { daemon, root, quiet = false } = options;
  return (req, res) => {
    void (async () => {
      const started = Date.now();
      if (req.url && req.url.startsWith(API_PREFIX)) {
        // Strip the prefix: the daemon's routes are `/health`, `/agents`, … with
        // no version prefix of their own.
        const stripped = req.url.slice(API_PREFIX.length) || '/';
        const forwarded = stripped.startsWith('/') ? stripped : `/${stripped}`;
        const result = await proxyToDaemon(daemon, req, forwarded);
        res.writeHead(result.status, {
          'content-type': result.contentType,
          'cache-control': 'no-store',
        });
        res.end(result.body);
        if (!quiet) {
          log(req.method, req.url, result.status, Date.now() - started);
        }
        return;
      }

      const path = resolveStaticPath(root, req.url ?? '/');
      if (path === null) {
        sendText(res, 400, 'bad request: the path escapes the served directory\n');
        return;
      }
      let filePath = path;
      try {
        const info = await stat(filePath);
        if (info.isDirectory()) filePath = join(filePath, 'index.html');
      } catch {
        sendText(res, 404, `not found: ${req.url}\n`);
        if (!quiet) log(req.method, req.url, 404, Date.now() - started);
        return;
      }
      let info;
      try {
        info = await stat(filePath);
      } catch {
        sendText(res, 404, `not found: ${req.url}\n`);
        if (!quiet) log(req.method, req.url, 404, Date.now() - started);
        return;
      }
      if (!info.isFile()) {
        sendText(res, 404, `not found: ${req.url}\n`);
        if (!quiet) log(req.method, req.url, 404, Date.now() - started);
        return;
      }
      const type = CONTENT_TYPES[extname(filePath).toLowerCase()] ?? 'application/octet-stream';
      res.writeHead(200, {
        'content-type': type,
        'content-length': info.size,
        'cache-control': 'no-store',
        // A local development surface should not be framed or sniffed.
        'x-content-type-options': 'nosniff',
      });
      createReadStream(filePath).pipe(res);
      if (!quiet) log(req.method, req.url, 200, Date.now() - started);
    })().catch((error) => {
      if (!res.headersSent) sendText(res, 500, `internal error: ${error.message}\n`);
      else res.destroy();
      if (!quiet) console.error(`[serve] ${req.method} ${req.url} failed: ${error.stack}`);
    });
  };
}

/** @param {import('node:http').ServerResponse} res */
function sendText(res, status, text) {
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
  });
  res.end(text);
}

/** @param {string} method @param {string} url @param {number} status @param {number} ms */
function log(method, url, status, ms) {
  console.log(`[serve] ${method} ${url} -> ${status} (${ms} ms)`);
}

/**
 * Start the server.
 *
 * @param {{port?: number, host?: string, daemon?: string, root?: string, quiet?: boolean}} [options]
 * @returns {Promise<{server: import('node:http').Server, port: number, url: string, close: () => Promise<void>}>}
 */
export async function startServer(options = {}) {
  const root = resolve(options.root ?? fileURLToPath(new URL('.', import.meta.url)));
  const daemon = (options.daemon ?? 'http://127.0.0.1:4002').replace(/\/+$/, '');
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 8080;
  const server = createServer(createHandler({ daemon, root, quiet: options.quiet ?? false }));
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(port, host, () => {
      server.off('error', rejectListen);
      resolveListen();
    });
  });
  const address = server.address();
  const actualPort = typeof address === 'object' && address !== null ? address.port : port;
  return {
    server,
    port: actualPort,
    url: `http://${host}:${actualPort}`,
    close: () =>
      new Promise((resolveClose, rejectClose) => {
        server.close((error) => (error ? rejectClose(error) : resolveClose()));
      }),
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`[serve] ${error.message}`);
    process.exit(2);
  }
  if (options.help) {
    console.log(HELP);
    process.exit(0);
  }
  const started = await startServer(options);
  console.log(`[serve] serving ${options.root}`);
  console.log(`[serve] proxying ${API_PREFIX}/* -> ${options.daemon}`);
  console.log(`[serve] open ${started.url}/ in a browser`);
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      void started.close().then(() => process.exit(0));
    });
  }
}
