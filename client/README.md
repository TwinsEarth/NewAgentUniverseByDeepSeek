# `client/` - a browser client that actually talks to the daemon

A real GUI for `nau-daemon`: static files, no build step, no bundler, no npm
dependency, and no simulation. Every button performs an HTTP request against a
running node and prints the node's own answer - including its refusals, with the
HTTP status.

```console
# 1. build and run a node (ephemeral: nothing is written to disk)
cargo build -p nau-node --bin nau-daemon
target/debug/nau-daemon --api-port 4002 --ephemeral      # nau-daemon on unix

# 2. serve the client, proxying /api/* to that node
node client/serve.mjs --port 8080 --daemon http://127.0.0.1:4002

# 3. open http://127.0.0.1:8080/
```

`node client/serve.mjs --help` prints all options (`--port`, `--host`,
`--daemon`, `--root`, `--quiet`; `--port 0` picks a free port).

---

## 1. Why this is a rewrite, not a repair

`docs/GAP-ANALYSIS.md` section 9.5 and `ATTRIBUTION.md` section 2.3 record what
upstream agent-universe v2.5.6 shipped as `client/` and `desktop/`, and this
directory is the replacement for the first of the two. The findings and what
changed here:

| Upstream finding | What this client does instead |
|---|---|
| `client/src/main.js:1` imported the npm package and ran an **in-memory market simulation in the tab** - no daemon, no HTTP | `client/lib/nau.mjs` is an HTTP client only. There is no in-process market: an unreachable daemon is an error the page shows, not a market it invents. |
| The two Rust sides totalled 36 lines and exposed two commands, and **neither frontend ever called them** (`grep invoke` found nothing) | The browser client has no Rust side at all, so there is nothing to fail to call. The Tauri shell in `src-tauri/` is a separate, thin, unbuilt shell (see section 7). |
| Both frontends read `c.totalPaid`, a field `conservationCheck()` never returned, and printed `undefined` | Panel 5 renders `GET /conservation` and `GET /audit` from the real response. `client/test/e2e.mjs` asserts that `totalPaid` is **absent**, so the upstream mistake cannot come back unnoticed. |
| `"csp": null` plus log lines built with `innerHTML` - an XSS sink with the mitigation switched off | `index.html` ships a real `Content-Security-Policy`, and `app.js` contains **no `innerHTML` and no `insertAdjacentHTML`**: text goes through `textContent`, structure through `createElement`. `client/test/e2e.mjs` greps for both. |
| The demo expected a second `settle()` to throw and printed a false alarm when it did not | No behaviour is asserted from the client's imagination: the panel calls the endpoint and shows the response. `POST /tasks/{id}/settle` twice is a `409 conflict` from the daemon. |

Nothing here is copied from upstream. The identity and canonical-JSON rules are
the project's own, pinned by `conformance/vectors.json`.

---

## 2. Quick tour of the UI

| Panel | Calls | What it demonstrates |
|---|---|---|
| 1, Identity | none (local `crypto.subtle`) | PKCS#8-importing a 32-byte seed; the DID derived as `did:nau:` + first 8 bytes of SHA-256(raw public key). "Load the conformance seed" reproduces `did:nau:34750f98bd59fcfc` and fails loudly if it does not. |
| 2, Account | `POST /accounts/{did}/deposit`, `GET /accounts/{did}/balance` | Decimal-string amounts, and a deliberate **"try a float"** button that sends `12.5` as a JSON number so the daemon's `422` is on screen. |
| 3, Registry | `POST /agents`, `GET /agents[?skill= \| ?q=]` | A card signed in the browser, then capability discovery and text search. |
| 4, Task lifecycle | `POST /tasks`, `/bids`, `/match`, `/start`, `/results`, `/verify`, `/settle`, `GET /tasks/{id}` | publish, bid, match, start, submit, verify with three **signed** votes, settle. Each step is one request; each object is signed. |
| 5, Invariant | `GET /conservation`, `GET /audit` | The O(1) counters and the independent O(N) recomputation side by side, with an explicit AGREE/DISAGREE verdict on `discrepancy`. |
| 6, Reporting | `GET /stats`, `GET /leaderboard?limit=10` | Counters and the reputation ranking. |
| 7, Raw request log | - | Every call the page made, with its outcome. A failure is recorded with its status, so no button can be a silent no-op. |

---

## 3. Amounts are decimal strings, and the refusal is visible

`Money` in `crates/nau-core/src/domain/money.rs` is an `i64` count of minor units
(10^-6) and serializes as a JSON **integer**. The API therefore accepts either

```json
{"amount": "12.5"}      // a decimal string - what the UI sends
{"amount_minor": 12500000}
```

and refuses a floating-point amount with `422 unprocessable`, because `100`,
`100.0` and `1e2` format differently in Rust, Python and JavaScript and a float
therefore cannot be reproduced byte-for-byte in a signed payload.

The panel has a button for each path. The float is reported as
``HTTP 422 unprocessable: `amount` must be a decimal string ...`` in the log, in a
banner, and in the request log. Hiding that would be exactly the kind of demo
that teaches the reader nothing.

> Note on JavaScript and floats: `JSON.parse('100.0')` is the integer `100`, so a
> JS client cannot tell `100` from `100.0` - see
> `sdks/js/test/conformance.test.js:187`. The daemon can, and does.

---

## 4. Signing in the browser

`client/lib/nau.mjs`:

1. `PKCS8_ED25519_PREFIX_HEX = '302e020100300506032b657004220420'` + the 32-byte
   seed, then `crypto.subtle.importKey('pkcs8', ..., { name: 'Ed25519' })`.
2. The raw public key is the `x` member of the JWK export (a PKCS#8 Ed25519 key
   carries no public part, so this is the portable way to recover it).
3. `DID = 'did:nau:' + hex(sha256(rawPublicKey)[0..8])`.
4. Signing canonicalizes the object, drops every `signature` key at **every**
   depth, sorts keys by **Unicode code point**, emits no whitespace and only
   integers, and signs the UTF-8 bytes.

The canonicalizer lives in `client/lib/canonical.mjs`, and `app.js` does not
re-implement it: the module is shared with `client/test/e2e.mjs`, which proves it
byte-for-byte against `conformance/vectors.json` and verifies a signature the
**Node** SDK produced. One implementation, two runtimes.

The page cannot forge identity: the daemon checks the signature, the DID-to-key
binding, freshness and the nonce itself. `client/test/e2e.mjs` also proves the
negative - a card signed by the wrong key is refused.

---

## 5. `serve.mjs` and why there is a proxy

The daemon deliberately sends no CORS headers. `client/serve.mjs` serves the
static files **and** proxies `/api/*` to the daemon with the prefix stripped, so
the page and its API calls share one origin: no CORS, no preflight, no
`Access-Control-Allow-Origin: *`. It is 326 lines of `node:http` and `node:fs`, and
imports nothing outside `node:`.

It sends the content types a browser needs (`text/javascript; charset=utf-8` for
`.js` and `.mjs`, `text/html; charset=utf-8` for `.html`), refuses a path that
escapes the served directory, and reports a daemon it cannot reach as
`502 bad_gateway` with a readable message instead of hanging.

---

## 6. What is verified locally, and how

```console
node client/test/e2e.mjs
```

**Result on the authoring machine (Windows, Node v24.16.0): 81 assertions,
`81 passed, 0 failed`, exit code 0.** The test:

1. rebuilds the daemon with `CARGO_BUILD_JOBS=2` when
   `target/debug/nau-daemon[.exe]` is missing, and reuses it otherwise;
2. starts it on a random free port with `--ephemeral`;
3. starts `client/serve.mjs` against it and checks the static content types and
   the directory-traversal refusal;
4. drives the **full lifecycle over HTTP through the proxy**: deposit, register
   (real signature), discover, publish, bid, match, start, submit, verify (three
   signed votes), settle, then `conservation` + `audit` with `discrepancy 0`,
   plus `stats` and `leaderboard`;
5. asserts a JSON-float deposit is `422`, that `GET /tasks/{id}/settle` is `405`,
   that an unknown amount encoding is `422`, and that a wrong-key signature is
   refused;
6. asserts the browser canonicalizer reproduces every `canonical` byte string in
   `conformance/vectors.json` it can represent, and that a **Node-SDK-produced**
   signature verifies under the browser `crypto.subtle` code path (and fails
   after one tampered field);
7. imports **`client/app.js` itself** under a 267-line DOM stub
   (`client/test/dom-stub.mjs`), which reads the ids, buttons and input defaults
   out of `index.html`, clicks buttons, and checks that the page contacted the
   daemon, rendered the `422` as text, and credited a deposit;
8. greps the sources for the rules that are easy to regress: no `innerHTML`, a
   real CSP, no inline handlers, no bare npm import, and no icon reference that
   points at a file that is not there.

### What is **not** verified - read this before trusting the screenshots you do not have

* **No browser was launched.** This machine has no browser automation available
  and the task forbids claiming otherwise. `client/test/e2e.mjs` exercises the
  page's modules, its HTTP calls and its button handlers under a DOM stub; it does
  not render pixels, run CSS, or execute a real event loop. `crypto.subtle` is
  Node's WebCrypto, which is the same API but not the same build as a browser's.
* **The Tauri shell in `client/src-tauri/` was never compiled** - see section 7.
* The two `int64-max` / `uint64-max` canonical vectors cannot be represented by
  `JSON.parse` at all; the test **reports them as skipped** rather than counting
  them as passing. The `float-value` and `exponent-notation` rejections are
  likewise re-pinned as JavaScript *acceptances*, exactly as the JS SDK does.
* Nothing here has been run against a node behind a real network, only against a
  local `--ephemeral` daemon on `127.0.0.1`.

---

## 7. `client/src-tauri/` - source only, **unbuilt and unverified**

`client/src-tauri/` is a Tauri 2 shell whose Rust side exposes real commands
(`daemon_health`, `market_stats`, `conservation`, `deposit`, `register_agent`)
that perform HTTP calls, with a real CSP in `tauri.conf.json`.

**It has not been built here and is not claimed to work.** The Tauri dependency
tree is large and this machine has already failed a comparable build with
`rustc-LLVM ERROR: out of memory / Allocation failed`, so `cargo build` and
`tauri build` were deliberately not run for it. What *was* run is
`cargo metadata`, which resolved the graph (483 packages, recorded in the
committed `Cargo.lock`) without compiling anything. The **browser client above is
the verified one**. Per-platform local build instructions - including that Linux
needs `webkit2gtk-4.1`, macOS needs Xcode Command Line Tools, and Windows needs
WebView2 and the MSVC build tools - are in `client/platforms/`.

`tauri.conf.json` deliberately declares **no `.icns` and no `.ico`**: upstream's
`desktop/src-tauri/tauri.conf.json:34-35` required `icons/icon.icns` and
`icons/icon.ico`, both gitignored and absent from the repository, so `tauri build`
could never succeed. The three PNGs it does list exist and are generated by
`icons/generate.mjs`; add real artwork (and the `.icns`/`.ico` via
`cargo tauri icon`) before you bundle.

---

## 8. Layout

```
client/
  index.html          the UI (real CSP, no inline handlers)
  app.js              panel wiring; textContent/createElement only
  style.css           the whole stylesheet
  serve.mjs           static server + /api proxy (node:http only)
  lib/canonical.mjs   canonical JSON - shared by the browser and the test
  lib/nau.mjs         Ed25519 identity, signing, domain payloads, HTTP client
  test/e2e.mjs        the end-to-end test described in section 6
  test/dom-stub.mjs   the minimal DOM used to import app.js under Node
  src-tauri/          the unbuilt Tauri 2 shell
  platforms/          per-OS local build notes for that shell
```

## 9. Continuous integration

* `.github/workflows/ci.yml`'s `javascript` job runs `node client/test/e2e.mjs`
  with the pinned Rust toolchain installed, so the browser client is part of the
  normal matrix and a regression fails the build rather than a release.
* `.github/workflows/client.yml` builds the Tauri app **only on a `v*` tag**, and
  its `needs:` chain (`tauri-bundle` needs `gate`, `gate` needs `verify`, and
  `verify` calls `ci.yml`) forbids publishing an artifact that the test suite has
  not passed.
