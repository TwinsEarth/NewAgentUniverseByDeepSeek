# Building the Tauri shell on Linux

> **This was never built on the authoring machine.** No Linux host was available
> and no `cargo build`/`tauri build` was attempted for the Tauri crate at all
> (see `client/README.md` section 7). Everything below is the documented local
> procedure, not a verified transcript. **The browser client is the verified one.**

## 1. Prerequisites

* **`webkit2gtk`** - the WebView Tauri uses on Linux. Without the development
  package the build stops in a `pkg-config` error naming `webkit2gtk-4.1`, which
  is the single most common first failure:

  ```sh
  # Debian / Ubuntu
  sudo apt update
  sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
                      librsvg2-dev patchelf build-essential curl wget file libssl-dev

  # Fedora
  sudo dnf install -y webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel \
                      librsvg2-devel openssl-devel

  # Arch
  sudo pacman -S --needed webkit2gtk-4.1 gtk3 libappindicator-gtk3 librsvg openssl
  ```

  Confirm it is visible to `pkg-config` before blaming Rust:

  ```sh
  pkg-config --modversion webkit2gtk-4.1     # must print a version
  ```

  Tauri 2 needs **`4.1`**, not the `4.0` that older guides mention. Ubuntu 22.04
  ships 4.1; older releases may force you onto a newer distribution.

* **Rust 1.85** (the workspace floor, for the edition-2024 crates in the tree):

  ```sh
  rustup toolchain install 1.85.0
  rustup default 1.85.0
  ```

* **The Tauri CLI** (no npm project here):

  ```sh
  cargo install tauri-cli --version "^2" --locked
  ```

* **Node.js 20+** only for `icons/generate.mjs`, which uses `node:zlib` alone.

* **A display.** `cargo tauri dev` needs an X11 or Wayland session. On a headless
  machine, run it under `xvfb-run -a cargo tauri dev`; a WebView that cannot open
  a display fails with `Failed to initialize GTK`.

## 2. Build

```sh
cd client/src-tauri
cargo build            # Rust side only: fastest way to see real errors
cargo tauri build      # bundle: .deb / .rpm / .AppImage under target/release/bundle/
cargo tauri dev        # run it against a live daemon
```

Start a daemon first, in another terminal:

```sh
cargo build -p nau-node --bin nau-daemon
./target/debug/nau-daemon --api-port 4002 --ephemeral
```

`NAU_DAEMON_URL` overrides the daemon URL (default `http://127.0.0.1:4002`):

```sh
NAU_DAEMON_URL=http://127.0.0.1:4100 cargo tauri dev
```

The CSP in `tauri.conf.json` lists `http://127.0.0.1:4002` and
`http://localhost:4002` in `connect-src`; another port must be added there too, or
the WebView blocks the request. In a dev build, right-click and choose
*Inspect Element* to open the WebKit inspector.

## 3. Memory

If `rustc` dies with `rustc-LLVM ERROR: out of memory / Allocation failed`, bound
the parallelism, exactly as `.cargo/config.toml` and CI do:

```sh
CARGO_BUILD_JOBS=2 cargo build -j 2
```

This crate sets `[workspace]` in its `Cargo.toml` on purpose, so the repository
root's `cargo build --workspace` never pulls the Tauri tree in.

## 4. Icons

`bundle.icon` lists three checked-in PNGs produced by `icons/generate.mjs`. They
are placeholders. Regenerate the full set (`.png`, `.ico`, `.icns`) with:

```sh
cargo tauri icon icons/128x128@2x.png
```

AppImage bundling additionally needs `linuxdeploy` and `patchelf`; Tauri downloads
`linuxdeploy` on first use, which needs network access.

## 5. Packaging notes

* `.deb` and `.rpm` metadata comes from `bundle.linux.*`; it is not set here, so
  the CLI's defaults apply.
* The AppImage is the only artifact that runs on a distribution other than the
  one that built it, and it still needs a WebKitGTK runtime on the target.
* Signing is not attempted here.

## 6. What to expect instead

```sh
node client/serve.mjs --port 8080 --daemon http://127.0.0.1:4002
node client/test/e2e.mjs       # 81 assertions, exit 0 on the authoring machine
```
