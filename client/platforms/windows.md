# Building the Tauri shell on Windows

> **This was never built on the authoring machine.** The host is Windows, but
> `cargo build`/`tauri build` was deliberately not attempted for the Tauri crate:
> the dependency tree is large and this machine has already failed a comparable
> build with `rustc-LLVM ERROR: out of memory / Allocation failed` (see
> `client/README.md` section 7). Everything below is the documented local
> procedure, not a verified transcript. **The browser client is the verified one.**

## 1. Prerequisites

* **WebView2 runtime** - the shell is a WebView2 host and will not start without
  it. Windows 11 and up-to-date Windows 10 include it; otherwise install the
  *Evergreen Standalone Installer* from Microsoft. Check with:

  ```powershell
  Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' |
    Select-Object pv
  ```

* **MSVC build tools** - the linker and the Windows SDK. The GNU toolchain is not
  supported by Tauri:

  ```powershell
  rustup default stable-x86_64-pc-windows-msvc
  rustup toolchain install 1.85.0-x86_64-pc-windows-msvc
  where.exe link.exe       # must resolve inside the Visual Studio installation
  ```

  Install *Visual Studio Build Tools* with the "Desktop development with C++"
  workload. If `link.exe` is not on `PATH`, run the build from an
  *x64 Native Tools Command Prompt* or call `vcvars64.bat` first.

* **The Tauri CLI** (no npm project here):

  ```powershell
  cargo install tauri-cli --version "^2" --locked
  ```

* **Node.js 20+** only for `icons/generate.mjs`, which uses `node:zlib` alone.

## 2. Build

```powershell
cd client\src-tauri
cargo build            # Rust side only: fastest way to see real errors
cargo tauri build      # bundle: .msi and .exe under target\release\bundle\
cargo tauri dev        # run it against a live daemon
```

Start a daemon first, in another terminal:

```powershell
cargo build -p nau-node --bin nau-daemon
.\target\debug\nau-daemon.exe --api-port 4002 --ephemeral
```

`NAU_DAEMON_URL` overrides the daemon URL (default `http://127.0.0.1:4002`):

```powershell
$env:NAU_DAEMON_URL = 'http://127.0.0.1:4100'; cargo tauri dev
```

The CSP in `tauri.conf.json` lists `http://127.0.0.1:4002` and
`http://localhost:4002` in `connect-src`; another port must be added there too, or
the WebView blocks the request. Open the WebView's devtools with
**Ctrl+Shift+I** in a dev build to see it.

## 3. Memory

If `rustc` dies with `rustc-LLVM ERROR: out of memory / Allocation failed`, that is
the reason this crate was left unbuilt here. Bound the parallelism, exactly as
`.cargo/config.toml` and CI do:

```powershell
$env:CARGO_BUILD_JOBS = '2'
cargo build -j 2
```

A `[profile.dev]` with `debug = 0`, or `split-debuginfo = "unpacked"`, also cuts
peak memory noticeably on MSVC. Note that this crate sets `[workspace]` in its
`Cargo.toml` on purpose, so the repository root's `cargo build --workspace` never
drags the Tauri tree in.

## 4. Icons

`bundle.icon` lists three checked-in PNGs produced by `icons/generate.mjs`. They
are placeholders. Regenerate the full `.ico`/`.png` set with:

```powershell
cargo tauri icon icons\128x128@2x.png
```

**Do not** reference `icon.ico` in `tauri.conf.json` before it exists. Upstream's
`desktop/src-tauri/tauri.conf.json:34-35` required `icons/icon.icns` and
`icons/icon.ico`, both `.gitignore`d and absent, so `tauri build` could never
succeed.

## 5. Signing (release only)

An unsigned `.msi` triggers SmartScreen on another machine. Signing needs an
Authenticode certificate and `signtool`, configured through
`bundle.windows.certificateThumbprint` (or the `TAURI_SIGNING_*` environment
variables). Not attempted here.

## 6. What to expect instead

```powershell
node client\serve.mjs --port 8080 --daemon http://127.0.0.1:4002
node client\test\e2e.mjs       # 81 assertions, exit 0 on the authoring machine
```
