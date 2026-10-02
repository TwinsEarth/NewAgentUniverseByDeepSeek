//! Tauri build script.
//!
//! `tauri-build` reads `tauri.conf.json`, generates the capability/permission
//! manifest and embeds the platform resources. It must be the build script; a
//! shell that skips it will compile and then fail at run time with a
//! permission error that names nothing useful.

fn main() {
    tauri_build::build();
}
