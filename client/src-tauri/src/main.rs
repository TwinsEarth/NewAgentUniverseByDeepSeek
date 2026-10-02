// Hide the console window on Windows in release builds. Without this a
// `cargo tauri build` on Windows leaves a black terminal behind the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Desktop entry point.
//!
//! All of the logic lives in `nau_client_lib` so that the shell is one line and
//! the mobile entry point can reuse the same builder.

fn main() {
    nau_client_lib::run();
}
