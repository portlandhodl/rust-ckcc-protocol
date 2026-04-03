// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// ckcc — Coldcard USB protocol library
//
// Communicate with your Coldcard hardware wallet over USB.

pub mod constants;
pub mod protocol;
pub mod sigheader;
pub mod utils;
pub mod client;
pub mod electrum;

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
