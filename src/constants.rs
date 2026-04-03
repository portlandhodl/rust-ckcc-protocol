// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// Constants and various "limits" shared between embedded and desktop USB protocol.
// Ported from ckcc/constants.py

// ─── USB encryption versions ───────────────────────────────────────────────────
//
// USB_NCRY_V1 is the default.
//
// USB_NCRY_V2 closes a potential attack vector where a malicious program may
// re-initialize the connection encryption by sending the ncry command a second
// time during USB operation.
//
// Sending version USB_NCRY_V2 changes the behavior in two ways:
//   * All future commands must be encrypted
//   * Returns an error if the ncry command is sent again for the duration of the power cycle
//
// USB_NCRY_V2 is most suitable for HSM mode — Coldcard will need to reboot to
// recover USB operation if USB_NCRY_V2.
pub const USB_NCRY_V1: u32 = 0x01;
pub const USB_NCRY_V2: u32 = 0x02;

// ─── Upload / download block sizes ─────────────────────────────────────────────

/// Max size of the data block for upload/download.
pub const MAX_BLK_LEN: usize = 2048;

/// Max total message length, excluding framing overhead (1 byte per 64).
/// Includes args for upload command.
pub const MAX_MSG_LEN: usize = 4 + 4 + 4 + MAX_BLK_LEN;

// ─── PSBT / transaction limits ─────────────────────────────────────────────────

/// Max PSBT txn we support (384k bytes as PSBT).
pub const MAX_TXN_LEN: usize = 384 * 1024;
pub const MAX_TXN_LEN_MK4: usize = 2 * 1024 * 1024;

/// Max size of any upload (firmware.dfu files in particular).
pub const MAX_UPLOAD_LEN: usize = 2 * MAX_TXN_LEN;
pub const MAX_UPLOAD_LEN_MK4: usize = 2 * MAX_TXN_LEN_MK4;

/// Max length of text messages for signing.
pub const MSG_SIGNING_MAX_LENGTH: usize = 240;

// ─── Multisig limits ───────────────────────────────────────────────────────────

/// Bitcoin limitation: max number of signatures in P2SH redeem script (non-segwit).
pub const MAX_SIGNERS: usize = 15;

/// Taproot artificial multisig limit.
pub const MAX_TR_SIGNERS: usize = 34;

pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

// ─── User auth types ───────────────────────────────────────────────────────────

/// RFC6238 TOTP
pub const USER_AUTH_TOTP: u8 = 1;
/// RFC4226 HOTP
pub const USER_AUTH_HOTP: u8 = 2;
/// PBKDF2('hmac-sha512', scrt, sha256(psbt), PBKDF2_ITER_COUNT)[:32]
pub const USER_AUTH_HMAC: u8 = 3;
/// Show secret on Coldcard screen (best for TOTP enroll)
pub const USER_AUTH_SHOW_QR: u8 = 0x80;

pub const MAX_USERNAME_LEN: usize = 16;
pub const PBKDF2_ITER_COUNT: u32 = 2500;

// ─── Derivation path limits ────────────────────────────────────────────────────

/// Max depth for derived keys, in PSBT files, and USB commands.
pub const MAX_PATH_DEPTH: usize = 12;

// ─── Sign-transaction flags (stxn command) ─────────────────────────────────────

pub const STXN_FINALIZE: u32 = 0x01;
pub const STXN_VISUALIZE: u32 = 0x02;
pub const STXN_SIGNED: u32 = 0x04;
pub const STXN_FLAGS_MASK: u32 = 0x07;

// ─── Address format component bits ─────────────────────────────────────────────

pub const AFC_PUBKEY: u32 = 0x01;
pub const AFC_SEGWIT: u32 = 0x02;
pub const AFC_BECH32: u32 = 0x04;
pub const AFC_SCRIPT: u32 = 0x08;
pub const AFC_WRAPPED: u32 = 0x10;
pub const AFC_BECH32M: u32 = 0x20;

// ─── Numeric codes for specific address types ──────────────────────────────────

/// p2pk bare public key address
pub const AF_BARE_PK: u32 = 0x00;
/// 1addr — classic P2PKH
pub const AF_CLASSIC: u32 = AFC_PUBKEY;
/// classic multisig / simple P2SH / 3hash
pub const AF_P2SH: u32 = AFC_SCRIPT;
/// bc1qsdklfj — native segwit
pub const AF_P2WPKH: u32 = AFC_PUBKEY | AFC_SEGWIT | AFC_BECH32;
/// segwit multisig
pub const AF_P2WSH: u32 = AFC_SCRIPT | AFC_SEGWIT | AFC_BECH32;
/// looks classic P2SH, but p2wpkh inside
pub const AF_P2WPKH_P2SH: u32 = AFC_WRAPPED | AFC_PUBKEY | AFC_SEGWIT;
/// looks classic P2SH, segwit multisig
pub const AF_P2WSH_P2SH: u32 = AFC_WRAPPED | AFC_SCRIPT | AFC_SEGWIT;
/// bc1p — taproot
pub const AF_P2TR: u32 = AFC_PUBKEY | AFC_SEGWIT | AFC_BECH32M;

/// All supported address formats.
pub const SUPPORTED_ADDR_FORMATS: &[u32] = &[
    AF_CLASSIC,
    AF_P2SH,
    AF_P2WPKH,
    AF_P2TR,
    AF_P2WSH,
    AF_P2WPKH_P2SH,
    AF_P2WSH_P2SH,
];

// ─── BIP-174 / PSBT defined values ────────────────────────────────────────────

// GLOBAL
pub const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
pub const PSBT_GLOBAL_XPUB: u8 = 0x01;
pub const PSBT_GLOBAL_VERSION: u8 = 0xfb;
pub const PSBT_GLOBAL_PROPRIETARY: u8 = 0xfc;
// BIP-370
pub const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
pub const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
pub const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
pub const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
pub const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;

// INPUTS
pub const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
pub const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
pub const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
pub const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
pub const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
pub const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
pub const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
pub const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
pub const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
pub const PSBT_IN_POR_COMMITMENT: u8 = 0x09;
pub const PSBT_IN_RIPEMD160: u8 = 0x0a;
pub const PSBT_IN_SHA256: u8 = 0x0b;
pub const PSBT_IN_HASH160: u8 = 0x0c;
pub const PSBT_IN_HASH256: u8 = 0x0d;
// BIP-370
pub const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
pub const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
pub const PSBT_IN_SEQUENCE: u8 = 0x10;
pub const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
pub const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
// BIP-371
pub const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
pub const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
pub const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
pub const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;

pub const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1a;
pub const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1b;
pub const PSBT_IN_MUSIG2_PARTIAL_SIG: u8 = 0x1c;

// OUTPUTS
pub const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
pub const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
pub const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
// BIP-370
pub const PSBT_OUT_AMOUNT: u8 = 0x03;
pub const PSBT_OUT_SCRIPT: u8 = 0x04;
// BIP-371
pub const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
pub const PSBT_OUT_TAP_TREE: u8 = 0x06;
pub const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
pub const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x08;

// ─── RFC signature template ────────────────────────────────────────────────────

pub const RFC_SIGNATURE_TEMPLATE: &str = "\
-----BEGIN BITCOIN SIGNED MESSAGE-----
{msg}
-----BEGIN BITCOIN SIGNATURE-----
{addr}
{sig}
-----END BITCOIN SIGNATURE-----
";

/// Format the RFC signature template with the given values.
pub fn format_rfc_signature(msg: &str, addr: &str, sig: &str) -> String {
    RFC_SIGNATURE_TEMPLATE
        .replace("{msg}", msg)
        .replace("{addr}", addr)
        .replace("{sig}", sig)
}

// EOF
