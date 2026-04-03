// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// Utility functions ported from ckcc/utils.py

use crate::constants::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

/// Convert bytes to hex string.
pub fn b2a(data: &[u8]) -> String {
    hex::encode(data)
}

/// Standardized way to show an xpub's fingerprint.
/// It's a 4-byte string and not really an integer.
pub fn xfp2str(xfp: u32) -> String {
    hex::encode(xfp.to_le_bytes()).to_uppercase()
}

// ─── DFU parsing ───────────────────────────────────────────────────────────────

/// Parse a DFU file to find the start offset and length of the main binary.
///
/// Returns `(offset, size)` pairs for each element found.
/// Only supports what ../stm32/Makefile generates.
pub fn dfu_parse<R: Read + Seek>(fd: &mut R) -> anyhow::Result<Vec<(u64, u32)>> {
    fd.seek(SeekFrom::Start(0))?;

    // DFU prefix: signature(5) + version(1) + size(4) + targets(1) = 11 bytes
    let mut prefix_buf = [0u8; 11];
    fd.read_exact(&mut prefix_buf)?;

    let signature = &prefix_buf[0..5];
    anyhow::ensure!(signature == b"DfuSe", "Not a DFU file (bad magic)");

    let _version = prefix_buf[5];
    let _size = u32::from_le_bytes(prefix_buf[6..10].try_into()?);
    let targets = prefix_buf[10];

    let mut results = Vec::new();

    for _ in 0..targets {
        // Target prefix: signature(6) + altsetting(1) + named(1) + name(255) + size(4) + elements(4) = 274 bytes
        let mut target_buf = [0u8; 274];
        fd.read_exact(&mut target_buf)?;

        let elements = u32::from_le_bytes(target_buf[270..274].try_into()?);

        for _ in 0..elements {
            // Element: address(4) + size(4) = 8 bytes
            let mut elem_buf = [0u8; 8];
            fd.read_exact(&mut elem_buf)?;

            let addr = u32::from_le_bytes(elem_buf[0..4].try_into()?);
            let size = u32::from_le_bytes(elem_buf[4..8].try_into()?);

            // Assume bootloader at least 32k, and targeting flash.
            anyhow::ensure!(addr >= 0x8008000, "Bad address?");

            let offset = fd.stream_position()?;
            results.push((offset, size));

            // Skip past the element data
            fd.seek(SeekFrom::Current(size as i64))?;
        }
    }

    Ok(results)
}

// ─── Base58 / xpub decoding ────────────────────────────────────────────────────

const B58_DIGITS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode an xpub string (base58) and return (pubkey_33_bytes, chaincode_32_bytes).
///
/// Adapted from python-bitcoinlib.
pub fn decode_xpub(s: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    anyhow::ensure!(s.len() > 4 && &s[1..4] == "pub", "Not an xpub string");

    // Convert base58 string to a big integer (as bytes)
    let mut n = vec![0u8]; // start with zero
    for c in s.chars() {
        let digit = B58_DIGITS
            .find(c)
            .ok_or_else(|| anyhow::anyhow!("Character '{}' is not a valid base58 character", c))?;

        // Multiply n by 58 and add digit
        let mut carry = digit;
        for byte in n.iter_mut().rev() {
            let val = (*byte as usize) * 58 + carry;
            *byte = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        while carry > 0 {
            n.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Add leading zero bytes for leading '1' characters
    let mut pad = 0;
    for c in s.chars() {
        if c == '1' {
            pad += 1;
        } else {
            break;
        }
    }

    let mut decoded = vec![0u8; pad];
    decoded.extend_from_slice(&n);

    // Get the pubkey (last 37 bytes minus last 4 checksum bytes = 33 bytes)
    // and chaincode (32 bytes before pubkey)
    anyhow::ensure!(decoded.len() >= 69 + 4, "xpub too short");

    let pubkey = decoded[decoded.len() - 37..decoded.len() - 4].to_vec();
    let chaincode = decoded[decoded.len() - 69..decoded.len() - 37].to_vec();

    Ok((pubkey, chaincode))
}

/// Decompress a SEC1 compressed public key (33 bytes) to uncompressed (64 bytes, no prefix).
pub fn get_pubkey_string(b: &[u8]) -> anyhow::Result<Vec<u8>> {
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::One;

    anyhow::ensure!(b.len() == 33, "Expected 33-byte compressed pubkey");

    // secp256k1 field prime
    let p = {
        let mut bytes = [0xFFu8; 32];
        bytes[28] = 0xFE;
        bytes[29] = 0xFF;
        bytes[30] = 0xFC;
        bytes[31] = 0x2F;
        BigUint::from_bytes_be(&bytes)
    };

    let x = BigUint::from_bytes_be(&b[1..]);
    let seven = BigUint::from(7u32);
    let three = BigUint::from(3u32);

    // y^2 = x^3 + 7 (mod p)
    let x_cubed = x.modpow(&three, &p);
    let rhs = (&x_cubed + &seven) % &p;

    // y = rhs^((p+1)/4) mod p
    let exp = (&p + BigUint::one()) / BigUint::from(4u32);
    let mut y = rhs.modpow(&exp, &p);

    // Ensure parity matches
    let y_parity = if y.is_odd() { 1u8 } else { 0u8 };
    let prefix_parity = b[0] & 1;
    if y_parity != prefix_parity {
        y = &p - &y;
    }

    let x_bytes = to_32_bytes(&x);
    let y_bytes = to_32_bytes(&y);

    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&x_bytes);
    result.extend_from_slice(&y_bytes);
    Ok(result)
}

/// Helper: convert BigUint to exactly 32 bytes (big-endian, zero-padded).
fn to_32_bytes(n: &num_bigint::BigUint) -> [u8; 32] {
    let bytes = n.to_bytes_be();
    let mut result = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    result[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    result
}

// ─── HSM local pincode ─────────────────────────────────────────────────────────

/// In HSM mode, generate the next 6-digit code for the local user.
///
/// - `next_local_code` comes from the hsm_status response (base64 encoded)
/// - `psbt_sha` is sha256() over the binary PSBT you will be submitting
pub fn calc_local_pincode(psbt_sha: &[u8; 32], next_local_code: &str) -> anyhow::Result<String> {
    use base64::Engine;
    use hmac::{Hmac, Mac};

    let key = base64::engine::general_purpose::STANDARD.decode(next_local_code)?;
    anyhow::ensure!(key.len() >= 15, "local code key too short");

    let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
    mac.update(psbt_sha);
    let digest = mac.finalize().into_bytes();

    let num = u32::from_be_bytes(digest[28..32].try_into()?) & 0x7fff_ffff;
    Ok(format!("{:06}", num % 1_000_000))
}

// ─── Descriptor template ───────────────────────────────────────────────────────

/// Generate a descriptor template for multisig wallets.
pub fn descriptor_template(
    xfp: &str,
    xpub: &str,
    path: &str,
    fmt: u32,
    m: Option<&str>,
) -> Option<String> {
    let m_str = m.unwrap_or("M");
    let key_exp = format!(
        "[{}{}]{}/0/*",
        xfp.to_lowercase(),
        path.replace("m", ""),
        xpub
    );

    let template = match fmt {
        AF_P2SH => format!("sh(sortedmulti({},{},...))", m_str, key_exp),
        AF_P2WSH_P2SH => format!("sh(wsh(sortedmulti({},{},...)))", m_str, key_exp),
        AF_P2WSH => format!("wsh(sortedmulti({},{},...))", m_str, key_exp),
        _ => return None,
    };

    Some(template)
}

// ─── Address format helper ─────────────────────────────────────────────────────

/// Determine address format and default derivation path based on flags.
///
/// Returns `(addr_fmt, derivation_path)`.
pub fn addr_fmt_help(
    master_xpub: Option<&str>,
    wrap: bool,
    segwit: bool,
    taproot: bool,
) -> (u32, String) {
    let chain = if let Some(xpub) = master_xpub {
        if xpub.starts_with('t') {
            1
        } else {
            0
        }
    } else {
        0
    };

    if wrap {
        (AF_P2WPKH_P2SH, format!("m/49h/{}h/0h/0/0", chain))
    } else if segwit {
        (AF_P2WPKH, format!("m/84h/{}h/0h/0/0", chain))
    } else if taproot {
        (AF_P2TR, format!("m/86h/{}h/0h/0/0", chain))
    } else {
        (AF_CLASSIC, format!("m/44h/{}h/0h/0/0", chain))
    }
}

// ─── Base64url encoding ────────────────────────────────────────────────────────

/// URL-safe base64 encoding without padding.
/// See <https://datatracker.ietf.org/doc/html/rfc4648#section-5>
pub fn b2a_base64url(s: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}

// ─── PushTx URL builder ────────────────────────────────────────────────────────

/// Build a PushTx URL for broadcasting a transaction.
pub fn txn_to_pushtx_url(
    txn: &[u8],
    base_url: &str,
    sha: Option<&[u8]>,
    chain: &str,
    verify_sha: bool,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        base_url.contains("http://") || base_url.contains("https://"),
        "url schema required"
    );
    anyhow::ensure!(
        base_url.ends_with('#') || base_url.ends_with('?') || base_url.ends_with('&'),
        "Final char must be # or ? or &."
    );

    let mut url = base_url.to_string();
    url.push_str("t=");
    url.push_str(&b2a_base64url(txn));

    let computed_sha = {
        let mut hasher = Sha256::new();
        hasher.update(txn);
        hasher.finalize()
    };

    let sha_bytes = if let Some(s) = sha {
        if verify_sha {
            anyhow::ensure!(s == computed_sha.as_slice(), "wrong hash");
        }
        s
    } else {
        computed_sha.as_slice()
    };

    url.push_str("&c=");
    url.push_str(&b2a_base64url(&sha_bytes[sha_bytes.len() - 8..]));

    if chain != "BTC" {
        url.push_str("&n=");
        url.push_str(chain); // XTN or XRT
    }

    Ok(url)
}

// ─── Path parsing ──────────────────────────────────────────────────────────────

/// Convert text path like `m/34'/33/44` into BIP174 binary compat format.
///
/// Returns a vector of u32 values where the first element is the fingerprint
/// and subsequent elements are the path components (with hardened bit set as needed).
pub fn str_to_int_path(xfp_hex: &str, path: &str) -> anyhow::Result<Vec<u32>> {
    let xfp_bytes = hex::decode(xfp_hex)?;
    anyhow::ensure!(xfp_bytes.len() == 4, "XFP must be 4 bytes");
    let xfp = u32::from_le_bytes(xfp_bytes.try_into().unwrap());

    let mut rv = vec![xfp];

    for component in path.split('/') {
        if component == "m" || component.is_empty() {
            continue;
        }

        let (num_str, hardened) = if component.ends_with('\'')
            || component.ends_with('p')
            || component.ends_with('h')
            || component.ends_with('H')
            || component.ends_with('P')
        {
            (&component[..component.len() - 1], true)
        } else {
            (component, false)
        };

        let num: u32 = num_str.parse()?;
        if hardened {
            rv.push(num | 0x8000_0000);
        } else {
            anyhow::ensure!(num < 0x8000_0000, "path component out of range");
            rv.push(num);
        }
    }

    Ok(rv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xfp2str() {
        assert_eq!(xfp2str(0x12345678), "78563412");
    }

    #[test]
    fn test_b2a() {
        assert_eq!(b2a(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn test_addr_fmt_help_default() {
        let (fmt, path) = addr_fmt_help(None, false, false, false);
        assert_eq!(fmt, AF_CLASSIC);
        assert_eq!(path, "m/44h/0h/0h/0/0");
    }

    #[test]
    fn test_addr_fmt_help_segwit() {
        let (fmt, path) = addr_fmt_help(None, false, true, false);
        assert_eq!(fmt, AF_P2WPKH);
        assert_eq!(path, "m/84h/0h/0h/0/0");
    }

    #[test]
    fn test_addr_fmt_help_taproot() {
        let (fmt, path) = addr_fmt_help(None, false, false, true);
        assert_eq!(fmt, AF_P2TR);
        assert_eq!(path, "m/86h/0h/0h/0/0");
    }

    #[test]
    fn test_addr_fmt_help_testnet() {
        let (fmt, path) = addr_fmt_help(Some("tpub..."), false, true, false);
        assert_eq!(fmt, AF_P2WPKH);
        assert_eq!(path, "m/84h/1h/0h/0/0");
    }

    #[test]
    fn test_descriptor_template_p2wsh() {
        let result = descriptor_template("AABBCCDD", "xpub123", "m/48'", AF_P2WSH, Some("2"));
        assert!(result.is_some());
        let desc = result.unwrap();
        assert!(desc.starts_with("wsh(sortedmulti(2,"));
        assert!(desc.contains("aabbccdd"));
    }

    #[test]
    fn test_str_to_int_path() {
        let result = str_to_int_path("AABBCCDD", "m/44'/0'/0'").unwrap();
        assert_eq!(result.len(), 4); // xfp + 3 components
        assert_eq!(result[1], 44 | 0x8000_0000);
        assert_eq!(result[2], 0x8000_0000);
        assert_eq!(result[3], 0x8000_0000);
    }

    #[test]
    fn test_b2a_base64url() {
        let data = b"hello world";
        let encoded = b2a_base64url(data);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }
}

// EOF
