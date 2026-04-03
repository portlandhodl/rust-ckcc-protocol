// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// Electrum wallet file conversion utilities.
// Ported from ckcc/electrum.py

use crate::utils::xfp2str;
use regex::Regex;
use serde_json::{Map, Value};
use std::path::Path;

// ─── Pattern matching ──────────────────────────────────────────────────────────

/// Check if a wallet type string matches the multisig pattern (e.g., "2of3").
pub fn is_multisig_wallet(wallet: &Value) -> bool {
    let pattern = Regex::new(r"^\d+of\d+$").unwrap();
    wallet
        .get("wallet_type")
        .and_then(|v| v.as_str())
        .map(|s| pattern.is_match(s))
        .unwrap_or(false)
}

/// Check if a key matches the multisig wallet key pattern (e.g., "x1/").
pub fn is_multisig_wallet_key(key: &str) -> bool {
    let pattern = Regex::new(r"^x\d+/$").unwrap();
    pattern.is_match(key)
}

/// Check if a keystore is a hardware wallet keystore.
pub fn is_hww_keystore(keystore: &Value) -> bool {
    keystore
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s == "hardware")
        .unwrap_or(false)
}

// ─── Keystore collection ───────────────────────────────────────────────────────

/// Find all hardware keystore objects in a multisig wallet.
pub fn collect_multisig_hww_keystores(wallet: &Value) -> anyhow::Result<Map<String, Value>> {
    if !is_multisig_wallet(wallet) {
        anyhow::bail!("Not an electrum multisig wallet");
    }

    let obj = wallet
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Wallet is not a JSON object"))?;

    let mut result = Map::new();
    for (key, value) in obj {
        if is_multisig_wallet_key(key) && is_hww_keystore(value) {
            result.insert(key.clone(), value.clone());
        }
    }

    Ok(result)
}

/// Find a target keystore in a list of keystores by key equals value.
pub fn multisig_find_target(
    keystores: &Map<String, Value>,
    key: &str,
    value: &str,
) -> anyhow::Result<(String, Value)> {
    let results: Vec<(String, Value)> = keystores
        .iter()
        .filter(|(_, ks)| {
            ks.get(key)
                .and_then(|v| v.as_str())
                .map(|s| s == value)
                .unwrap_or(false)
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    match results.len() {
        0 => anyhow::bail!("Found 0 keystores."),
        1 => Ok(results.into_iter().next().unwrap()),
        n => anyhow::bail!("Found {} keystores.{}:{} is ambiguous", n, key, value),
    }
}

// ─── File path helpers ─────────────────────────────────────────────────────────

/// Append '_cc' suffix to file path, considering one file extension.
pub fn filepath_append_cc(f_path: &str) -> String {
    let path = Path::new(f_path);
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|s| s.to_str());

    let new_name = if let Some(ext) = ext {
        format!("{}_cc.{}", stem, ext)
    } else {
        format!("{}_cc", stem)
    };

    let result = parent.join(&new_name);
    result.to_string_lossy().to_string()
}

// ─── Keystore adjustment ───────────────────────────────────────────────────────

/// Create a new updated version of a keystore for Coldcard.
///
/// If `master_fingerprint` and `master_xpub` are provided (from a connected device),
/// additional validation and fields are set.
pub fn cc_adjust_hww_keystore(
    keystore: &Value,
    master_fingerprint: Option<u32>,
    master_xpub: Option<&str>,
) -> anyhow::Result<Value> {
    if !is_hww_keystore(keystore) {
        anyhow::bail!("Not a hardware wallet type");
    }

    let mut new_keystore = keystore.clone();
    let obj = new_keystore
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Keystore is not a JSON object"))?;

    // 1. Change hw type to coldcard
    obj.insert("hw_type".into(), Value::String("coldcard".into()));

    // 2. Soft device id should be nullified
    obj.insert("soft_device_id".into(), Value::Null);

    // 3. Remove cfg key if exists (ledger specific)
    obj.remove("cfg");

    // 4. Label
    let root_fp = obj
        .get("root_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    obj.insert(
        "label".into(),
        Value::String(format!("Coldcard {}", root_fp)),
    );

    // If device is connected, do additional checks
    if let (Some(xfp), Some(xpub)) = (master_fingerprint, master_xpub) {
        let xfp_str = xfp2str(xfp).to_lowercase();
        if xfp_str != root_fp {
            anyhow::bail!(
                "Fingerprint mismatch! Is this a correct coldcard/wallet file? \
                 Make sure that your bip39 passphrase is in effect (if used). \
                 device fingerprint {}; wallet fingerprint {}",
                xfp_str,
                root_fp
            );
        }

        obj.insert(
            "label".into(),
            Value::String(format!("Coldcard {}", xfp_str)),
        );
        obj.insert("ckcc_xpub".into(), Value::String(xpub.to_string()));
    }

    Ok(new_keystore)
}

/// Update a multisig wallet keystore for Coldcard.
pub fn cc_adjust_multisig_hww_keystore(
    wallet: &mut Value,
    key: &str,
    value: &str,
    master_fingerprint: Option<u32>,
    master_xpub: Option<&str>,
) -> anyhow::Result<()> {
    let keystores = collect_multisig_hww_keystores(wallet)?;
    let (k, keystore) = multisig_find_target(&keystores, key, value)?;
    let new_keystore = cc_adjust_hww_keystore(&keystore, master_fingerprint, master_xpub)?;

    wallet
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Wallet is not a JSON object"))?
        .insert(k, new_keystore);

    Ok(())
}

// ─── Main conversion function ──────────────────────────────────────────────────

/// Convert an Electrum wallet file to use Coldcard.
///
/// - `wallet_str`: JSON string of the wallet file
/// - `master_fingerprint`: optional fingerprint from connected device
/// - `master_xpub`: optional master xpub from connected device
/// - `key`/`val`: for multisig, specify which keystore to convert
pub fn convert2cc(
    wallet_str: &str,
    master_fingerprint: Option<u32>,
    master_xpub: Option<&str>,
    key: Option<&str>,
    val: Option<&str>,
) -> anyhow::Result<String> {
    let mut wallet: Value = serde_json::from_str(wallet_str)?;

    let wallet_type = wallet
        .get("wallet_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if wallet_type == "standard" {
        let keystore = wallet
            .get("keystore")
            .ok_or_else(|| anyhow::anyhow!("No keystore in wallet"))?
            .clone();
        let new_keystore = cc_adjust_hww_keystore(&keystore, master_fingerprint, master_xpub)?;
        wallet
            .as_object_mut()
            .unwrap()
            .insert("keystore".into(), new_keystore);
    } else if is_multisig_wallet(&wallet) {
        match (key, val, master_fingerprint) {
            (None, None, None) => {
                anyhow::bail!("--key and --val have to be specified for multisig wallets");
            }
            (None, None, Some(xfp)) => {
                // Auto-detect by fingerprint
                cc_adjust_multisig_hww_keystore(
                    &mut wallet,
                    "root_fingerprint",
                    &xfp2str(xfp).to_lowercase(),
                    master_fingerprint,
                    master_xpub,
                )?;
            }
            (Some(k), Some(v), _) => {
                cc_adjust_multisig_hww_keystore(
                    &mut wallet,
                    k,
                    v,
                    master_fingerprint,
                    master_xpub,
                )?;
            }
            _ => {
                anyhow::bail!("Both --key and --val must be specified together");
            }
        }
    } else {
        anyhow::bail!("Unsupported wallet type: {}", wallet_type);
    }

    Ok(serde_json::to_string(&wallet)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_multisig_wallet() {
        let valid = vec!["2of3", "2of2", "35of50"];
        for v in valid {
            let wallet = serde_json::json!({"wallet_type": v});
            assert!(is_multisig_wallet(&wallet), "should be multisig: {}", v);
        }

        let invalid = vec!["a2of3", "2ofo3", "2of3a", "aaa", "x", "of"];
        for v in invalid {
            let wallet = serde_json::json!({"wallet_type": v});
            assert!(
                !is_multisig_wallet(&wallet),
                "should not be multisig: {}",
                v
            );
        }
    }

    #[test]
    fn test_is_multisig_wallet_key() {
        let valid = vec!["x1/", "x2/", "x30/", "x156/"];
        for v in valid {
            assert!(is_multisig_wallet_key(v), "should match: {}", v);
        }

        let invalid = vec!["1/", "x/", "xxxx", "aaa", "x", "of", "ax1/", "x1/a", "x1a/"];
        for v in invalid {
            assert!(!is_multisig_wallet_key(v), "should not match: {}", v);
        }
    }

    #[test]
    fn test_filepath_append_cc() {
        assert_eq!(filepath_append_cc("ledger_wallet"), "ledger_wallet_cc");
        assert_eq!(
            filepath_append_cc("ledger_wallet.json"),
            "ledger_wallet_cc.json"
        );
        assert_eq!(
            filepath_append_cc("ledger wallet.json"),
            "ledger wallet_cc.json"
        );
        assert_eq!(filepath_append_cc("/ledger_wallet"), "/ledger_wallet_cc");
        assert_eq!(
            filepath_append_cc("/tmp/.../ledger_wallet"),
            "/tmp/.../ledger_wallet_cc"
        );
        assert_eq!(
            filepath_append_cc("/user/local/h.ledger.wallet"),
            "/user/local/h.ledger_cc.wallet"
        );
    }

    #[test]
    fn test_cc_adjust_hww_keystore() {
        let keystore = serde_json::json!({
            "type": "hardware",
            "hw_type": "ledger",
            "root_fingerprint": "aabbccdd",
            "soft_device_id": "some-id",
            "label": "Ledger",
            "cfg": {"some": "config"}
        });

        let result = cc_adjust_hww_keystore(&keystore, None, None).unwrap();
        assert_eq!(result["hw_type"], "coldcard");
        assert_eq!(result["soft_device_id"], Value::Null);
        assert!(result.get("cfg").is_none());
        assert_eq!(result["label"], "Coldcard aabbccdd");
    }
}

// EOF
