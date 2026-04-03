// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// Details of our USB level protocol. Shared file between desktop and embedded.
// Ported from ckcc/protocol.py
//
// - first 4 bytes of all messages is the command code or response code
// - uses little-endian byte order

use crate::constants::*;
use thiserror::Error;

// ─── Error types ───────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum CCError {
    #[error("{0}")]
    ProtoError(String),

    #[error("Framing Error: {0}")]
    FramingError(String),

    #[error("You refused permission to do the operation")]
    UserRefused,

    #[error("Coldcard is handling another request right now")]
    BusyError,

    #[error("Unknown response signature: {0}")]
    UnknownResponse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CCError>;

// ─── Response types ────────────────────────────────────────────────────────────

/// Decoded response from the Coldcard.
#[derive(Debug)]
pub enum CCResponse {
    /// Trivial OK, no content.
    Ok,
    /// Binary data.
    Binary(Vec<u8>),
    /// Single u32.
    Int1(u32),
    /// Two u32 values.
    Int2(u32, u32),
    /// Three u32 values.
    Int3(u32, u32, u32),
    /// ASCII string.
    Ascii(String),
    /// Encryption handshake: (device_pubkey_64, fingerprint, xpub).
    MyPubKey {
        dev_pubkey: Vec<u8>,
        fingerprint: u32,
        xpub: Vec<u8>,
    },
    /// Message signing result: (address, signature_65_bytes).
    SignedMessage { address: String, signature: Vec<u8> },
    /// Transaction signing result: (length, sha256).
    SignedTxn { length: u32, sha256: [u8; 32] },
}

// ─── Protocol Packer ───────────────────────────────────────────────────────────

/// Builds binary command messages to send to the Coldcard.
pub struct CCProtocolPacker;

impl CCProtocolPacker {
    pub fn logout() -> Vec<u8> {
        b"logo".to_vec()
    }

    pub fn reboot() -> Vec<u8> {
        b"rebo".to_vec()
    }

    /// Returns a string with newline separators.
    pub fn version() -> Vec<u8> {
        b"vers".to_vec()
    }

    /// Returns whatever binary you give it.
    pub fn ping(msg: &[u8]) -> Vec<u8> {
        let mut buf = b"ping".to_vec();
        buf.extend_from_slice(msg);
        buf
    }

    pub fn bip39_passphrase(pw: &str) -> Vec<u8> {
        let mut buf = b"pass".to_vec();
        buf.extend_from_slice(pw.as_bytes());
        buf
    }

    /// Poll completion of BIP39 encryption change (provides root xpub).
    pub fn get_passphrase_done() -> Vec<u8> {
        b"pwok".to_vec()
    }

    pub fn check_mitm() -> Vec<u8> {
        b"mitm".to_vec()
    }

    /// Prompts user with password for encrypted backup.
    pub fn start_backup() -> Vec<u8> {
        b"back".to_vec()
    }

    /// Backup file has to be already uploaded.
    ///
    /// - `custom_pwd`: .7z encrypted with custom password
    /// - `plaintext`: clear-text (dev)
    /// - `tmp`: force load as tmp, effective only on seed-less CC
    pub fn restore_backup(
        length: u32,
        file_sha: &[u8; 32],
        custom_pwd: bool,
        plaintext: bool,
        tmp: bool,
    ) -> Vec<u8> {
        assert!(!(custom_pwd && plaintext));
        let mut bf: u8 = 0;
        if custom_pwd {
            bf |= 1;
        }
        if plaintext {
            bf |= 2;
        }
        if tmp {
            bf |= 4;
        }

        let mut buf = b"rest".to_vec();
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(file_sha);
        buf.push(bf);
        buf
    }

    /// Start link-layer encryption.
    ///
    /// `device_pubkey` must be an uncompressed 64-byte pubkey (no prefix byte).
    pub fn encrypt_start(device_pubkey: &[u8], version: u32) -> Vec<u8> {
        let supported = [USB_NCRY_V1, USB_NCRY_V2];
        assert!(
            supported.contains(&version),
            "Unsupported USB encryption version. Supported: {:?}",
            supported
        );
        assert_eq!(
            device_pubkey.len(),
            64,
            "want uncompressed 64-byte pubkey, no prefix byte"
        );

        let mut buf = b"ncry".to_vec();
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(device_pubkey);
        buf
    }

    pub fn upload(offset: u32, total_size: u32, data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= MAX_MSG_LEN, "badlen");
        let mut buf = b"upld".to_vec();
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(&total_size.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    pub fn download(offset: u32, length: u32, file_number: u32) -> Vec<u8> {
        assert!(file_number < 2);
        let mut buf = b"dwld".to_vec();
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&file_number.to_le_bytes());
        buf
    }

    pub fn sha256() -> Vec<u8> {
        b"sha2".to_vec()
    }

    /// Must have already uploaded binary, and give expected sha256.
    pub fn sign_transaction(
        length: u32,
        file_sha: &[u8; 32],
        finalize: bool,
        flags: u32,
        miniscript_name: Option<&str>,
    ) -> Vec<u8> {
        let mut f = flags;
        if finalize {
            f |= STXN_FINALIZE;
        }

        let mut buf = b"stxn".to_vec();
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&f.to_le_bytes());
        buf.extend_from_slice(file_sha);

        if let Some(name) = miniscript_name {
            let name_bytes = name.as_bytes();
            buf.push(name_bytes.len() as u8);
            buf.extend_from_slice(name_bytes);
        }
        buf
    }

    /// Only begins user interaction.
    pub fn sign_message(raw_msg: &[u8], subpath: &str, addr_fmt: u32) -> Vec<u8> {
        let subpath_bytes = subpath.as_bytes();
        let mut buf = b"smsg".to_vec();
        buf.extend_from_slice(&addr_fmt.to_le_bytes());
        buf.extend_from_slice(&(subpath_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(raw_msg.len() as u32).to_le_bytes());
        buf.extend_from_slice(subpath_bytes);
        buf.extend_from_slice(raw_msg);
        buf
    }

    /// Poll completion/results of message signing.
    pub fn get_signed_msg() -> Vec<u8> {
        b"smok".to_vec()
    }

    /// Poll completion/results of backup.
    pub fn get_backup_file() -> Vec<u8> {
        b"bkok".to_vec()
    }

    /// Poll completion/results of transaction signing.
    pub fn get_signed_txn() -> Vec<u8> {
        b"stok".to_vec()
    }

    /// Multisig details must already be uploaded as a text file.
    pub fn multisig_enroll(length: u32, file_sha: &[u8; 32]) -> Vec<u8> {
        let mut buf = b"enrl".to_vec();
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(file_sha);
        buf
    }

    /// List registered miniscript wallet names.
    pub fn miniscript_ls() -> Vec<u8> {
        b"msls".to_vec()
    }

    /// Delete registered miniscript wallet by name.
    pub fn miniscript_delete(name: &str) -> Vec<u8> {
        assert!((2..=40).contains(&name.len()), "name len must be 2..=40");
        let mut buf = b"msdl".to_vec();
        buf.extend_from_slice(name.as_bytes());
        buf
    }

    /// Get registered miniscript wallet object by name.
    pub fn miniscript_get(name: &str) -> Vec<u8> {
        assert!((2..=40).contains(&name.len()), "name len must be 2..=40");
        let mut buf = b"msgt".to_vec();
        buf.extend_from_slice(name.as_bytes());
        buf
    }

    /// Get BIP-388 policy of registered miniscript wallet object by name.
    pub fn miniscript_policy(name: &str) -> Vec<u8> {
        assert!((2..=40).contains(&name.len()), "name len must be 2..=40");
        let mut buf = b"mspl".to_vec();
        buf.extend_from_slice(name.as_bytes());
        buf
    }

    /// Get miniscript address from internal or external chain by id.
    pub fn miniscript_address(name: &str, change: bool, idx: u32) -> Vec<u8> {
        assert!((2..=40).contains(&name.len()), "name len must be 2..=40");
        assert!(idx < (1 << 31), "child idx out of range");
        let mut buf = b"msas".to_vec();
        buf.extend_from_slice(&(change as u32).to_le_bytes());
        buf.extend_from_slice(&idx.to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf
    }

    /// Miniscript details must already be uploaded as a text file.
    pub fn miniscript_enroll(length: u32, file_sha: &[u8; 32]) -> Vec<u8> {
        let mut buf = b"mins".to_vec();
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(file_sha);
        buf
    }

    /// Do we have a wallet already that matches M+N and xor(*xfps)?
    pub fn multisig_check(m: u32, n: u32, xfp_xor: u32) -> Vec<u8> {
        let mut buf = b"msck".to_vec();
        buf.extend_from_slice(&m.to_le_bytes());
        buf.extend_from_slice(&n.to_le_bytes());
        buf.extend_from_slice(&xfp_xor.to_le_bytes());
        buf
    }

    /// Takes a string, like: m/44'/0'/23/23
    pub fn get_xpub(subpath: &str) -> Vec<u8> {
        let mut buf = b"xpub".to_vec();
        buf.extend_from_slice(subpath.as_bytes());
        buf
    }

    /// Shows on screen, no feedback from user expected.
    pub fn show_address(subpath: &str, addr_fmt: u32) -> Vec<u8> {
        assert!(addr_fmt & AFC_SCRIPT == 0);
        let mut buf = b"show".to_vec();
        buf.extend_from_slice(&addr_fmt.to_le_bytes());
        buf.extend_from_slice(subpath.as_bytes());
        buf
    }

    /// For multisig (P2SH) cases.
    ///
    /// - `xfp_paths`: list of (xfp, path_components...) as u32 slices
    /// - `witdeem_script`: the redeem/witness script
    pub fn show_p2sh_address(
        m: u8,
        xfp_paths: &[Vec<u32>],
        witdeem_script: &[u8],
        addr_fmt: u32,
    ) -> Vec<u8> {
        assert!(addr_fmt & AFC_SCRIPT != 0);
        assert!((30..=520).contains(&witdeem_script.len()));

        let mut buf = b"p2sh".to_vec();
        buf.extend_from_slice(&addr_fmt.to_le_bytes());
        buf.push(m);
        buf.push(xfp_paths.len() as u8);
        buf.extend_from_slice(&(witdeem_script.len() as u16).to_le_bytes());
        buf.extend_from_slice(witdeem_script);

        for xfp_path in xfp_paths {
            let ln = xfp_path.len() as u8;
            buf.push(ln);
            for val in xfp_path {
                buf.extend_from_slice(&val.to_le_bytes());
            }
        }

        buf
    }

    /// Ask what blockchain it's set for; expect "BTC" or "XTN".
    pub fn block_chain() -> Vec<u8> {
        b"blkc".to_vec()
    }

    /// Simulator ONLY: pretend a key is pressed.
    pub fn sim_keypress(key: &[u8]) -> Vec<u8> {
        let mut buf = b"XKEY".to_vec();
        buf.extend_from_slice(key);
        buf
    }

    /// One time only: put into bag, or readback bag.
    pub fn bag_number(new_number: &[u8]) -> Vec<u8> {
        let mut buf = b"bagi".to_vec();
        buf.extend_from_slice(new_number);
        buf
    }

    /// Start HSM mode.
    ///
    /// If `length > 0`, new policy already uploaded as JSON file.
    /// Otherwise, use policy on device already.
    pub fn hsm_start(length: u32, file_sha: &[u8]) -> Vec<u8> {
        if length > 0 {
            assert_eq!(file_sha.len(), 32);
            let mut buf = b"hsms".to_vec();
            buf.extend_from_slice(&length.to_le_bytes());
            buf.extend_from_slice(file_sha);
            buf
        } else {
            b"hsms".to_vec()
        }
    }

    /// Get current status of HSM mode. Returns JSON.
    pub fn hsm_status() -> Vec<u8> {
        b"hsts".to_vec()
    }

    /// Create username with pre-shared secret/password, or we generate.
    pub fn create_user(username: &[u8], auth_mode: u8, secret: &[u8]) -> Vec<u8> {
        assert!(
            (1..=MAX_USERNAME_LEN).contains(&username.len()),
            "username length"
        );
        assert!(
            [0, 10, 20, 32].contains(&secret.len()),
            "secret length must be 0, 10, 20, or 32"
        );
        let mut buf = b"nwur".to_vec();
        buf.push(auth_mode);
        buf.push(username.len() as u8);
        buf.push(secret.len() as u8);
        buf.extend_from_slice(username);
        buf.extend_from_slice(secret);
        buf
    }

    /// Remove a username and forget secret.
    pub fn delete_user(username: &[u8]) -> Vec<u8> {
        assert!(
            !username.is_empty() && username.len() <= MAX_USERNAME_LEN,
            "username length"
        );
        let mut buf = b"rmur".to_vec();
        buf.push(username.len() as u8);
        buf.extend_from_slice(username);
        buf
    }

    /// HSM mode: try an authentication method for a username.
    pub fn user_auth(username: &[u8], token: &[u8], totp_time: u32) -> Vec<u8> {
        assert!(
            !username.is_empty() && username.len() <= 16,
            "username length"
        );
        assert!(
            (6..=32).contains(&token.len()),
            "token length must be 6..=32"
        );
        let mut buf = b"user".to_vec();
        buf.extend_from_slice(&totp_time.to_le_bytes());
        buf.push(username.len() as u8);
        buf.push(token.len() as u8);
        buf.extend_from_slice(username);
        buf.extend_from_slice(token);
        buf
    }

    /// Returns up to 414 bytes of user-defined sensitive data.
    pub fn get_storage_locker() -> Vec<u8> {
        b"gslr".to_vec()
    }
}

// ─── Protocol Unpacker ─────────────────────────────────────────────────────────

/// Decodes binary responses from the Coldcard.
pub struct CCProtocolUnpacker;

impl CCProtocolUnpacker {
    /// Decode a full response message (after un-framing).
    pub fn decode(msg: &[u8]) -> Result<CCResponse> {
        if msg.len() < 4 {
            return Err(CCError::FramingError("Message too short".into()));
        }

        let sign = std::str::from_utf8(&msg[0..4]).unwrap_or("????");

        match sign {
            "okay" => {
                if msg.len() != 4 {
                    return Err(CCError::FramingError(
                        "okay response should be 4 bytes".into(),
                    ));
                }
                Ok(CCResponse::Ok)
            }
            "fram" => {
                let text = String::from_utf8_lossy(&msg[4..]);
                Err(CCError::FramingError(text.into_owned()))
            }
            "err_" => {
                let text = String::from_utf8_lossy(&msg[4..]);
                Err(CCError::ProtoError(format!("Coldcard Error: {}", text)))
            }
            "refu" => Err(CCError::UserRefused),
            "busy" => Err(CCError::BusyError),
            "biny" => Ok(CCResponse::Binary(msg[4..].to_vec())),
            "int1" => {
                if msg.len() < 8 {
                    return Err(CCError::FramingError("int1 too short".into()));
                }
                let val = u32::from_le_bytes(msg[4..8].try_into().unwrap());
                Ok(CCResponse::Int1(val))
            }
            "int2" => {
                if msg.len() < 12 {
                    return Err(CCError::FramingError("int2 too short".into()));
                }
                let a = u32::from_le_bytes(msg[4..8].try_into().unwrap());
                let b = u32::from_le_bytes(msg[8..12].try_into().unwrap());
                Ok(CCResponse::Int2(a, b))
            }
            "int3" => {
                if msg.len() < 16 {
                    return Err(CCError::FramingError("int3 too short".into()));
                }
                let a = u32::from_le_bytes(msg[4..8].try_into().unwrap());
                let b = u32::from_le_bytes(msg[8..12].try_into().unwrap());
                let c = u32::from_le_bytes(msg[12..16].try_into().unwrap());
                Ok(CCResponse::Int3(a, b, c))
            }
            "mypb" => {
                // response to "ncry" command:
                // - the (uncompressed) pubkey of the Coldcard (64 bytes)
                // - info about master key: xpub, fingerprint
                // - anti-MitM: remote xpub
                if msg.len() < 4 + 64 + 4 + 4 {
                    return Err(CCError::FramingError("mypb too short".into()));
                }
                let dev_pubkey = msg[4..68].to_vec();
                let fingerprint = u32::from_le_bytes(msg[68..72].try_into().unwrap());
                let xpub_len = u32::from_le_bytes(msg[72..76].try_into().unwrap()) as usize;
                let xpub = if xpub_len > 0 {
                    msg[msg.len() - xpub_len..].to_vec()
                } else {
                    Vec::new()
                };
                Ok(CCResponse::MyPubKey {
                    dev_pubkey,
                    fingerprint,
                    xpub,
                })
            }
            "asci" => {
                let text = String::from_utf8_lossy(&msg[4..]).into_owned();
                Ok(CCResponse::Ascii(text))
            }
            "smrx" => {
                // message signing result
                if msg.len() < 8 {
                    return Err(CCError::FramingError("smrx too short".into()));
                }
                let aln = u32::from_le_bytes(msg[4..8].try_into().unwrap()) as usize;
                let address = String::from_utf8_lossy(&msg[8..8 + aln]).into_owned();
                let signature = msg[8 + aln..].to_vec();
                Ok(CCResponse::SignedMessage { address, signature })
            }
            "strx" => {
                // txn signing result
                if msg.len() < 4 + 4 + 32 {
                    return Err(CCError::FramingError("strx too short".into()));
                }
                let ln = u32::from_le_bytes(msg[4..8].try_into().unwrap());
                let mut sha = [0u8; 32];
                sha.copy_from_slice(&msg[8..40]);
                Ok(CCResponse::SignedTxn {
                    length: ln,
                    sha256: sha,
                })
            }
            _ => Err(CCError::UnknownResponse(sign.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_roundtrip() {
        let msg = b"hello world";
        let packed = CCProtocolPacker::ping(msg);
        assert_eq!(&packed[..4], b"ping");
        assert_eq!(&packed[4..], msg);
    }

    #[test]
    fn test_version_command() {
        let packed = CCProtocolPacker::version();
        assert_eq!(packed, b"vers");
    }

    #[test]
    fn test_decode_okay() {
        let resp = CCProtocolUnpacker::decode(b"okay").unwrap();
        assert!(matches!(resp, CCResponse::Ok));
    }

    #[test]
    fn test_decode_error() {
        let msg = b"err_Something went wrong";
        let resp = CCProtocolUnpacker::decode(msg);
        assert!(resp.is_err());
    }

    #[test]
    fn test_decode_int1() {
        let mut msg = b"int1".to_vec();
        msg.extend_from_slice(&42u32.to_le_bytes());
        let resp = CCProtocolUnpacker::decode(&msg).unwrap();
        match resp {
            CCResponse::Int1(v) => assert_eq!(v, 42),
            _ => panic!("expected Int1"),
        }
    }

    #[test]
    fn test_upload_command() {
        let data = vec![0xAA; 100];
        let packed = CCProtocolPacker::upload(0, 100, &data);
        assert_eq!(&packed[..4], b"upld");
        assert_eq!(u32::from_le_bytes(packed[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(packed[8..12].try_into().unwrap()), 100);
        assert_eq!(&packed[12..], &data[..]);
    }

    #[test]
    fn test_encrypt_start() {
        let pubkey = [0x42u8; 64];
        let packed = CCProtocolPacker::encrypt_start(&pubkey, USB_NCRY_V1);
        assert_eq!(&packed[..4], b"ncry");
        assert_eq!(
            u32::from_le_bytes(packed[4..8].try_into().unwrap()),
            USB_NCRY_V1
        );
        assert_eq!(&packed[8..72], &pubkey[..]);
    }
}

// EOF
