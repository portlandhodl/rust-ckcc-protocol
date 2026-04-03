// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// client.rs
//
// Implement the desktop side of our Coldcard USB protocol.
// Ported from ckcc/client.py

use crate::constants::*;
use crate::protocol::*;
use crate::utils::{decode_xpub, get_pubkey_string};

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use k256::{
    ecdh::EphemeralSecret,
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey,
};
use sha2::{Digest, Sha256};
use std::time::Duration;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Unofficial, unpermissioned USB numbers.
pub const COINKITE_VID: u16 = 0xd13e;
pub const CKCC_PID: u16 = 0xcc10;

/// Default simulator socket path.
pub const DEFAULT_SIM_SOCKET: &str = "/tmp/ckcc-simulator.sock";

// ─── Transport trait ───────────────────────────────────────────────────────────

/// Abstraction over USB HID and Unix socket transports.
pub trait ColdcardTransport {
    fn read(&self, buf: &mut [u8], timeout_ms: Option<u64>) -> Result<usize>;
    fn write(&self, buf: &[u8]) -> Result<usize>;
    fn get_serial_number(&self) -> String;
    fn close(&mut self);
    fn error(&self) -> Option<String>;
}

// ─── HID Transport ─────────────────────────────────────────────────────────────

/// USB HID transport for real Coldcard devices.
pub struct HidTransport {
    device: hidapi::HidDevice,
    serial: String,
}

impl HidTransport {
    /// Open a connection to a Coldcard via USB HID.
    ///
    /// If `serial` is provided, only connect to that specific device.
    pub fn open(api: &hidapi::HidApi, serial: Option<&str>) -> Result<Self> {
        for info in api.device_list() {
            if info.vendor_id() != COINKITE_VID || info.product_id() != CKCC_PID {
                continue;
            }

            let found_serial = info.serial_number().unwrap_or("").to_string();

            if let Some(sn) = serial {
                if sn != found_serial {
                    continue;
                }
            }

            let device = api
                .open_path(info.path())
                .map_err(|e| CCError::Other(format!("Failed to open HID device: {}", e)))?;

            return Ok(HidTransport {
                device,
                serial: found_serial,
            });
        }

        Err(if let Some(sn) = serial {
            CCError::Other(format!("Cannot find Coldcard with serial: {}", sn))
        } else {
            CCError::Other("Could not find Coldcard!".into())
        })
    }
}

impl ColdcardTransport for HidTransport {
    fn read(&self, buf: &mut [u8], timeout_ms: Option<u64>) -> Result<usize> {
        let timeout = timeout_ms.map(|t| t as i32).unwrap_or(-1);
        let n = self
            .device
            .read_timeout(buf, timeout)
            .map_err(|e| CCError::Other(format!("HID read error: {}", e)))?;
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        let n = self
            .device
            .write(buf)
            .map_err(|e| CCError::Other(format!("HID write error: {}", e)))?;
        Ok(n)
    }

    fn get_serial_number(&self) -> String {
        self.serial.clone()
    }

    fn close(&mut self) {
        // hidapi device is closed on drop
    }

    fn error(&self) -> Option<String> {
        None
    }
}

// ─── Unix Simulator Transport ──────────────────────────────────────────────────

/// Unix socket transport for the Coldcard simulator.
pub struct SimulatorTransport {
    socket: std::os::unix::net::UnixDatagram,
    _client_path: String,
}

impl SimulatorTransport {
    /// Connect to the Coldcard simulator via Unix socket.
    pub fn open(socket_path: Option<&str>) -> Result<Self> {
        use std::os::unix::net::UnixDatagram;

        let path = socket_path.unwrap_or(DEFAULT_SIM_SOCKET);
        // Bind to a client-side path
        let client_path = format!("/tmp/ckcc-client-{}-rust.sock", std::process::id());

        // Remove stale socket if it exists
        let _ = std::fs::remove_file(&client_path);

        let sock = UnixDatagram::bind(&client_path)
            .map_err(|e| CCError::Other(format!("Cannot bind client socket: {}", e)))?;

        sock.connect(path)
            .map_err(|_| CCError::Other("Cannot connect to simulator. Is it running?".into()))?;

        Ok(SimulatorTransport {
            socket: sock,
            _client_path: client_path,
        })
    }
}

impl ColdcardTransport for SimulatorTransport {
    fn read(&self, buf: &mut [u8], timeout_ms: Option<u64>) -> Result<usize> {
        if let Some(ms) = timeout_ms {
            self.socket
                .set_read_timeout(Some(Duration::from_millis(ms)))
                .map_err(|e| CCError::Other(format!("Socket timeout error: {}", e)))?;
        } else {
            self.socket
                .set_read_timeout(None)
                .map_err(|e| CCError::Other(format!("Socket timeout error: {}", e)))?;
        }

        match self.socket.recv(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(CCError::Other(format!("Socket read error: {}", e))),
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        // Skip the first byte (HID report number)
        let data = if buf.len() == 65 { &buf[1..] } else { buf };
        self.socket
            .send(data)
            .map(|n| if buf.len() == 65 { n + 1 } else { n })
            .map_err(|e| CCError::Other(format!("Socket write error: {}", e)))
    }

    fn get_serial_number(&self) -> String {
        "F1F1F1F1F1F1".to_string()
    }

    fn close(&mut self) {
        let _ = std::fs::remove_file(&self._client_path);
    }

    fn error(&self) -> Option<String> {
        None
    }
}

impl Drop for SimulatorTransport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self._client_path);
    }
}

// ─── ColdcardDevice ────────────────────────────────────────────────────────────

/// Main interface for communicating with a Coldcard hardware wallet.
pub struct ColdcardDevice {
    transport: Box<dyn ColdcardTransport>,
    pub serial: String,
    pub is_simulator: bool,
    pub ncry_ver: u32,
    pub session_key: Option<[u8; 32]>,
    encrypt_request: Option<Aes256Ctr>,
    decrypt_response: Option<Aes256Ctr>,
    pub master_xpub: Option<String>,
    pub master_fingerprint: u32,
}

impl ColdcardDevice {
    /// Open a connection to a Coldcard device.
    ///
    /// - `serial`: optional serial number or simulator socket path
    /// - `encrypt`: whether to enable link-layer encryption
    /// - `ncry_ver`: encryption version (USB_NCRY_V1 or USB_NCRY_V2)
    /// - `is_simulator`: force simulator mode
    pub fn open(
        serial: Option<&str>,
        encrypt: bool,
        ncry_ver: u32,
        is_simulator: bool,
    ) -> Result<Self> {
        let (transport, found_serial, sim): (Box<dyn ColdcardTransport>, String, bool) =
            if is_simulator || serial.is_some_and(|s| s.contains('/')) {
                let t = SimulatorTransport::open(serial)?;
                let sn = t.get_serial_number();
                (Box::new(t), sn, true)
            } else {
                let api = hidapi::HidApi::new()
                    .map_err(|e| CCError::Other(format!("HID API init failed: {}", e)))?;
                let t = HidTransport::open(&api, serial)?;
                let sn = t.get_serial_number();
                (Box::new(t), sn, false)
            };

        let mut dev = ColdcardDevice {
            transport,
            serial: found_serial,
            is_simulator: sim,
            ncry_ver,
            session_key: None,
            encrypt_request: None,
            decrypt_response: None,
            master_xpub: None,
            master_fingerprint: 0,
        };

        dev.resync()?;

        if encrypt {
            dev.start_encryption(ncry_ver)?;
        }

        Ok(dev)
    }

    /// Close the underlying transport.
    pub fn close(&mut self) {
        self.transport.close();
    }

    /// Flush any pending data and resync the connection.
    pub fn resync(&mut self) -> Result<()> {
        let mut junk = [0u8; 64];

        // Flush anything already waiting
        loop {
            let n = self.transport.read(&mut junk, Some(1))?;
            if n == 0 {
                break;
            }
        }

        // Write a special packet: zero-length data, last packet in sequence
        let mut buf = [0xFFu8; 65];
        buf[0] = 0x00; // report number
        buf[1] = 0x80; // last packet, zero length
        self.transport.write(&buf)?;

        // Flush any response
        loop {
            let n = self.transport.read(&mut junk, Some(1))?;
            if n == 0 {
                break;
            }
        }

        Ok(())
    }

    /// Send a command and receive the response.
    pub fn send_recv(
        &mut self,
        msg: &[u8],
        timeout: Option<u64>,
        force_encrypt: Option<bool>,
    ) -> Result<CCResponse> {
        let timeout = timeout.unwrap_or(3000);

        let mut encrypt = force_encrypt.unwrap_or(self.encrypt_request.is_some());

        if self.encrypt_request.is_none() {
            encrypt = false;
        }

        if self.encrypt_request.is_some() && self.ncry_ver == USB_NCRY_V2 {
            encrypt = true;
        }

        let msg_data = if encrypt {
            let enc = self.encrypt_request.as_mut().unwrap();
            let mut encrypted = msg.to_vec();
            enc.apply_keystream(&mut encrypted);
            encrypted
        } else {
            msg.to_vec()
        };

        assert!(
            msg_data.len() >= 4 && msg_data.len() <= MAX_MSG_LEN,
            "msg length: {}",
            msg_data.len()
        );

        // Send framed packets
        let mut offset = 0;
        let total = msg_data.len();
        while offset < total {
            let here = std::cmp::min(63, total - offset);
            let mut buf = [0u8; 65];
            buf[2..2 + here].copy_from_slice(&msg_data[offset..offset + here]);

            if offset + here == total {
                // Final packet
                buf[1] = (here as u8) | 0x80 | if encrypt { 0x40 } else { 0x00 };
            } else {
                buf[1] = here as u8;
            }

            let rv = self.transport.write(&buf)?;
            assert_eq!(rv, 65);

            offset += here;
        }

        // Collect response
        let mut resp = Vec::new();
        #[allow(unused_assignments)]
        let mut last_flag = 0u8;
        loop {
            let mut buf = [0u8; 64];
            let n = self.transport.read(&mut buf, Some(timeout))?;

            if n == 0 {
                // Retry once
                let n = self.transport.read(&mut buf, Some(timeout))?;
                if n == 0 {
                    return Err(CCError::Other("timeout reading USB EP".into()));
                }
            }

            let flag = buf[0];
            let payload_len = (flag & 0x3F) as usize;
            resp.extend_from_slice(&buf[1..1 + payload_len]);
            last_flag = flag;

            if flag & 0x80 != 0 {
                break;
            }
        }

        // Decrypt if needed
        if last_flag & 0x40 != 0 {
            if let Some(dec) = self.decrypt_response.as_mut() {
                dec.apply_keystream(&mut resp);
            }
        }

        CCProtocolUnpacker::decode(&resp)
    }

    /// Set up link-layer encryption using ECDH key exchange.
    pub fn start_encryption(&mut self, version: u32) -> Result<()> {
        // Generate our ephemeral key pair
        let my_secret = EphemeralSecret::random(&mut rand::thread_rng());
        let my_pubkey = my_secret.public_key();
        let my_pubkey_point = my_pubkey.to_encoded_point(false);
        let my_pubkey_bytes = &my_pubkey_point.as_bytes()[1..]; // skip 0x04 prefix
        assert_eq!(my_pubkey_bytes.len(), 64);

        // Send our pubkey to the device
        let msg = CCProtocolPacker::encrypt_start(my_pubkey_bytes, version);
        let resp = self.send_recv(&msg, None, Some(false))?;

        let (his_pubkey_bytes, fingerprint, xpub_bytes) = match resp {
            CCResponse::MyPubKey {
                dev_pubkey,
                fingerprint,
                xpub,
            } => (dev_pubkey, fingerprint, xpub),
            _ => return Err(CCError::Other("Unexpected response to ncry".into())),
        };

        self.ncry_ver = version;

        // Reconstruct his public key and do ECDH
        assert_eq!(his_pubkey_bytes.len(), 64);
        let mut his_full_pubkey = vec![0x04u8]; // uncompressed prefix
        his_full_pubkey.extend_from_slice(&his_pubkey_bytes);

        let his_pubkey = PublicKey::from_sec1_bytes(&his_full_pubkey)
            .map_err(|e| CCError::Other(format!("Invalid device pubkey: {}", e)))?;

        let shared_point = my_secret.diffie_hellman(&his_pubkey);

        // Session key is SHA256 of the shared point (raw bytes)
        let raw_bytes = shared_point.raw_secret_bytes();
        // We need the full point (x,y) for the hash, but k256 ECDH gives us just x.
        // The Python code hashes x||y. We'll use the shared secret directly via SHA256.
        let mut hasher = Sha256::new();
        hasher.update(raw_bytes);
        let session_key: [u8; 32] = hasher.finalize().into();

        self.session_key = Some(session_key);

        // Capture master key info
        if !xpub_bytes.is_empty() {
            self.master_xpub = Some(String::from_utf8_lossy(&xpub_bytes).into_owned());
        }
        self.master_fingerprint = fingerprint;

        // Set up AES-CTR encryption/decryption
        self.aes_setup(&session_key);

        Ok(())
    }

    /// Set up AES-256-CTR encryption and decryption with the session key.
    fn aes_setup(&mut self, session_key: &[u8; 32]) {
        let iv = [0u8; 16]; // counter starts at zero
        self.encrypt_request = Some(Aes256Ctr::new(session_key.into(), &iv.into()));
        self.decrypt_response = Some(Aes256Ctr::new(session_key.into(), &iv.into()));
    }

    /// Verify the session against MitM attacks using the master xpub.
    pub fn check_mitm(&mut self, expected_xpub: Option<&str>) -> Result<()> {
        let xpub = expected_xpub
            .map(|s| s.to_string())
            .or_else(|| self.master_xpub.clone())
            .ok_or_else(|| CCError::Other("device doesn't have any secrets yet".into()))?;

        let _session_key = self
            .session_key
            .ok_or_else(|| CCError::Other("connection not yet in encrypted mode".into()))?;

        let sig_resp = self.send_recv(&CCProtocolPacker::check_mitm(), Some(5000), None)?;

        let sig_bytes = match sig_resp {
            CCResponse::Binary(b) => b,
            _ => return Err(CCError::Other("Unexpected response to mitm check".into())),
        };

        assert_eq!(sig_bytes.len(), 65);

        let ok = self.mitm_verify(&sig_bytes, &xpub)?;
        if !ok {
            return Err(CCError::Other(
                "Possible active MiTM attack in progress! Incorrect signature.".into(),
            ));
        }

        Ok(())
    }

    /// Verify a MitM signature.
    fn mitm_verify(&self, sig: &[u8], expected_xpub: &str) -> Result<bool> {
        let (pubkey_bytes, _chaincode) = decode_xpub(expected_xpub)
            .map_err(|e| CCError::Other(format!("Failed to decode xpub: {}", e)))?;

        let full_pubkey = get_pubkey_string(&pubkey_bytes)
            .map_err(|e| CCError::Other(format!("Failed to decompress pubkey: {}", e)))?;

        // Build SEC1 uncompressed pubkey (0x04 || x || y)
        let mut sec1_pubkey = vec![0x04u8];
        sec1_pubkey.extend_from_slice(&full_pubkey);

        let vk = VerifyingKey::from_sec1_bytes(&sec1_pubkey)
            .map_err(|e| CCError::Other(format!("Invalid verifying key: {}", e)))?;

        let session_key = self
            .session_key
            .ok_or_else(|| CCError::Other("No session key".into()))?;

        // sig[0] is recovery byte, actual signature is sig[1..65]
        let signature = Signature::from_slice(&sig[1..])
            .map_err(|e| CCError::Other(format!("Invalid signature: {}", e)))?;

        match vk.verify(&session_key, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Upload a file to the Coldcard.
    ///
    /// Returns `(length, sha256)`.
    pub fn upload_file(
        &mut self,
        data: &[u8],
        verify: bool,
        blksize: usize,
    ) -> Result<(usize, [u8; 32])> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let chk: [u8; 32] = hasher.finalize().into();

        let mut offset = 0;
        while offset < data.len() {
            let end = std::cmp::min(offset + blksize, data.len());
            let chunk = &data[offset..end];

            let resp = self.send_recv(
                &CCProtocolPacker::upload(offset as u32, data.len() as u32, chunk),
                None,
                None,
            )?;

            match resp {
                CCResponse::Int1(pos) => {
                    assert_eq!(pos as usize, offset);
                }
                _ => return Err(CCError::Other("Unexpected upload response".into())),
            }

            offset = end;
        }

        if verify {
            let resp = self.send_recv(&CCProtocolPacker::sha256(), None, None)?;
            match resp {
                CCResponse::Binary(rb) => {
                    if rb != chk {
                        return Err(CCError::Other("Checksum wrong during file upload".into()));
                    }
                }
                _ => return Err(CCError::Other("Unexpected sha256 response".into())),
            }
        }

        Ok((data.len(), chk))
    }

    /// Download a file from the Coldcard.
    pub fn download_file(
        &mut self,
        length: usize,
        checksum: &[u8; 32],
        blksize: usize,
        file_number: u32,
    ) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(length);
        let mut hasher = Sha256::new();
        let mut pos = 0;

        while pos < length {
            let here_len = std::cmp::min(blksize, length - pos);
            let resp = self.send_recv(
                &CCProtocolPacker::download(pos as u32, here_len as u32, file_number),
                None,
                None,
            )?;

            match resp {
                CCResponse::Binary(chunk) => {
                    assert!(!chunk.is_empty());
                    hasher.update(&chunk);
                    pos += chunk.len();
                    data.extend_from_slice(&chunk);
                }
                _ => return Err(CCError::Other("Unexpected download response".into())),
            }
        }

        let digest: [u8; 32] = hasher.finalize().into();
        if &digest != checksum {
            return Err(CCError::Other("Checksum wrong during file download".into()));
        }

        Ok(data)
    }

    /// Hash a text password for use in HSM auth protocol.
    pub fn hash_password(&self, text_password: &[u8], v3: bool) -> Vec<u8> {
        use sha2::Sha256 as S256;

        let mut salt_hasher = S256::new();
        salt_hasher.update(b"pepper");
        salt_hasher.update(self.serial.as_bytes());
        let salt: [u8; 32] = salt_hasher.finalize().into();

        let mut output = [0u8; 32];
        if v3 {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                text_password,
                &salt,
                PBKDF2_ITER_COUNT,
                &mut output,
            );
        } else {
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
                text_password,
                &salt,
                PBKDF2_ITER_COUNT,
                &mut output,
            );
        }

        output.to_vec()
    }

    /// Get the firmware version string(s).
    pub fn firmware_version(&mut self) -> Result<Vec<String>> {
        let resp = self.send_recv(&CCProtocolPacker::version(), None, None)?;
        match resp {
            CCResponse::Ascii(s) => Ok(s.split('\n').map(|s| s.to_string()).collect()),
            _ => Err(CCError::Other("Unexpected version response".into())),
        }
    }

    /// Check if the device is running EDGE firmware.
    pub fn is_edge(&mut self) -> Result<bool> {
        let versions = self.firmware_version()?;
        if versions.len() > 1 {
            Ok(versions[1].ends_with('X'))
        } else {
            Ok(false)
        }
    }
}

/// List all connected Coldcard devices.
///
/// Returns a vector of `(serial_number, path)` tuples.
pub fn list_devices() -> Result<Vec<(String, String)>> {
    let api =
        hidapi::HidApi::new().map_err(|e| CCError::Other(format!("HID API init failed: {}", e)))?;

    let mut devices = Vec::new();
    for info in api.device_list() {
        if info.vendor_id() == COINKITE_VID && info.product_id() == CKCC_PID {
            let serial = info.serial_number().unwrap_or("").to_string();
            let path = info.path().to_string_lossy().to_string();
            devices.push((serial, path));
        }
    }

    Ok(devices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(COINKITE_VID, 0xd13e);
        assert_eq!(CKCC_PID, 0xcc10);
    }
}

// EOF
