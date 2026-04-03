// Autogen'ed file, don't edit. See stm32/sigheader.h for original
//
// (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
// Ported from ckcc/sigheader.py

/// Our simple firmware header size in bytes.
pub const FW_HEADER_SIZE: usize = 128;

/// Offset of the header within the firmware image (at start of firmware + 16k - sizeof(header)).
pub const FW_HEADER_OFFSET: usize = 0x4000 - FW_HEADER_SIZE;

/// Magic value expected at the start of the firmware header.
pub const FW_HEADER_MAGIC: u32 = 0xCC001234;

// ─── Firmware image size limits ────────────────────────────────────────────────

/// Arbitrary minimum firmware size.
pub const FW_MIN_LENGTH: usize = 256 * 1024;

/// (mk1-3) absolute max size: 1MB flash - 32k for bootloader = 1,015,808
/// Practical limit for our-protocol USB upgrades: 786432 (or else settings damaged).
pub const FW_MAX_LENGTH: usize = 0x100000 - 0x8000;

/// For Mk4: 2Mbytes, less bootrom of 128k.
pub const FW_MAX_LENGTH_MK4: usize = 0x200000 - 0x20000;

// ─── Struct format for Python's struct module (reference) ──────────────────────
// FWH_PY_FORMAT = "<I8s8sIIII8s20s64s"
// FWH_PY_VALUES = "magic_value timestamp version_string pubkey_num firmware_length
//                  install_flags hw_compat best_ts future signature"

/// Number of future fields in the header.
pub const FWH_NUM_FUTURE: usize = 7;

/// Offset of pubkey number within the header.
pub const FWH_PK_NUM_OFFSET: usize = 20;

// ─── Install flags ─────────────────────────────────────────────────────────────

pub const FWHIF_HIGH_WATER: u32 = 0x01;
pub const FWHIF_BEST_TS: u32 = 0x02;

// ─── Hardware compatibility bits ───────────────────────────────────────────────

pub const MK_1_OK: u32 = 0x01;
pub const MK_2_OK: u32 = 0x02;
pub const MK_3_OK: u32 = 0x04;
pub const MK_4_OK: u32 = 0x08;
pub const MK_Q1_OK: u32 = 0x10;
pub const MK_5_OK: u32 = 0x20;

/// Parsed firmware header.
#[derive(Debug, Clone)]
pub struct FirmwareHeader {
    pub magic_value: u32,
    pub timestamp: [u8; 8],
    pub version_string: [u8; 8],
    pub pubkey_num: u32,
    pub firmware_length: u32,
    pub install_flags: u32,
    pub hw_compat: u32,
    pub best_ts: [u8; 8],
    pub future: [u8; 20],
    pub signature: [u8; 64],
}

impl FirmwareHeader {
    /// Parse a firmware header from a 128-byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < FW_HEADER_SIZE {
            return None;
        }

        let magic_value = u32::from_le_bytes(data[0..4].try_into().ok()?);

        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&data[4..12]);

        let mut version_string = [0u8; 8];
        version_string.copy_from_slice(&data[12..20]);

        let pubkey_num = u32::from_le_bytes(data[20..24].try_into().ok()?);
        let firmware_length = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let install_flags = u32::from_le_bytes(data[28..32].try_into().ok()?);
        let hw_compat = u32::from_le_bytes(data[32..36].try_into().ok()?);

        let mut best_ts = [0u8; 8];
        best_ts.copy_from_slice(&data[36..44]);

        let mut future = [0u8; 20];
        future.copy_from_slice(&data[44..64]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[64..128]);

        Some(FirmwareHeader {
            magic_value,
            timestamp,
            version_string,
            pubkey_num,
            firmware_length,
            install_flags,
            hw_compat,
            best_ts,
            future,
            signature,
        })
    }

    /// Check if the magic value is correct.
    pub fn is_valid_magic(&self) -> bool {
        self.magic_value == FW_HEADER_MAGIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_constants() {
        assert_eq!(FW_HEADER_SIZE, 128);
        assert_eq!(FW_HEADER_OFFSET, 0x4000 - 128);
        assert_eq!(FW_HEADER_MAGIC, 0xCC001234);
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; 128];
        // Write magic
        data[0..4].copy_from_slice(&FW_HEADER_MAGIC.to_le_bytes());
        let hdr = FirmwareHeader::from_bytes(&data).unwrap();
        assert!(hdr.is_valid_magic());
    }
}

// EOF
