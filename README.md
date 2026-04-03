# ckcc — Coldcard CLI and Rust Library

Coldcard is an affordable, ultra-secure and open-source hardware wallet for Bitcoin.
Learn more at [coldcard.com](https://coldcard.com).

This is the **Rust** implementation of the Coldcard USB protocol library and CLI tool,
ported from the original [Python ckcc-protocol](https://github.com/Coldcard/ckcc-protocol).

## Features

- **Library (`ckcc`)** — Communicate with Coldcard over USB HID or Unix simulator socket
- **CLI binary (`ckcc`)** — Full-featured command-line tool for all Coldcard operations
- Link-layer encryption (ECDH + AES-256-CTR)
- PSBT signing, message signing, firmware upgrades
- Multisig and miniscript wallet management
- HSM mode support
- Electrum wallet file conversion
- Backup/restore operations

## Installation

### From source

```bash
cargo install --path .
```

### From crates.io (when published)

```bash
cargo install ckcc
```

### As a library dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
ckcc = "0.1"
```

## Linux udev Rules

On Linux, you may need to set up udev rules for USB access. Copy the included
rules file:

```bash
sudo cp ../51-coinkite.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

Then unplug and re-plug your Coldcard.

## CLI Usage

```
ckcc --help
```

### Global Options

| Flag | Description |
|------|-------------|
| `-s, --serial <HEX>` | Operate on specific unit (default: first found) |
| `-c, --socket <PATH>` | Operate on specific simulator socket |
| `-x, --simulator` | Connect to the simulator via Unix socket |
| `-P, --plaintext` | Disable USB link-layer encryption |

### Commands

| Command | Description |
|---------|-------------|
| `list` | List all attached Coldcard devices |
| `version` | Get firmware version |
| `xfp` | Get master fingerprint |
| `xpub [PATH]` | Get XPUB (master or derived) |
| `pubkey [PATH]` | Get compressed public key |
| `addr [PATH]` | Show/display an address |
| `msg <MESSAGE>` | Sign a text message |
| `sign <PSBT_IN> [PSBT_OUT]` | Sign a PSBT transaction |
| `backup` | Create encrypted backup |
| `restore <FILE>` | Restore from backup |
| `upload <FILE>` | Upload file to Coldcard |
| `upgrade <FILE>` | Firmware upgrade |
| `pass <PASSPHRASE>` | Set BIP39 passphrase |
| `multisig` | Create multisig wallet config |
| `miniscript <SUBCOMMAND>` | Miniscript wallet operations |
| `hsm-start [POLICY]` | Enable HSM mode |
| `hsm` | Get HSM status |
| `user <USERNAME>` | Manage HSM users |
| `convert2cc <FILE>` | Convert Electrum wallet to Coldcard |
| `chain` | Get configured blockchain |
| `bag` | Set/read bag number |
| `test` | Test USB connection |
| `logout` | Securely logout |
| `reboot` | Reboot device |
| `get-locker` | Read storage locker |

### Examples

```bash
# List connected devices
ckcc list

# Get firmware version
ckcc version

# Get master fingerprint
ckcc xfp

# Get xpub at a derivation path
ckcc xpub "m/84'/0'/0'"

# Sign a message
ckcc msg "Hello Coldcard" -p "m/84'/0'/0'/0/0" --segwit

# Sign a PSBT
ckcc sign input.psbt output.psbt

# Sign and finalize for broadcast
ckcc sign input.psbt -f | ckcc sign - --pushtx coldcard

# Create backup
ckcc backup -d ./backups/

# Connect to simulator
ckcc -x version
```

## Library Usage

```rust
use ckcc::client::ColdcardDevice;
use ckcc::protocol::CCProtocolPacker;
use ckcc::constants::USB_NCRY_V1;

fn main() -> anyhow::Result<()> {
    // Connect to first available Coldcard
    let mut dev = ColdcardDevice::open(None, true, USB_NCRY_V1, false)?;

    // Get firmware version
    let resp = dev.send_recv(&CCProtocolPacker::version(), None, None)?;
    println!("Version: {:?}", resp);

    // Get master fingerprint
    println!("XFP: {:08X}", dev.master_fingerprint);

    dev.close();
    Ok(())
}
```

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run the CLI
cargo run -- --help
```

## Project Structure

```
src/
├── lib.rs          — Library entry point
├── main.rs         — CLI binary (clap-based)
├── constants.rs    — Protocol constants and address formats
├── protocol.rs     — USB protocol packer/unpacker
├── client.rs       — ColdcardDevice + HID/simulator transports
├── utils.rs        — Utility functions (DFU, base58, crypto helpers)
├── sigheader.rs    — Firmware signature header parsing
└── electrum.rs     — Electrum wallet file conversion
```

## License

MIT + Commons Clause — see [COPYING-CC](../COPYING-CC) for details.

Original code (c) Copyright 2021-2025 by Coinkite Inc.
