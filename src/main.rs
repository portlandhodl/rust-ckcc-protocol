// (c) Copyright 2021-2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// ckcc CLI — Command-line interface for Coldcard hardware wallet
// Ported from ckcc/cli.py

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use ckcc::client::{ColdcardDevice, DEFAULT_SIM_SOCKET, list_devices};
use ckcc::constants::*;
use ckcc::electrum::{convert2cc, filepath_append_cc};
use ckcc::protocol::*;
use ckcc::sigheader::*;
use ckcc::utils::*;

/// First account, not change, first index for Bitcoin mainnet in BIP44 path.
const BIP44_FIRST: &str = "m/44'/0'/0'/0/0";

// ─── CLI argument definitions ──────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "ckcc", version, about = "Coldcard CLI — communicate with your Coldcard hardware wallet")]
struct Cli {
    /// Operate on specific unit (default: first found)
    #[arg(short, long, global = true)]
    serial: Option<String>,

    /// Operate on specific simulator socket
    #[arg(short = 'c', long = "socket", global = true)]
    socket: Option<String>,

    /// Connect to the simulator via Unix socket
    #[arg(short = 'x', long, global = true)]
    simulator: bool,

    /// Disable USB link-layer encryption
    #[arg(short = 'P', long, global = true)]
    plaintext: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all attached Coldcard devices
    List,

    /// Securely logout of device (will require replug to start over)
    Logout,

    /// Reboot coldcard, force relogin and start over
    Reboot,

    /// Get the version of the firmware installed
    Version,

    /// Get which blockchain (Bitcoin/Testnet) is configured
    Chain,

    /// Get the fingerprint for this wallet (master level)
    Xfp {
        /// Reverse endian of result (32-bit)
        #[arg(short, long)]
        swab: bool,
    },

    /// Get the XPUB for this wallet (master level, or any derivation)
    Xpub {
        /// Derivation path (default: m)
        #[arg(default_value = "m")]
        subpath: String,

        /// Show extended key with master fingerprint and derivation
        #[arg(short, long)]
        verbose: bool,
    },

    /// Get the public key for a derivation path
    Pubkey {
        /// Derivation path (default: m)
        #[arg(default_value = "m")]
        subpath: String,
    },

    /// Show the human version of an address
    Addr {
        /// Derivation path
        path: Option<String>,

        /// Show in segwit native (p2wpkh, bech32)
        #[arg(short, long)]
        segwit: bool,

        /// Show in taproot (p2tr, bech32m)
        #[arg(short, long)]
        taproot: bool,

        /// Show in segwit wrapped in P2SH (p2sh-p2wpkh)
        #[arg(short, long)]
        wrap: bool,

        /// Show less details; just the address
        #[arg(short, long)]
        quiet: bool,
    },

    /// Sign a short text message
    Msg {
        /// Message to sign
        message: String,

        /// Derivation for key to use
        #[arg(short, long)]
        path: Option<String>,

        /// Include fancy ascii armour
        #[arg(short, long)]
        verbose: bool,

        /// Just the signature itself, nothing more
        #[arg(short, long)]
        just_sig: bool,

        /// Address in segwit native (p2wpkh, bech32)
        #[arg(short, long)]
        segwit: bool,

        /// Address in segwit wrapped in P2SH (p2sh-p2wpkh)
        #[arg(short, long)]
        wrap: bool,
    },

    /// Approve a spending transaction by signing it on Coldcard
    Sign {
        /// Input PSBT file (use - for stdin)
        psbt_in: String,

        /// Output PSBT file
        psbt_out: Option<String>,

        /// Show final signed transaction, ready for transmission
        #[arg(short, long)]
        finalize: bool,

        /// Show text of Coldcard's interpretation of the transaction
        #[arg(short = 'z', long)]
        visualize: bool,

        /// Broadcast transaction via provided PushTx URL
        #[arg(short, long)]
        pushtx: Option<String>,

        /// Miniscript wallet name
        #[arg(short, long)]
        miniscript: Option<String>,

        /// Include a signature over visualization text
        #[arg(short = 's', long)]
        signed: bool,

        /// Write out (signed) PSBT in hexadecimal
        #[arg(short = 'x', long = "hex")]
        hex_mode: bool,

        /// Write out (signed) PSBT encoded in base64
        #[arg(short = '6', long = "base64")]
        b64_mode: bool,
    },

    /// Creates 7z encrypted backup file
    Backup {
        /// Save into indicated directory (auto filename)
        #[arg(short = 'd', long, default_value = ".")]
        outdir: String,

        /// Name for backup file
        #[arg(short, long)]
        outfile: Option<String>,
    },

    /// Uploads 7z encrypted backup file & starts backup restore process
    Restore {
        /// Backup file path
        filename: String,

        /// Force plaintext restore
        #[arg(short = 'c', long)]
        plaintext: bool,

        /// This backup has custom password
        #[arg(short, long)]
        password: bool,

        /// Force restoring backup as temporary seed
        #[arg(short, long)]
        tmp: bool,
    },

    /// Send file to Coldcard (PSBT transaction or firmware)
    Upload {
        /// File to upload
        filename: String,

        /// Block size to use (testing)
        #[arg(long, default_value_t = MAX_BLK_LEN)]
        blksize: usize,

        /// Attempt multisig enroll using file
        #[arg(short, long)]
        multisig: bool,

        /// Attempt miniscript enroll using file
        #[arg(long)]
        miniscript: bool,

        /// Upload encrypted backup
        #[arg(long)]
        backup: bool,
    },

    /// Send firmware file (.dfu) and trigger upgrade process
    Upgrade {
        /// Firmware file path
        filename: String,

        /// Stop just before reboot
        #[arg(short, long)]
        stop_early: bool,
    },

    /// Factory: set or read bag number -- single use only!
    Bag {
        /// Bag number to set
        #[arg(short, long)]
        number: Option<String>,
    },

    /// Test USB connection (debug/dev)
    Test {
        /// If set, use this value on wire
        #[arg(short, long)]
        single: Option<u8>,
    },

    /// Provide a BIP39 passphrase
    Pass {
        /// The passphrase
        passphrase: String,

        /// Show new root xpub
        #[arg(short, long)]
        verbose: bool,
    },

    /// Create a skeleton file which defines a multisig wallet
    Multisig {
        /// Minimum M signers of N required to approve
        #[arg(short = 'm', long, default_value_t = 0)]
        min_signers: usize,

        /// N signers in wallet
        #[arg(short = 'n', long = "signers", default_value_t = 3)]
        num_signers: usize,

        /// Wallet name on Coldcard
        #[arg(short = 'l', long, default_value = "Unnamed")]
        name: String,

        /// Save configuration to file
        #[arg(short = 'f', long = "output-file")]
        output_file: Option<String>,

        /// Show file uploaded
        #[arg(short, long)]
        verbose: bool,

        /// Derivation for key
        #[arg(short, long, default_value = "m/45'")]
        path: String,

        /// Just show line required to add this Coldcard
        #[arg(short = 'a', long = "add")]
        just_add: bool,

        /// Use BIP380 descriptor template
        #[arg(short = 'd', long = "desc")]
        descriptor: bool,

        /// Address format
        #[arg(long, default_value = "p2wsh")]
        format: String,
    },

    /// Enable Hardware Security Module (HSM) mode
    HsmStart {
        /// Policy file (JSON)
        policy: Option<String>,

        /// Just validate file, don't upload
        #[arg(short = 'n', long)]
        dry_run: bool,
    },

    /// Get current status of HSM feature
    Hsm,

    /// Miniscript related commands
    Miniscript {
        #[command(subcommand)]
        command: MiniscriptCommands,
    },

    /// Create a new user on the Coldcard for HSM policy (also delete)
    User {
        /// Username
        username: String,

        /// Remove a user by name
        #[arg(short, long)]
        delete: bool,

        /// Prompt for password
        #[arg(short = 'a', long)]
        ask_pass: bool,

        /// Provide password on command line
        #[arg(short = 'p', long)]
        text_secret: Option<String>,

        /// Use a password picked by Coldcard
        #[arg(long = "pass")]
        pick_pass: bool,
    },

    /// Get the value held in the Storage Locker
    GetLocker,

    /// Convert existing Electrum wallet file into COLDCARD wallet file
    Convert2cc {
        /// Electrum wallet file path
        file: String,

        /// Output file path
        #[arg(short, long)]
        outfile: Option<String>,

        /// Do not write files, print to console
        #[arg(short = 'n', long)]
        dry_run: bool,

        /// Keystore dict key to match
        #[arg(short, long)]
        key: Option<String>,

        /// Value to match for specified key
        #[arg(short, long)]
        val: Option<String>,
    },
}

#[derive(Subcommand)]
enum MiniscriptCommands {
    /// Enroll miniscript wallet from string
    Enroll {
        /// Descriptor (can be JSON wrapped)
        desc: String,
    },

    /// List registered miniscript wallet names
    Ls,

    /// Delete registered miniscript wallet by name
    Del {
        /// Wallet name
        name: String,
    },

    /// Get registered miniscript wallet by name
    Get {
        /// Wallet name
        name: String,
    },

    /// Get registered miniscript wallet policy (BIP-388) by name
    Policy {
        /// Wallet name
        name: String,
    },

    /// Get miniscript address by index
    Addr {
        /// Wallet name
        name: String,

        /// Address index
        index: u32,

        /// Use internal chain
        #[arg(long)]
        change: bool,
    },
}

// ─── Helper: get device connection ─────────────────────────────────────────────

fn get_device(cli: &Cli) -> Result<ColdcardDevice> {
    let serial = if cli.simulator || cli.socket.is_some() {
        Some(
            cli.socket
                .as_deref()
                .unwrap_or(DEFAULT_SIM_SOCKET)
                .to_string(),
        )
    } else {
        cli.serial.clone()
    };

    let dev = ColdcardDevice::open(
        serial.as_deref(),
        !cli.plaintext,
        USB_NCRY_V1,
        cli.simulator,
    )
    .context("Failed to connect to Coldcard")?;

    Ok(dev)
}

fn get_device_optional(cli: &Cli) -> Option<ColdcardDevice> {
    get_device(cli).ok()
}

// ─── Helper: wait and download ─────────────────────────────────────────────────

fn wait_and_download(dev: &mut ColdcardDevice, req: &[u8], file_number: u32) -> Result<(Vec<u8>, [u8; 32])> {
    eprint!("Waiting for OK on the Coldcard...");

    loop {
        std::thread::sleep(Duration::from_millis(250));
        let done = dev.send_recv(req, None, None);

        match done {
            Ok(CCResponse::Ok) => continue,
            Ok(CCResponse::Int2(_result_len, _)) => {
                // Need to reconstruct as SignedTxn
                bail!("Unexpected Int2 response");
            }
            Ok(CCResponse::SignedTxn { length, sha256 }) => {
                eprintln!("\r                                  ");
                eprintln!("Ok! Downloading result ({} bytes)", length);

                let result = dev.download_file(length as usize, &sha256, 1024, file_number)?;
                return Ok((result, sha256));
            }
            Ok(CCResponse::SignedMessage { address, signature }) => {
                eprintln!("\r                                  ");
                return Ok((
                    [address.as_bytes(), &signature].concat(),
                    [0u8; 32], // placeholder
                ));
            }
            Ok(other) => {
                eprintln!();
                bail!("Unexpected response: {:?}", other);
            }
            Err(CCError::BusyError) => continue,
            Err(e) => {
                eprintln!();
                return Err(e.into());
            }
        }
    }
}

// ─── Helper: file upload ───────────────────────────────────────────────────────

fn real_file_upload(
    data: &[u8],
    dev: &mut ColdcardDevice,
    blksize: usize,
) -> Result<(usize, [u8; 32])> {
    eprintln!("{} bytes to send", data.len());

    let mut hasher = Sha256::new();
    let mut offset = 0;

    while offset < data.len() {
        let end = std::cmp::min(offset + blksize, data.len());
        let chunk = &data[offset..end];

        let resp = dev.send_recv(
            &CCProtocolPacker::upload(offset as u32, data.len() as u32, chunk),
            None,
            None,
        )?;

        match resp {
            CCResponse::Int1(pos) => {
                assert_eq!(pos as usize, offset, "Upload position mismatch");
            }
            _ => bail!("Unexpected upload response"),
        }

        hasher.update(chunk);
        offset = end;
    }

    let expect: [u8; 32] = hasher.finalize().into();

    // Verify
    let result = dev.send_recv(&CCProtocolPacker::sha256(), None, None)?;
    match result {
        CCResponse::Binary(rb) => {
            if rb.as_slice() != expect.as_slice() {
                bail!(
                    "Wrong checksum:\nexpect: {}\n   got: {}",
                    hex::encode(&expect),
                    hex::encode(&rb)
                );
            }
        }
        _ => bail!("Unexpected sha256 response"),
    }

    Ok((data.len(), expect))
}

// ─── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::List => {
            let devices = list_devices()?;
            if devices.is_empty() {
                println!("(none found)");
            } else {
                for (serial, path) in &devices {
                    println!("\nColdcard {}:\n    path: {}", serial, path);
                }
            }
        }

        Commands::Logout => {
            let mut dev = get_device(&cli)?;
            let resp = dev.send_recv(&CCProtocolPacker::logout(), None, None)?;
            match resp {
                CCResponse::Ok => println!("Okay!"),
                _ => println!("Device says: {:?}", resp),
            }
        }

        Commands::Reboot => {
            let mut dev = get_device(&cli)?;
            let resp = dev.send_recv(&CCProtocolPacker::reboot(), None, None)?;
            match resp {
                CCResponse::Ok => println!("Okay!"),
                _ => println!("Device says: {:?}", resp),
            }
        }

        Commands::Version => {
            let mut dev = get_device(&cli)?;
            let resp = dev.send_recv(&CCProtocolPacker::version(), None, None)?;
            match resp {
                CCResponse::Ascii(v) => println!("{}", v),
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Chain => {
            let mut dev = get_device(&cli)?;
            let resp = dev.send_recv(&CCProtocolPacker::block_chain(), None, None)?;
            match resp {
                CCResponse::Ascii(code) => println!("{}", code),
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Xfp { swab } => {
            let dev = get_device(&cli)?;
            let xfp = dev.master_fingerprint;
            assert!(xfp != 0, "No fingerprint available");

            if *swab {
                println!("0x{:08x}", xfp);
            } else {
                println!("{}", xfp2str(xfp));
            }
        }

        Commands::Xpub { subpath, verbose } => {
            let mut dev = get_device(&cli)?;
            let path = if subpath == "bip44" {
                BIP44_FIRST.to_string()
            } else {
                subpath.clone()
            };

            let resp = dev.send_recv(&CCProtocolPacker::get_xpub(&path), None, None)?;
            match resp {
                CCResponse::Ascii(xpub) => {
                    if *verbose {
                        let sp = path.replace("m/", "").replace('\'', "h");
                        println!(
                            "[{}/{}]{}",
                            xfp2str(dev.master_fingerprint).to_lowercase(),
                            sp,
                            xpub
                        );
                    } else {
                        println!("{}", xpub);
                    }
                }
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Pubkey { subpath } => {
            let mut dev = get_device(&cli)?;
            let resp = dev.send_recv(&CCProtocolPacker::get_xpub(subpath), None, None)?;
            match resp {
                CCResponse::Ascii(xpub) => {
                    let (pubkey, _) = decode_xpub(&xpub)?;
                    let full = get_pubkey_string(&pubkey)?;
                    // Compress: take x coordinate and prefix with 02 or 03
                    let prefix = if full[63] & 1 == 0 { 0x02 } else { 0x03 };
                    let mut compressed = vec![prefix];
                    compressed.extend_from_slice(&full[0..32]);
                    println!("{}", hex::encode(&compressed));
                }
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Addr {
            path,
            segwit,
            taproot,
            wrap,
            quiet,
        } => {
            let mut dev = get_device(&cli)?;
            let (addr_fmt, af_path) = addr_fmt_help(
                dev.master_xpub.as_deref(),
                *wrap,
                *segwit,
                *taproot,
            );
            let use_path = path.as_deref().unwrap_or(&af_path);

            let resp = dev.send_recv(
                &CCProtocolPacker::show_address(use_path, addr_fmt),
                None,
                None,
            )?;
            match resp {
                CCResponse::Ascii(addr) => {
                    if *quiet {
                        println!("{}", addr);
                    } else {
                        println!("Displaying address:\n\n{}\n", addr);
                    }
                }
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Msg {
            message,
            path,
            verbose,
            just_sig,
            segwit,
            wrap,
        } => {
            let mut dev = get_device(&cli)?;
            let (addr_fmt, af_path) = addr_fmt_help(
                dev.master_xpub.as_deref(),
                *wrap,
                *segwit,
                false,
            );
            let signing_path = path.as_deref().unwrap_or(&af_path);
            let msg_bytes = message.as_bytes();

            dev.send_recv(
                &CCProtocolPacker::sign_message(msg_bytes, signing_path, addr_fmt),
                None,
                None,
            )?;

            eprint!("Waiting for OK on the Coldcard...");

            loop {
                std::thread::sleep(Duration::from_millis(250));
                let done = dev.send_recv(&CCProtocolPacker::get_signed_msg(), None, None)?;
                match done {
                    CCResponse::Ok => continue,
                    CCResponse::SignedMessage { address, signature } => {
                        eprint!("\r                                  \r");
                        let sig = B64.encode(&signature);

                        if *just_sig {
                            println!("{}", sig);
                        } else if *verbose {
                            println!(
                                "{}",
                                format_rfc_signature(message, &address, &sig)
                            );
                        } else {
                            println!("{}\n{}\n{}", message, address, sig);
                        }
                        break;
                    }
                    _ => bail!("Unexpected response: {:?}", done),
                }
            }
        }

        Commands::Sign {
            psbt_in,
            psbt_out,
            finalize,
            visualize,
            pushtx,
            miniscript,
            signed,
            hex_mode,
            b64_mode,
        } => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            // Read PSBT
            let data = if psbt_in == "-" {
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf)?;
                buf
            } else {
                fs::read(psbt_in)?
            };

            // Handle encodings
            let data = if data.len() >= 10 && data[..10].iter().all(|b| b.is_ascii_hexdigit()) {
                // Hex encoded
                hex::decode(
                    std::str::from_utf8(&data)
                        .unwrap_or("")
                        .chars()
                        .filter(|c| c.is_ascii_hexdigit())
                        .collect::<String>(),
                )?
            } else if data.starts_with(b"cHNidP") {
                // Base64 encoded
                B64.decode(&data)?
            } else {
                data
            };

            if !data.starts_with(b"psbt\xff") {
                bail!("File doesn't have PSBT magic number at start.");
            }

            let (txn_len, sha) = real_file_upload(&data, &mut dev, MAX_BLK_LEN)?;

            let mut do_finalize = *finalize;
            let mut do_visualize = *visualize;
            let mut do_signed = *signed;

            if pushtx.is_some() {
                do_finalize = true;
                do_visualize = false;
                do_signed = false;
            }

            let mut flags = 0u32;
            if do_visualize || do_signed {
                flags |= STXN_VISUALIZE;
                if do_signed {
                    flags |= STXN_SIGNED;
                }
            } else if do_finalize {
                flags |= STXN_FINALIZE;
            }

            let sha_arr: [u8; 32] = sha;
            dev.send_recv(
                &CCProtocolPacker::sign_transaction(
                    txn_len as u32,
                    &sha_arr,
                    false,
                    flags,
                    miniscript.as_deref(),
                ),
                None,
                None,
            )?;

            let (result, result_sha) =
                wait_and_download(&mut dev, &CCProtocolPacker::get_signed_txn(), 1)?;

            if let Some(pushtx_url) = pushtx {
                let url = match pushtx_url.as_str() {
                    "coldcard" => "https://coldcard.com/pushtx#",
                    "mempool" => "https://mempool.space/pushtx#",
                    other => other,
                };

                let chain_resp = dev.send_recv(&CCProtocolPacker::block_chain(), None, None)?;
                let chain = match chain_resp {
                    CCResponse::Ascii(c) => c,
                    _ => "BTC".to_string(),
                };

                match txn_to_pushtx_url(&result, url, Some(&result_sha), &chain, false) {
                    Ok(url) => {
                        println!("{}", url);
                        // Note: opening browser not implemented in CLI, print URL instead
                    }
                    Err(e) => eprintln!("ERROR: {}", e),
                }
            } else if do_visualize {
                if let Some(out) = psbt_out {
                    fs::write(out, &result)?;
                } else {
                    io::stdout().write_all(&result)?;
                }
            } else {
                let output = if *hex_mode {
                    hex::encode(&result).into_bytes()
                } else if *b64_mode || psbt_out.is_none() {
                    B64.encode(&result).into_bytes()
                } else {
                    result
                };

                if let Some(out) = psbt_out {
                    fs::write(out, &output)?;
                } else {
                    io::stdout().write_all(&output)?;
                    println!();
                }
            }
        }

        Commands::Backup { outdir, outfile } => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            dev.send_recv(&CCProtocolPacker::start_backup(), None, None)?;

            let (result, chk) =
                wait_and_download(&mut dev, &CCProtocolPacker::get_backup_file(), 0)?;

            let filename = if let Some(out) = outfile {
                fs::write(out, &result)?;
                out.clone()
            } else {
                let now = chrono::Local::now();
                let fn_name = format!("backup-{}.7z", now.format("%Y%m%d-%H%M"));
                let path = PathBuf::from(outdir).join(&fn_name);
                fs::write(&path, &result)?;
                path.to_string_lossy().to_string()
            };

            println!(
                "Wrote {} bytes into: {}\nSHA256: {}",
                result.len(),
                filename,
                hex::encode(&chk)
            );
        }

        Commands::Restore {
            filename,
            plaintext,
            password,
            tmp,
        } => {
            let mut dev = get_device(&cli)?;

            let is_plaintext = *plaintext || filename.to_lowercase().ends_with(".txt");

            if is_plaintext && *password {
                bail!("Plaintext backup cannot have custom password.");
            }

            let data = fs::read(filename)?;
            let (file_len, sha) = real_file_upload(&data, &mut dev, MAX_BLK_LEN)?;

            dev.send_recv(
                &CCProtocolPacker::restore_backup(
                    file_len as u32,
                    &sha,
                    *password,
                    is_plaintext,
                    *tmp,
                ),
                None,
                None,
            )?;
        }

        Commands::Upload {
            filename,
            blksize,
            multisig,
            miniscript,
            backup,
        } => {
            if [*multisig, *miniscript, *backup].iter().filter(|&&x| x).count() > 1 {
                bail!("Only one can be specified from miniscript/multisig/backup");
            }

            let mut dev = get_device(&cli)?;
            let data = fs::read(filename)?;
            let (file_len, sha) = real_file_upload(&data, &mut dev, *blksize)?;

            if *multisig {
                dev.send_recv(&CCProtocolPacker::multisig_enroll(file_len as u32, &sha), None, None)?;
            } else if *miniscript {
                dev.send_recv(&CCProtocolPacker::miniscript_enroll(file_len as u32, &sha), None, None)?;
            } else if *backup {
                dev.send_recv(
                    &CCProtocolPacker::restore_backup(file_len as u32, &sha, false, false, false),
                    None,
                    None,
                )?;
            }
        }

        Commands::Upgrade {
            filename,
            stop_early,
        } => {
            let mut dev = get_device(&cli)?;
            let data = fs::read(filename)?;

            // Check for DFU or raw binary
            let (fw_data, _offset) = if data.starts_with(b"DfuSe") {
                let mut cursor = std::io::Cursor::new(&data);
                let elements = dfu_parse(&mut cursor)?;
                if let Some(&(offset, size)) = elements.first() {
                    let start = offset as usize;
                    let end = start + size as usize;
                    (data[start..end].to_vec(), offset)
                } else {
                    bail!("No elements found in DFU file");
                }
            } else {
                (data.clone(), 0)
            };

            // Check firmware header magic
            if fw_data.len() > FW_HEADER_OFFSET + FW_HEADER_SIZE {
                let hdr_data = &fw_data[FW_HEADER_OFFSET..FW_HEADER_OFFSET + FW_HEADER_SIZE];
                let magic = u32::from_le_bytes(hdr_data[0..4].try_into()?);
                if magic != FW_HEADER_MAGIC {
                    bail!("This does not look like a firmware file! Bad magic value.");
                }
            }

            let (sz, _expect) = real_file_upload(&fw_data, &mut dev, MAX_BLK_LEN)?;

            // Write signature header trailer
            if fw_data.len() > FW_HEADER_OFFSET + FW_HEADER_SIZE {
                let hdr = &fw_data[FW_HEADER_OFFSET..FW_HEADER_OFFSET + FW_HEADER_SIZE];
                dev.send_recv(
                    &CCProtocolPacker::upload(sz as u32, (sz + FW_HEADER_SIZE) as u32, hdr),
                    None,
                    None,
                )?;
            }

            if !stop_early {
                eprintln!("Upgrade started. Observe Coldcard screen for progress.");
                dev.send_recv(&CCProtocolPacker::reboot(), None, None)?;
            }
        }

        Commands::Bag { number } => {
            let mut dev = get_device(&cli)?;
            let nn = number.as_deref().unwrap_or("").as_bytes();
            let resp = dev.send_recv(&CCProtocolPacker::bag_number(nn), None, None)?;
            println!("Bag number: {:?}", resp);
        }

        Commands::Test { single } => {
            let mut dev = get_device(&cli)?;
            let mut ranges: Vec<usize> = Vec::new();
            ranges.extend(55..66);
            ranges.extend(1013..1024);
            ranges.extend((MAX_MSG_LEN - 10)..(MAX_MSG_LEN - 4));

            for i in ranges {
                print!("Ping with length: {}", i);
                let body: Vec<u8> = if let Some(val) = single {
                    vec![*val; i]
                } else {
                    (0..i).map(|_| rand::random::<u8>()).collect()
                };

                let resp = dev.send_recv(&CCProtocolPacker::ping(&body), None, None)?;
                match resp {
                    CCResponse::Binary(rb) => {
                        assert_eq!(rb, body, "Fail @ len: {}", i);
                        println!("  Okay");
                    }
                    _ => bail!("Unexpected response at len {}", i),
                }
            }
        }

        Commands::Pass {
            passphrase,
            verbose,
        } => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            dev.send_recv(
                &CCProtocolPacker::bip39_passphrase(passphrase),
                None,
                None,
            )?;

            eprint!("Waiting for OK on the Coldcard...");

            loop {
                std::thread::sleep(Duration::from_millis(250));
                let done = dev.send_recv(&CCProtocolPacker::get_passphrase_done(), None, None)?;
                match done {
                    CCResponse::Ok => continue,
                    CCResponse::Ascii(xpub) => {
                        eprint!("\r                                  \r");
                        if *verbose {
                            println!("{}", xpub);
                        } else {
                            println!("Done.");
                        }
                        break;
                    }
                    _ => {
                        eprint!("\r                                  \r");
                        println!("Done.");
                        break;
                    }
                }
            }
        }

        Commands::Multisig {
            min_signers,
            num_signers,
            name,
            output_file,
            verbose,
            path,
            just_add,
            descriptor,
            format,
        } => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            let xfp = dev.master_fingerprint;
            let resp = dev.send_recv(&CCProtocolPacker::get_xpub(path), None, None)?;
            let my_xpub = match resp {
                CCResponse::Ascii(x) => x,
                _ => bail!("Unexpected response"),
            };

            let xfp_str = xfp2str(xfp);
            let new_line = format!("{}: {}", xfp_str, my_xpub);

            if *just_add {
                println!("{}", new_line);
                return Ok(());
            }

            let n = std::cmp::max(*num_signers, *min_signers);
            let m = if *min_signers == 0 { n } else { *min_signers };

            if !(1..15).contains(&n) {
                bail!("N must be 1..15");
            }
            if !(1..=n).contains(&m) {
                bail!("Minimum number of signers (M) must be between 1 and N={}", n);
            }

            let config = if *descriptor {
                let fmt = match format.as_str() {
                    "p2sh" => AF_P2SH,
                    "p2sh-p2wsh" => AF_P2WSH_P2SH,
                    _ => AF_P2WSH,
                };
                let desc = descriptor_template(&xfp_str, &my_xpub, path, fmt, Some(&m.to_string()))
                    .unwrap_or_default();
                if name != "Unnamed" {
                    serde_json::json!({"name": name, "desc": desc}).to_string()
                } else {
                    desc
                }
            } else {
                let mut config = format!(
                    "name: {}\npolicy: {} of {}\nformat: {}\n\n#path: {}\n{}\n",
                    name,
                    m,
                    n,
                    format.to_uppercase(),
                    path,
                    new_line
                );
                if *num_signers > 1 {
                    for i in 0..(*num_signers - 1) {
                        config.push_str(&format!(
                            "#{}# FINGERPRINT: xpub123123123123123\n",
                            i + 2
                        ));
                    }
                }
                config
            };

            if *verbose || output_file.is_none() {
                let display = config.trim_end_matches('\n');
                println!("{}", display);
            }

            if let Some(out) = output_file {
                fs::write(out, &config)?;
                println!("Wrote to: {}", out);
            }
        }

        Commands::HsmStart { policy, dry_run } => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            if let Some(policy_file) = policy {
                if *dry_run {
                    let raw = fs::read_to_string(policy_file)?;
                    let _: serde_json::Value = serde_json::from_str(&raw)?;
                    println!("Policy ok");
                    return Ok(());
                }

                let data = fs::read(policy_file)?;
                let (file_len, sha) = real_file_upload(&data, &mut dev, MAX_BLK_LEN)?;
                dev.send_recv(
                    &CCProtocolPacker::hsm_start(file_len as u32, &sha),
                    None,
                    None,
                )?;
            } else {
                if *dry_run {
                    bail!("Dry run not useful without a policy file to check.");
                }
                dev.send_recv(&CCProtocolPacker::hsm_start(0, &[]), None, None)?;
            }

            println!("Approve HSM policy on Coldcard screen.");
        }

        Commands::Hsm => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            let resp = dev.send_recv(&CCProtocolPacker::hsm_status(), None, None)?;
            match resp {
                CCResponse::Ascii(json_str) => {
                    let v: serde_json::Value = serde_json::from_str(&json_str)?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Miniscript { command } => match command {
            MiniscriptCommands::Enroll { desc } => {
                let mut dev = get_device(&cli)?;
                let data = desc.as_bytes();
                let (file_len, sha) = real_file_upload(data, &mut dev, MAX_BLK_LEN)?;
                dev.send_recv(
                    &CCProtocolPacker::miniscript_enroll(file_len as u32, &sha),
                    None,
                    None,
                )?;
            }
            MiniscriptCommands::Ls => {
                let mut dev = get_device(&cli)?;
                dev.check_mitm(None)?;
                let resp = dev.send_recv(&CCProtocolPacker::miniscript_ls(), None, None)?;
                match resp {
                    CCResponse::Ascii(json_str) => {
                        let v: serde_json::Value = serde_json::from_str(&json_str)?;
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    }
                    _ => bail!("Unexpected response"),
                }
            }
            MiniscriptCommands::Del { name } => {
                let mut dev = get_device(&cli)?;
                dev.check_mitm(None)?;
                dev.send_recv(&CCProtocolPacker::miniscript_delete(name), None, None)?;
            }
            MiniscriptCommands::Get { name } => {
                let mut dev = get_device(&cli)?;
                dev.check_mitm(None)?;
                let resp = dev.send_recv(&CCProtocolPacker::miniscript_get(name), None, None)?;
                match resp {
                    CCResponse::Ascii(json_str) => {
                        let v: serde_json::Value = serde_json::from_str(&json_str)?;
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    }
                    _ => bail!("Unexpected response"),
                }
            }
            MiniscriptCommands::Policy { name } => {
                let mut dev = get_device(&cli)?;
                dev.check_mitm(None)?;
                let resp = dev.send_recv(&CCProtocolPacker::miniscript_policy(name), None, None)?;
                match resp {
                    CCResponse::Ascii(json_str) => {
                        let v: serde_json::Value = serde_json::from_str(&json_str)?;
                        println!("{}", serde_json::to_string_pretty(&v)?);
                    }
                    _ => bail!("Unexpected response"),
                }
            }
            MiniscriptCommands::Addr {
                name,
                index,
                change,
            } => {
                let mut dev = get_device(&cli)?;
                dev.check_mitm(None)?;
                let resp = dev.send_recv(
                    &CCProtocolPacker::miniscript_address(name, *change, *index),
                    None,
                    None,
                )?;
                match resp {
                    CCResponse::Ascii(addr) => println!("{}", addr),
                    _ => bail!("Unexpected response"),
                }
            }
        },

        Commands::User {
            username,
            delete,
            ask_pass,
            text_secret,
            pick_pass,
        } => {
            let mut dev = get_device(&cli)?;
            dev.check_mitm(None)?;

            let username_bytes = username.as_bytes();

            if *delete {
                dev.send_recv(&CCProtocolPacker::delete_user(username_bytes), None, None)?;
                println!("Deleted, if it was there");
                return Ok(());
            }

            let (mode, secret) = if *ask_pass || text_secret.is_some() || *pick_pass {
                let secret = if let Some(pw) = text_secret {
                    dev.hash_password(pw.as_bytes(), false)
                } else {
                    vec![]
                };
                (USER_AUTH_HMAC, secret)
            } else {
                (USER_AUTH_TOTP, vec![])
            };

            let resp = dev.send_recv(
                &CCProtocolPacker::create_user(username_bytes, mode, &secret),
                None,
                None,
            )?;

            match resp {
                CCResponse::Binary(new_secret) if !new_secret.is_empty() => {
                    if text_secret.is_none() {
                        println!("New password is: {}", String::from_utf8_lossy(&new_secret));
                    }
                }
                _ => println!("Done"),
            }
        }

        Commands::GetLocker => {
            let mut dev = get_device(&cli)?;
            let resp = dev.send_recv(&CCProtocolPacker::get_storage_locker(), None, None)?;
            match resp {
                CCResponse::Binary(data) => {
                    println!("{}", String::from_utf8_lossy(&data));
                }
                CCResponse::Ascii(s) => println!("{}", s),
                _ => bail!("Unexpected response"),
            }
        }

        Commands::Convert2cc {
            file,
            outfile,
            dry_run,
            key,
            val,
        } => {
            if outfile.as_deref() == Some(file.as_str()) {
                bail!("'FILE' and '--outfile' cannot be the same");
            }

            let dev = get_device_optional(&cli);
            let (master_fp, master_xpub) = if let Some(ref d) = dev {
                (Some(d.master_fingerprint), d.master_xpub.as_deref())
            } else {
                (None, None)
            };

            let wallet_str = fs::read_to_string(file)
                .context("Failed to read wallet file")?;

            let new_wallet_str = convert2cc(
                &wallet_str,
                master_fp,
                master_xpub,
                key.as_deref(),
                val.as_deref(),
            )?;

            if *dry_run {
                println!("{}", new_wallet_str);
            } else {
                let out = outfile
                    .clone()
                    .unwrap_or_else(|| filepath_append_cc(file));
                fs::write(&out, &new_wallet_str)?;
                println!("New wallet file created: {}", out);
            }
        }
    }

    Ok(())
}
