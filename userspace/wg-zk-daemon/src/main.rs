mod netlink;

use neli::genl::{AttrType, Nlattr};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use neli::consts::genl::{CtrlAttr, CtrlCmd};
use neli::consts::nl::NlmF;
use neli::genl::{Genlmsghdr, NlattrBuilder};
use neli::nl::Nlmsghdr;
// use neli::nlattr::Nlattr;
// use neli::socket::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer};
// use neli::utils::U32Bitfield;

use neli::consts::nl::{ Nlmsg};
use neli::genl::{GenlmsghdrBuilder};
use neli::nl::{NlPayload, NlmsghdrBuilder};
// use neli::nlattr::NlattrBuilder;
// use neli::socket::tokio::NlSocketHandle;
// use neli::types::Groups;
// attrs

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, edwards::EdwardsPoint, scalar::Scalar};
use sha2::{Digest, Sha512};
use std::{fs,  time::Duration};
use neli::socket::asynchronous::NlSocketHandle;
use neli::utils::Groups;


/// Resolve family id via CTRL_CMD_GETFAMILY
use neli::consts::nl::GenlId;// Netlink attribute builder

use neli::consts::socket::NlFamily;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY},
};

use tokio::{fs as tfs, time::sleep};

use neli::err::Nlmsgerr;

// Async soket

// Groups (multicast grupları)

/// WireGuard ZK userspace CLI
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send VERIFY_ACK (cmd=1) with peer_index (u32) and result (u8)
    SendVerifyAck {
        /// peer index (u32)
        #[arg(long)]
        peer_index: u32,
        /// result (u8), e.g. 0/1
        #[arg(long)]
        result: u8,
        /// family name (defaults to wgzk)
        #[arg(long, default_value = "wgzk")]
        family: String,
        /// generic netlink version (defaults to 1)
        #[arg(long, default_value_t = 1u8)]
        version: u8,
    },
    /// Run the daemon that watches zk_handshake and sends ACKs
    Daemon,
}

// --- crypto helpers ---

fn decompress_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    CompressedEdwardsY::from_slice(bytes).ok()?.decompress()
}

fn verify_proof(pk: EdwardsPoint, zk_r: EdwardsPoint, zk_s: Scalar) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(G.compress().as_bytes());
    hasher.update(pk.compress().as_bytes());
    hasher.update(zk_r.compress().as_bytes());
    let c = Scalar::from_hash(hasher);
    zk_s * G == zk_r + c * pk
}

pub fn load_static_pk() -> Result<EdwardsPoint> {
    let s = std::fs::read_to_string("config/static_pk.hex")
        .with_context(|| "reading static_pk.hex failed")?;
    let s = s.trim();
    if s.is_empty() {
        bail!("static_pk.hex is empty");
    }
    let bytes = hex::decode(s).with_context(|| "static_pk.hex is not valid hex")?;
    if bytes.len() != 32 {
        bail!("static_pk.hex must be 32 bytes (64 hex chars), got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("invalid point in static_pk.hex"))
}


// --- daemon ---

async fn run_daemon(pk: EdwardsPoint) -> Result<()> {
    const HANDSHAKE_PATH: &str = "/sys/kernel/debug/wireguard/zk_handshake";
    let mut last96 = [0u8; 96];

    loop {
        match tfs::read(HANDSHAKE_PATH).await {
            Ok(buf) if buf.len() >= 96 && &buf[..96] != &last96 => {
                eprintln!("New handshake received");
                last96.copy_from_slice(&buf[..96]);

                // offsets based on your format
                // [0..4]=? (ignored), [4..8]=sender_index (LE), [32..64]=R, [64..96]=s
                let sender_index = u32::from_le_bytes(match buf[4..8].try_into() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("Bad sender_index slice; skipping");
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                });

                let zk_r = match decompress_point(&buf[32..64]) {
                    Some(p) => p,
                    None => {
                        eprintln!("Malformed zk_r for peer {}", sender_index);
                        // send failure ack but don’t crash
                        if let Err(e) = netlink::send_verify_ack("wgzk", 1, sender_index, 0).await {
                            eprintln!("netlink ack (fail) error: {e:#}");
                        }
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };

                let Ok(arr) = <[u8; 32]>::try_from(&buf[64..96]) else {
                    eprintln!("Bad zk_s slice for peer {sender_index}");
                    if let Err(e) = netlink::send_verify_ack("wgzk", 1, sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                    sleep(Duration::from_millis(200)).await;
                    continue;
                };

                let Some(zk_s) = Scalar::from_canonical_bytes(arr).into() else {
                    eprintln!("Non-canonical zk_s for peer {sender_index}");
                    if let Err(e) = netlink::send_verify_ack("wgzk", 1, sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                    sleep(Duration::from_millis(200)).await;
                    continue;
                };

                let ok = verify_proof(pk, zk_r, zk_s);
                if ok {
                    eprintln!("ZK verified for peer {}", sender_index);
                    if let Err(e) = netlink::send_verify_ack("wgzk", 1, sender_index, 1).await {
                        eprintln!("netlink ack (success) error: {e:#}");
                    }
                } else {
                    eprintln!("ZK failed for peer {}", sender_index);
                    if let Err(e) = netlink::send_verify_ack("wgzk", 1, sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                }
            }
            Ok(_) => { /* no change or too short; ignore */ }
            Err(e) => {
                // debugfs may momentarily be missing; don’t crash the daemon
                eprintln!("read {} failed: {e}", HANDSHAKE_PATH);
            }
        }

        // simple, reliable backoff (you can switch to inotify later)
        sleep(Duration::from_millis(200)).await;
    }
}



#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting wg-zk-daemon...");
    let pk = load_static_pk().with_context(|| "loading static public key")?;
    let cli = Cli::parse();


        match cli.cmd {
            Commands::SendVerifyAck { peer_index, result, family, version } => {
            // if your netlink module exposes an async helper that resolves family+builds msg:
            netlink::send_verify_ack(&family, version, peer_index, result)
                .await
                .with_context(|| "sending VERIFY_ACK failed")?;
            Ok(())
        }
        Commands::Daemon => run_daemon(pk).await,

    }

}