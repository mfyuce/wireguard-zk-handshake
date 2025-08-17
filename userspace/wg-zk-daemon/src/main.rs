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
use std::{fs, thread, time::Duration};
use neli::socket::asynchronous::NlSocketHandle;
use neli::utils::Groups;


/// Resolve family id via CTRL_CMD_GETFAMILY
use neli::consts::nl::GenlId;// Netlink attribute builder

use neli::consts::socket::NlFamily;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY},
};

use tokio::{fs as tfs, time::sleep};
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

fn load_static_pk() -> EdwardsPoint {
    let hex = fs::read_to_string("config/static_pk.hex").expect("missing static_pk");
    let pk_bytes = hex::decode(hex.trim()).expect("bad hex");
    decompress_point(&pk_bytes).expect("invalid point")
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
                        if let Err(e) = netlink::send_wgzk_ack(sender_index, 0).await {
                            eprintln!("netlink ack (fail) error: {e:#}");
                        }
                        sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                };

                let Ok(arr) = <[u8; 32]>::try_from(&buf[64..96]) else {
                    eprintln!("Bad zk_s slice for peer {sender_index}");
                    if let Err(e) = netlink::send_wgzk_ack(sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                    sleep(Duration::from_millis(200)).await;
                    continue;
                };

                let Some(zk_s) = Scalar::from_canonical_bytes(arr).into() else {
                    eprintln!("Non-canonical zk_s for peer {sender_index}");
                    if let Err(e) = netlink::send_wgzk_ack(sender_index, 0).await {
                        eprintln!("netlink ack (fail) error: {e:#}");
                    }
                    sleep(Duration::from_millis(200)).await;
                    continue;
                };

                let ok = verify_proof(pk, zk_r, zk_s);
                if ok {
                    eprintln!("ZK verified for peer {}", sender_index);
                    if let Err(e) = netlink::send_wgzk_ack(sender_index, 1).await {
                        eprintln!("netlink ack (success) error: {e:#}");
                    }
                } else {
                    eprintln!("ZK failed for peer {}", sender_index);
                    if let Err(e) = netlink::send_wgzk_ack(sender_index, 0).await {
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
    let pk = load_static_pk();
    let cli = Cli::parse();


        match cli.cmd {
            Commands::SendVerifyAck { peer_index, result, family, version } => {
            // if your netlink module exposes an async helper that resolves family+builds msg:
            send_verify_ack(&family, version, peer_index, result)
                .await
                .with_context(|| "sending VERIFY_ACK failed")?;
            Ok(())
        }
        Commands::Daemon => run_daemon(pk).await,

    }

}
/// Family id çöz
async fn resolve_family_id(sock: &mut NlSocketHandle, name: &str) -> Result<u16> {
    // family name attribute
    let attr: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(u16::from(CtrlAttr::FamilyName)))
        .nla_payload(Buffer::from(name.as_bytes().to_vec()))
        .build()?;

    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
    // attribute’ları ekle
    attrs.push(attr);

    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(CtrlCmd::Getfamily)
        .version(1)
        .attrs(attrs)
        .build()?;

    let nlhdr = NlmsghdrBuilder::default()
        .nl_type(GenlId::Ctrl)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&nlhdr).await?;

    let (iter, _) = sock.recv().await?;
    for msg in iter {
        let msg: Nlmsghdr<u16, Genlmsghdr<CtrlCmd, CtrlAttr>> = msg?;
        if let NlPayload::Payload(p) = msg.nl_payload() {
            for attr in p.attrs().iter() {
                if u16::from(*attr.nla_type().nla_type()) ==  u16::from(CtrlAttr::FamilyId) {
                    let id = u16::from_ne_bytes(
                        attr.nla_payload().as_ref()[..2].try_into().unwrap(),
                    );
                    return Ok(id);
                }
            }
        }
    }
    bail!("family '{}' id not found", name)
}


/// VERIFY_ACK gönder
pub async fn send_verify_ack(
    family: &str,
    genl_version: u8,
    peer_index: u32,
    result: u8,
) -> Result<()> {
    const WGZK_CMD_VERIFY_ACK: u8 = 1;
    const WGZK_ATTR_PEER_INDEX: u16 = 1;
    const WGZK_ATTR_RESULT: u16 = 2;

    let mut sock = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?;

    let fam_id = resolve_family_id(&mut sock, family).await?;
    eprintln!("family '{}' resolved to id {}", family, fam_id);



    use neli::genl::{AttrType, Nlattr};
    use neli::types::{Buffer, GenlBuffer};

    // constants
    let a1: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_PEER_INDEX))
        .nla_payload(Buffer::from(peer_index.to_ne_bytes().to_vec()))
        .build()?;

    let a2: Nlattr<u16, Buffer> = NlattrBuilder::default()
        .nla_type(AttrType::from(WGZK_ATTR_RESULT))
        .nla_payload(Buffer::from(vec![result]))
        .build()?;
    let mut attrs: GenlBuffer<u16, Buffer> = GenlBuffer::new();
    // attribute’ları ekle
    attrs.push(a1);
    attrs.push(a2);


    let genlhdr = GenlmsghdrBuilder::default()
        .cmd(WGZK_CMD_VERIFY_ACK)
        .version(genl_version)
        .attrs(attrs)
        .build()?;


    let nlhdr = NlmsghdrBuilder::default()
        .nl_type(fam_id)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(genlhdr))
        .build()?;

    sock.send(&nlhdr).await.context("send failed")?;

    let (iter, _) = sock.recv().await.context("recv failed")?;
    for msg in iter {
        let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = msg?;
        if matches!((*msg.nl_type()).into(), Nlmsg::Error) {
            eprintln!("got ACK");
            return Ok(());
        }
    }

    bail!("no ACK received")
}