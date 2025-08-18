use anyhow::{bail, Context};
use neli::{
    consts::{
        genl::CtrlAttr, // only needed if you parse ctrl replies elsewhere
        nl::{GenlId, NlTypeWrapper, NlmF},
        socket::NlFamily,
    },
    genl::{AttrType, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::NlPayload,
    router::synchronous::NlRouter,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};
use neli::consts::genl::CtrlCmd;
use neli::consts::nl::Nlmsg;
use neli::genl::Nlattr;
use neli::nl::{Nlmsghdr, NlmsghdrBuilder};
use neli::socket::asynchronous::NlSocketHandle;

const WGZK_GENL: &str = "wgzk_genl";
const WGZK_VERSION: u8 = 1;
const WGZK_CMD_VERIFY: u8 = 1;
const WGZK_ATTR_PEER_INDEX: u16 = 1;
const WGZK_ATTR_RESULT: u16 = 2;

/// VERIFY_ACK
pub async fn send_verify_ack(
    family: &str,
    genl_version: u8,
    peer_index: u32,
    result: u8,
) -> anyhow::Result<()> {
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

    // let (iter, _) = sock.recv().await.context("recv failed")?;
    // for msg in iter {
    //     let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = msg?;
    //     if matches!((*msg.nl_type()).into(), Nlmsg::Error) {
    //         eprintln!("got ACK");
    //         return Ok(());
    //     }
    // }
    //

    let (iter, _) = sock.recv().await?;
    for msg in iter {
        let msg: Nlmsghdr<u16, Genlmsghdr<u8, u16>> = msg?;
        if *msg.nl_type() == u16::from(Nlmsg::Error) {
            match msg.nl_payload() {
                NlPayload::Err(e) => {
                    let code: i32 = *e.error();
                    if code == 0 {
                        // // Optional: pull extended ack text if present
                        // if let Some(human_msg) = e
                        //     .ext_ack()
                        //     .iter()
                        //     .find(|a| a.nla_type() == neli::consts::nl::NlmsgerrAttr::Msg)
                        //     .and_then(|a| std::str::from_utf8(a.nla_payload().as_ref()).ok())
                        // {
                        //     eprintln!("netlink error {}: {}", code, human_msg);
                        // }
                        //
                        // let errno = -code; // kernel sends negative errno
                        // let io_err = std::io::Error::from_raw_os_error(errno);
                        // anyhow::bail!("netlink error {} ({})", code, io_err);
                        return Ok(());
                    } else {
                        bail!("Kernel returned NLMSG_ERROR: {}", e);
                    }
                }
                _ => bail!("Expected NLMSG_ERROR payload, got something else"),
            }
        }
    }
    // if you want to be tolerant, allow no-ack success for unicast genl ops:
    bail!("no ACK (NLMSG_ERROR) received from kernel");

}


/// Family id çöz
async fn resolve_family_id(sock: &mut NlSocketHandle, name: &str) -> anyhow::Result<u16> {
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
                let ty: u16 = (*attr.nla_type().nla_type()).into();
                // if u16::from(*attr.nla_type().nla_type()) ==  u16::from(CtrlAttr::FamilyId)
                if ty == u16::from(CtrlAttr::FamilyId)
                {
                    let bytes = attr.nla_payload().as_ref();
                    let id = if bytes.len() >= 2 {
                        u16::from_ne_bytes([bytes[0], bytes[1]])
                    } else {
                        bail!("CTRL_ATTR_FAMILY_ID payload too short");
                    };

                    // let id = u16::from_ne_bytes(
                    //     attr.nla_payload().as_ref()[..2].try_into().unwrap(),
                    // );
                    return Ok(id);
                }
            }
        }
    }
    bail!("family '{}' id not found", name)
}
