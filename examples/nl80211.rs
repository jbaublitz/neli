use std::error::Error;

#[cfg(not(feature = "async"))]
use neli::iter::IterationBehavior;
#[cfg(feature = "async")]
use neli::socket::tokio::NlSocket;
use neli::{
    consts::{
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, GenlmsghdrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::NlSocketHandle,
    utils::Groups,
};

#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211Command {
    Unspecified = 0,
    GetWiPhy = 1,
    /* Many many more elided */
}
impl neli::consts::genl::Cmd for Nl80211Command {}

#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Attribute {
    Unspecified = 0,

    Wiphy = 1,
    /* Literally hundreds elided */
}
impl neli::consts::genl::NlAttrType for Nl80211Attribute {}

fn handle(msg: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>) {
    println!("msg={:?}", msg.nl_type());
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )?;
    let family_id = sock.resolve_genl_family("nl80211")?;

    let mut ss = NlSocket::new(sock)?;

    let req = NlmsghdrBuilder::default()
        .nl_type(family_id)
        .nl_flags(NlmF::REQUEST | NlmF::DUMP | NlmF::ACK)
        .nl_seq(1)
        .nl_payload(NlPayload::Payload(
            GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                .cmd(Nl80211Command::GetWiPhy)
                .version(1)
                .build()?,
        ))
        .build()?;

    ss.send(&req).await?;

    let mut buffer = Vec::new();

    let msgs = ss.recv(&mut buffer).await?;
    println!("msgs: {:?}", msgs);
    for msg in msgs {
        handle(msg);
    }
    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )?;
    let family_id = sock.resolve_genl_family("nl80211")?;

    let req = NlmsghdrBuilder::default()
        .nl_type(family_id)
        .nl_flags(NlmF::REQUEST | NlmF::DUMP | NlmF::ACK)
        .nl_seq(1)
        .nl_payload(NlPayload::Payload(
            GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                .cmd(Nl80211Command::GetWiPhy)
                .version(1)
                .build()?,
        ))
        .build()?;

    sock.send(req)?;

    for msg in sock.recv(IterationBehavior::EndMultiOnDone) {
        let msg = msg?;
        handle(msg);
    }
    Ok(())
}
