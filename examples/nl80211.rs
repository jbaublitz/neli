use std::error::Error;

#[cfg(feature = "async")]
use neli::router::asynchronous::NlRouter;
#[cfg(not(feature = "async"))]
use neli::router::synchronous::NlRouter;
use neli::{
    consts::{
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    genl::{Genlmsghdr, GenlmsghdrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr},
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

    let (sock, _) = NlRouter::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )
    .await?;
    let family_id = sock.resolve_genl_family("nl80211").await?;

    let mut recv = sock
        .send::<_, _, u16, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(
                GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                    .cmd(Nl80211Command::GetWiPhy)
                    .version(1)
                    .build()?,
            ),
        )
        .await?;

    while let Some(Ok(msg)) = recv.next().await {
        handle(msg);
    }
    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let (sock, _) = NlRouter::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        Groups::empty(),   /* groups */
    )?;
    let family_id = sock.resolve_genl_family("nl80211")?;

    let recv = sock.send(
        family_id,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(
            GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                .cmd(Nl80211Command::GetWiPhy)
                .version(1)
                .build()?,
        ),
    )?;

    for msg in recv {
        let msg = msg?;
        handle(msg);
    }
    Ok(())
}
