use std::error::Error;

#[cfg(feature = "async")]
use neli::socket::tokio::NlSocket;
use neli::{
    consts::{
        nl::{GenlId, NlmF, NlmFFlags},
        socket::NlFamily,
    },
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::GenlBuffer,
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
    println!("msg={:?}", msg.nl_type);
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        &[],               /* groups */
    )?;
    let family_id = sock.resolve_genl_family("nl80211")?;

    let mut ss = NlSocket::new(sock)?;

    let req = &Nlmsghdr::new(
        /* len */ None,
        /* type */ family_id,
        /* flags */ NlmFFlags::new(&[NlmF::Request, NlmF::Dump, NlmF::Ack]),
        /* seq */ Some(1),
        /* pid */ Some(0),
        /* payload */
        NlPayload::Payload(Genlmsghdr::<Nl80211Command, Nl80211Attribute>::new(
            /* cmd */ Nl80211Command::GetWiPhy,
            /* version */ 1,
            /* attrs */ GenlBuffer::new(),
        )),
    );

    ss.send(req).await?;

    let mut buffer = Vec::new();

    let msgs = ss.recv(&mut buffer).await?;
    println!("msgs: {:?}", msgs);
    for msg in msgs {
        if let NlPayload::Err(e) = msg.nl_payload {
            if e.error == -2 {
                println!(
                    "This test is not supported on this machine as it requires nl80211; skipping"
                );
            } else {
                return Err(Box::new(e) as Box<dyn Error>);
            }
        } else {
            handle(msg);
        }
    }
    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic, /* family */
        Some(0),           /* pid */
        &[],               /* groups */
    )?;
    let family_id = sock.resolve_genl_family("nl80211")?;

    let req = Nlmsghdr::new(
        /* len */ None,
        /* type */ family_id,
        /* flags */ NlmFFlags::new(&[NlmF::Request, NlmF::Dump, NlmF::Ack]),
        /* seq */ Some(1),
        /* pid */ Some(0),
        /* payload */
        NlPayload::Payload(Genlmsghdr::<Nl80211Command, Nl80211Attribute>::new(
            /* cmd */ Nl80211Command::GetWiPhy,
            /* version */ 1,
            /* attrs */ GenlBuffer::new(),
        )),
    );

    sock.send(req)?;

    for msg in sock.iter(false) {
        let msg = msg?;
        if let NlPayload::Err(e) = msg.nl_payload {
            if e.error == -2 {
                println!(
                    "This test is not supported on this machine as it requires nl80211; skipping"
                );
            } else {
                return Err(Box::new(e) as Box<dyn Error>);
            }
        } else {
            handle(msg);
        }
    }
    Ok(())
}
