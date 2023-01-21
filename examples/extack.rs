use std::iter::once;

use neli::{
    consts::{
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    err::RouterError,
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader},
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::NlRouter,
    types::GenlBuffer,
    utils::Groups,
};

#[neli::neli_enum(serialized_type = "u8")]
pub enum Nl80211Command {
    GetInterface = 5,
    /* Others elided */
}
impl neli::consts::genl::Cmd for Nl80211Command {}

#[neli::neli_enum(serialized_type = "u16")]
pub enum Nl80211Attribute {
    Mac = 6,
    /* Attributes Elided */
}
impl neli::consts::genl::NlAttrType for Nl80211Attribute {}

#[neli::neli_enum(serialized_type = "u16")]
pub enum ExtAckAttr {
    Unused = 0,
    Msg = 1,
    Offs = 2,
    Cookie = 3,
    Policy = 4,
}
impl neli::consts::genl::NlAttrType for ExtAckAttr {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let (sock, _) = NlRouter::connect(
        NlFamily::Generic, /* family */
        None,              /* pid */
        Groups::empty(),   /* groups */
    )?;
    sock.enable_ext_ack(true)?;
    let family_id = sock.resolve_genl_family("nl80211")?;
    let attrs = once(
        NlattrBuilder::default()
            .nla_type(
                AttrTypeBuilder::default()
                    .nla_type(/* Attribute */ Nl80211Attribute::Mac)
                    .build()
                    .unwrap(),
            )
            .nla_payload(
                /* Value */ vec![0_u8], /* NOTE: Deliberately wrong length */
            )
            .build()
            .unwrap(),
    )
    .collect::<GenlBuffer<_, _>>();

    let mut recv = sock.send::<_, _, GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
        family_id,
        NlmF::ACK,
        NlPayload::Payload(
            GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
                .cmd(Nl80211Command::GetInterface)
                .version(1)
                .attrs(attrs)
                .build()?,
        ),
    )?;
    let data: Option<Result<Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>, _>> =
        recv.next();
    match data {
        Some(Ok(msgs)) => {
            println!("msgs: {:?}", msgs);
        }
        Some(Err(RouterError::Nlmsgerr(e))) => {
            println!("msg err: {:?}", e);
            println!(
                "unix error: {:?}",
                std::io::Error::from_raw_os_error(-e.error())
            );
            for attr in e.ext_ack().iter() {
                match ExtAckAttr::from(u16::from(attr.nla_type())) {
                    ExtAckAttr::Msg => {
                        println!(
                            "Msg={:?}",
                            String::from_utf8(attr.nla_payload().as_ref().to_vec())
                        );
                    }
                    ExtAckAttr::Offs => {
                        println!("Offs={:?}", attr.nla_payload().as_ref());
                    }
                    ExtAckAttr::Cookie => {
                        println!("Cookie={:?}", attr.nla_payload().as_ref());
                    }
                    ExtAckAttr::Policy => {
                        println!("Policy={:?}", attr.nla_payload().as_ref());
                    }
                    _ => println!("attr: {:?}", attr),
                }
            }
        }
        Some(Err(e)) => {
            println!("err: {:#?}", e);
        }
        None => {
            println!("No messages received");
        }
    }
    Ok(())
}
