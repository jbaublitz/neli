use neli::{
    consts::{
        nl::{GenlId, NlmF},
        socket::NlFamily,
    },
    err::NlError,
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    socket::NlSocketHandle,
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

    let mut sock = NlSocketHandle::connect(
        NlFamily::Generic, /* family */
        None,              /* pid */
        Groups::empty(),   /* groups */
    )?;
    sock.enable_ext_ack(true)?;
    let family_id = sock.resolve_genl_family("nl80211")?;
    let mut attrs = GenlBuffer::new();

    attrs.push(
        Nlattr::new(
            /* Attribute */ Nl80211Attribute::Mac,
            /* Value */ vec![0_u8], /* NOTE: Deliberately wrong length */
        )
        .unwrap(),
    );

    let req = NlmsghdrBuilder::default()
        .nl_type(family_id)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_seq(1)
        .nl_payload(NlPayload::Payload(Genlmsghdr::<
            Nl80211Command,
            Nl80211Attribute,
        >::new(
            /* cmd */ Nl80211Command::GetInterface,
            /* version */ 1,
            /* attrs */ attrs,
        )))
        .build()?;

    sock.send(req)?;
    let data: Result<Option<Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>>, _> =
        sock.recv();
    match data {
        Ok(msgs) => {
            println!("msgs: {:?}", msgs);
        }
        Err(NlError::Nlmsgerr(e)) => {
            println!("msg err: {:?}", e);
            println!(
                "unix error: {:?}",
                std::io::Error::from_raw_os_error(-e.error)
            );
            for attr in e.ext_ack.iter() {
                match ExtAckAttr::from(u16::from(&attr.nla_type)) {
                    ExtAckAttr::Msg => {
                        println!(
                            "Msg={:?}",
                            String::from_utf8(attr.nla_payload.as_ref().to_vec())
                        );
                    }
                    ExtAckAttr::Offs => {
                        println!("Offs={:?}", attr.nla_payload.as_ref());
                    }
                    ExtAckAttr::Cookie => {
                        println!("Cookie={:?}", attr.nla_payload.as_ref());
                    }
                    ExtAckAttr::Policy => {
                        println!("Policy={:?}", attr.nla_payload.as_ref());
                    }
                    _ => println!("attr: {:?}", attr),
                }
            }
        }
        Err(e) => {
            println!("err: {:#?}", e);
        }
    }
    Ok(())
}
