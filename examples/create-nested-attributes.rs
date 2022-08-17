extern crate neli;

use std::{error::Error, io::Cursor};

use neli::{
    consts::{genl::*, nl::*},
    genl::{GenlmsghdrBuilder, Nlattr},
    nl::{NlPayload, NlmsghdrBuilder},
    types::GenlBuffer,
    ToBytes,
};

pub fn main() -> Result<(), Box<dyn Error>> {
    // The following works as Nlattr payload types are the same but is STRONGLY discouraged.
    // As of v0.7.0, this can cause breakage due to the flag indicating whether an
    // attribute is nested is handled automatically.
    //
    // let attrs = vec![Nlattr::new(1, vec![Nlattr::new(false, 1, "this_family")?]),
    //                  Nlattr::new(2, vec![Nlattr::new(false, 1, "that_family")?])];

    // let genlmsg = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs)?;
    // let nlmsg = Nlmsghdr::new(None, Nlmsg::Noop, vec![consts::NlmF::Request], None, None,
    //                           Some(genlmsg));
    // let mut buffer = neli::BytesMut::from(vec![0; nlmsg.asize()]);
    // nlmsg.serialize(&mut buffer)?;
    // println!("Serialized homogeneous nested attributes: {:?}", buffer.as_ref());

    // This is also discouraged because the following method does not work -
    // the payload type of one nested attribute is a &str while another is an integer value:
    //
    // let attrs = vec![Nlattr::new(1, vec![
    //                Nlattr::new(1, "this_family"),
    //                Nlattr::new(2, 0),
    //           ]), Nlattr::new(2, vec![
    //                Nlattr::new(1, "that_family"),
    //                Nlattr::new(2, 5),
    //            ])];

    // Instead, do the following:
    let mut attrs = GenlBuffer::new();
    attrs.push(
        Nlattr::new(0, Vec::<u8>::new())?
            .nest(&Nlattr::new(1, "this is a string")?)?
            .nest(&Nlattr::new(2, 0)?)?,
    );
    attrs.push(
        Nlattr::new(2, Vec::<u8>::new())?
            .nest(&Nlattr::new(1, "this is also a string")?)?
            .nest(&Nlattr::new(2, 5)?)?,
    );

    let genlmsg = GenlmsghdrBuilder::default()
        .cmd(CtrlCmd::Getfamily)
        .version(2)
        .attrs(attrs)
        .build()?;
    let nlmsg = NlmsghdrBuilder::default()
        .nl_type(Nlmsg::Noop)
        .nl_flags(NlmF::REQUEST)
        .nl_payload(NlPayload::Payload(genlmsg))
        .build()?;
    let mut buffer = Cursor::new(Vec::new());
    nlmsg.to_bytes(&mut buffer)?;
    println!(
        "Serialized heterogeneous attributes: {:?}",
        buffer.into_inner()
    );
    Ok(())
}
