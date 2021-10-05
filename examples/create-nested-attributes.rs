extern crate neli;

use std::{error::Error, io::Cursor};

use neli::{
    consts::{genl::*, nl::*},
    genl::{Genlmsghdr, Nlattr},
    nl::{NlPayload, Nlmsghdr},
    types::GenlBuffer,
    ToBytes,
};

pub fn main() -> Result<(), Box<dyn Error>> {
    // The following works as Nlattr payload types are the same but is STRONGLY discouraged
    //
    // let attrs = vec![Nlattr::new(None, 1, vec![Nlattr::new(None, 1, "this_family")?]),
    //                  Nlattr::new(None, 2, vec![Nlattr::new(None, 1, "that_family")?])];

    // let genlmsg = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs)?;
    // let nlmsg = Nlmsghdr::new(None, Nlmsg::Noop, vec![consts::NlmF::Request], None, None,
    //                           Some(genlmsg));
    // let mut buffer = neli::BytesMut::from(vec![0; nlmsg.asize()]);
    // nlmsg.serialize(&mut buffer)?;
    // println!("Serialized homogeneous nested attributes: {:?}", buffer.as_ref());

    // This is discouraged because the following method does not work -
    // the payload type of one nested attribute is a &str while another is an integer value:
    //
    // let attrs = vec![Nlattr::new(None, 1, vec![
    //                Nlattr::new(None, 1, "this_family"),
    //                Nlattr::new(None, 2, 0),
    //           ]), Nlattr::new(None, 2, vec![
    //                Nlattr::new(None, 1, "that_family"),
    //                Nlattr::new(None, 2, 5),
    //            ])];

    // Instead, do the following:
    let mut attr1 = Nlattr::new(true, false, 0, Vec::<u8>::new())?;
    attr1.add_nested_attribute(&Nlattr::new(false, false, 1, "this is a string")?)?;
    // This is not a string
    attr1.add_nested_attribute(&Nlattr::new(false, false, 2, 0)?)?;

    // And again for another set of nested attributes
    let mut attr2 = Nlattr::new(true, false, 2, Vec::<u8>::new())?;
    attr2.add_nested_attribute(&Nlattr::new(false, false, 1, "this is also a string")?)?;
    // Not a string
    attr2.add_nested_attribute(&Nlattr::new(false, false, 2, 5)?)?;

    let mut attrs = GenlBuffer::new();
    attrs.push(attr1);
    attrs.push(attr2);

    let genlmsg = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs);
    let nlmsg = Nlmsghdr::new(
        None,
        Nlmsg::Noop,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(genlmsg),
    );
    let mut buffer = Cursor::new(Vec::new());
    nlmsg.to_bytes(&mut buffer)?;
    println!(
        "Serialized heterogeneous attributes: {:?}",
        buffer.into_inner()
    );
    Ok(())
}
