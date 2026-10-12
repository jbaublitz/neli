extern crate neli;

use std::{error::Error, io::Cursor};

use neli::{
    Size, ToBytes,
    consts::{genl::*, nl::*},
    genl::{AttrTypeBuilder, GenlmsghdrBuilder, NlattrBuilder},
    nl::{NlPayload, NlmsghdrBuilder},
    types::GenlBuffer,
};

pub fn main() -> Result<(), Box<dyn Error>> {
    let attrs = vec![
        NlattrBuilder::default()
            .nla_type(AttrTypeBuilder::default().nla_type(0).build()?)
            .nla_payload(Vec::<u8>::new())
            .build()?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(AttrTypeBuilder::default().nla_type(1).build()?)
                    .nla_payload("this is a string")
                    .build()?,
            )?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(AttrTypeBuilder::default().nla_type(1).build()?)
                    .nla_payload(0)
                    .build()?,
            )?,
        NlattrBuilder::default()
            .nla_type(AttrTypeBuilder::default().nla_type(2).build()?)
            .nla_payload(Vec::<u8>::new())
            .build()?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(AttrTypeBuilder::default().nla_type(1).build()?)
                    .nla_payload("this is also a string")
                    .build()?,
            )?
            .nest(
                &NlattrBuilder::default()
                    .nla_type(AttrTypeBuilder::default().nla_type(2).build()?)
                    .nla_payload(5)
                    .build()?,
            )?,
    ]
    .into_iter()
    .collect::<GenlBuffer<_, _>>();

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
    let mut buffer = Cursor::new(vec![0; nlmsg.padded_size()]);
    nlmsg.to_bytes(&mut buffer)?;
    println!(
        "Serialized heterogeneous attributes: {:?}",
        buffer.into_inner()
    );
    Ok(())
}
