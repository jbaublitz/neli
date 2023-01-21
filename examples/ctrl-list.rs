use std::error::Error;

use neli::{
    attr::Attribute,
    consts::{genl::*, nl::*, socket::*},
    genl::{Genlmsghdr, GenlmsghdrBuilder},
    nl::NlPayload,
    router::synchronous::NlRouter,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

const GENL_VERSION: u8 = 2;

// This example attempts to mimic the "genl ctrl list" command. For simplicity, it only outputs
// the name and identifier of each generic netlink family.

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let (socket, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())?;
    let recv = socket.send::<_, _, NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(
        GenlId::Ctrl,
        NlmF::DUMP,
        NlPayload::Payload(
            GenlmsghdrBuilder::default()
                .cmd(CtrlCmd::Getfamily)
                .version(GENL_VERSION)
                .attrs(GenlBuffer::<u16, Buffer>::new())
                .build()?,
        ),
    )?;

    for response_result in recv {
        let response = response_result?;

        if let Some(p) = response.get_payload() {
            let handle = p.get_attr_handle();
            for attr in handle.iter() {
                match attr.nla_type().nla_type() {
                    CtrlAttr::FamilyName => {
                        println!("{}", attr.get_payload_as_with_len::<String>()?);
                    }
                    CtrlAttr::FamilyId => {
                        println!("\tID: 0x{:x}", attr.get_payload_as::<u16>()?);
                    }
                    _ => (),
                }
            }
        }
    }

    Ok(())
}
