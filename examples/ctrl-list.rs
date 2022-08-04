use std::error::Error;

use neli::{
    attr::Attribute,
    consts::{genl::*, nl::*, socket::*},
    genl::Genlmsghdr,
    nl::{NlPayload, NlmsghdrBuilder},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

const GENL_VERSION: u8 = 2;

// This example attempts to mimic the "genl ctrl list" command. For simplicity, it only outputs
// the name and identifier of each generic netlink family.

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, Groups::empty())?;

    let attrs = GenlBuffer::<NlAttrTypeWrapper, Buffer>::new();
    let nlhdr = NlmsghdrBuilder::default()
        .nl_type(GenlId::Ctrl)
        .nl_flags(NlmF::REQUEST | NlmF::DUMP)
        .nl_payload(NlPayload::Payload(Genlmsghdr::new(
            CtrlCmd::Getfamily,
            GENL_VERSION,
            attrs,
        )))
        .build()?;
    socket.send(nlhdr)?;

    let iter = socket.iter::<NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(false);
    for response_result in iter {
        let response = response_result?;

        if let Some(p) = response.nl_payload.get_payload() {
            let handle = p.get_attr_handle();
            for attr in handle.iter() {
                match &attr.nla_type.nla_type {
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
