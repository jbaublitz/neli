use std::error::Error;

use neli::{
    attr::Attribute,
    consts::{genl::*, nl::*, socket::*},
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};

const GENL_VERSION: u8 = 2;

// This example attempts to mimic the "genl ctrl list" command. For simplicity, it only outputs
// the name and identifier of each generic netlink family.

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[])?;

    let attrs = GenlBuffer::<NlAttrTypeWrapper, Buffer>::new();
    let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, GENL_VERSION, attrs);
    let nlhdr = {
        let len = None;
        let nl_type = GenlId::Ctrl;
        let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
        let seq = None;
        let pid = None;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(genlhdr))
    };
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
