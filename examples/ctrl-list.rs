extern crate neli;
use neli::consts::{CtrlAttr, CtrlCmd, GenlId, NlFamily, NlmF, Nlmsg};
use neli::err::NlError;
use neli::genl::Genlmsghdr;
use neli::nl::Nlmsghdr;
use neli::nlattr::Nlattr;
use neli::socket::NlSocket;
use neli::Nl;
use neli::StreamReadBuffer;

const GENL_VERSION: u8 = 2;

// This example attempts to mimic the "genl ctrl list" command. For simplicity, it only outputs
// the name and identifier of each generic netlink family.

fn main() -> Result<(), NlError> {
    let mut socket = NlSocket::connect(NlFamily::Generic, None, None, true)?;

    let attrs: Vec<Nlattr<CtrlAttr>> = vec![];
    let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, GENL_VERSION, attrs)?;
    let nlhdr = {
        let len = None;
        let nl_type = GenlId::Ctrl;
        let flags = vec![NlmF::Request, NlmF::Dump];
        let seq = None;
        let pid = None;
        let payload = genlhdr;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };
    socket.send_nl(nlhdr)?;

    loop {
        let response = socket.recv_nl::<GenlId, Genlmsghdr<CtrlCmd>>(None)?;

        if let GenlId::UnrecognizedVariant(id) = response.nl_type {
            match Nlmsg::from(id) {
                // This example could be improved by reinterpreting the payload as an Nlmsgerr
                // struct and printing the specific error encountered.
                Nlmsg::Error => panic!("An error occurred while retrieving available families."),
                Nlmsg::Done => break,
                _ => {}
            }
        }

        let mut handle = response.nl_payload.get_attr_handle::<CtrlAttr>();
        handle.parse_nested_attributes()?;

        for attr in handle.iter().unwrap() {
            match &attr.nla_type {
                CtrlAttr::FamilyName => {
                    let mut mem = StreamReadBuffer::new(&attr.payload);
                    mem.set_size_hint(attr.payload.len() - 1);
                    let name = String::deserialize(&mut mem)?;
                    println!("{}", name);
                }
                CtrlAttr::FamilyId => {
                    let mut mem = StreamReadBuffer::new(&attr.payload);
                    let id = u16::deserialize(&mut mem)?;
                    println!("\tID: 0x{:x}", id);
                }
                _ => {}
            }
        }
    }

    Ok(())
}
