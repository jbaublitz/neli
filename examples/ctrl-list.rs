use neli::{
    consts::{CtrlAttr, CtrlCmd, GenlId, NlFamily, NlmF, NlmFFlags, Nlmsg},
    err::NlError,
    genl::Genlmsghdr,
    nl::Nlmsghdr,
    socket::NlSocket,
    Buffer, Bytes, GenlBuffer, Nl, SmallVec, U32Bitmask,
};

const GENL_VERSION: u8 = 2;

// This example attempts to mimic the "genl ctrl list" command. For simplicity, it only outputs
// the name and identifier of each generic netlink family.

fn main() -> Result<(), NlError> {
    let mut socket = NlSocket::connect(NlFamily::Generic, None, U32Bitmask::empty())?;

    let attrs: GenlBuffer<CtrlAttr, Buffer> = SmallVec::new();
    let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, GENL_VERSION, attrs);
    let nlhdr = {
        let len = None;
        let nl_type = GenlId::Ctrl;
        let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
        let seq = None;
        let pid = None;
        let payload = genlhdr;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };
    socket.send_nl(nlhdr)?;

    let mut iter = socket.iter::<Nlmsg, Genlmsghdr<CtrlCmd, CtrlAttr>>();
    while let Some(Ok(response)) = iter.next() {
        match response.nl_type {
            // This example could be improved by reinterpreting the payload as an Nlmsgerr struct
            // and printing the specific error encountered.
            Nlmsg::Error => {
                return Err(NlError::new(
                    "An error occurred while retrieving available families",
                ))
            }
            Nlmsg::Done => break,
            _ => (),
        };

        let handle = response.nl_payload.get_attr_handle();

        for attr in handle.iter() {
            match &attr.nla_type {
                CtrlAttr::FamilyName => {
                    let mem = Bytes::from(attr.payload.as_ref());
                    let name = String::deserialize(mem)?;
                    println!("{}", name);
                }
                CtrlAttr::FamilyId => {
                    let mem = Bytes::from(attr.payload.as_ref());
                    let id = u16::deserialize(mem)?;
                    println!("\tID: 0x{:x}", id);
                }
                _ => {}
            }
        }
    }

    Ok(())
}
