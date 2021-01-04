use std::net::Ipv4Addr;

use neli::{
    attr::Attribute,
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{Ifa, IfaFFlags, RtAddrFamily, RtScope, Rtm},
        socket::NlFamily,
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::Ifaddrmsg,
    socket::NlSocketHandle,
    types::RtBuffer,
    utils::U32Bitmask,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rtnl = NlSocketHandle::connect(NlFamily::Route, None, U32Bitmask::empty())?;
    let ifaddrmsg = Ifaddrmsg {
        ifa_family: RtAddrFamily::Inet,
        ifa_prefixlen: 0,
        ifa_flags: IfaFFlags::empty(),
        ifa_scope: 0,
        ifa_index: 0,
        rtattrs: RtBuffer::new(),
    };
    let nl_header = Nlmsghdr::new(
        None,
        Rtm::Getaddr,
        NlmFFlags::new(&[NlmF::Request, NlmF::Root]),
        None,
        None,
        NlPayload::Payload(ifaddrmsg),
    );
    rtnl.send(nl_header)?;
    let mut addrs = Vec::<Ipv4Addr>::with_capacity(1);
    for response in rtnl.iter(false) {
        let header: Nlmsghdr<_, Ifaddrmsg> = response?;
        if header.nl_type != Rtm::Newaddr.into() {
            return Err(Box::new(NlError::new(
                "Netlink error retrieving IP address",
            )));
        }
        let msg = header.get_payload()?;
        if RtScope::from(msg.ifa_scope) != RtScope::Universe {
            continue;
        }
        for rtattr in msg.rtattrs.iter() {
            if rtattr.rta_type == Ifa::Local {
                addrs.push(Ipv4Addr::from(u32::from_be(
                    rtattr.get_payload_as::<u32>()?,
                )));
            }
        }
    }

    println!("Local IPv4 addresses:");
    for addr in addrs {
        println!("{}", addr);
    }

    Ok(())
}
