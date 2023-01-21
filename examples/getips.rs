use std::net::Ipv4Addr;

use neli::{
    attr::Attribute,
    consts::{
        nl::NlmF,
        rtnl::{Ifa, RtAddrFamily, RtScope, Rtm},
        socket::NlFamily,
    },
    err::MsgError,
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::NlRouter,
    rtnl::{Ifaddrmsg, IfaddrmsgBuilder},
    utils::Groups,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())?;
    let ifaddrmsg = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet)
        .ifa_prefixlen(0)
        .ifa_scope(RtScope::Universe)
        .ifa_index(0)
        .build()?;
    let recv = rtnl.send(Rtm::Getaddr, NlmF::ROOT, NlPayload::Payload(ifaddrmsg))?;
    let mut addrs = Vec::<Ipv4Addr>::with_capacity(1);
    for response in recv {
        let header: Nlmsghdr<Rtm, Ifaddrmsg> = response?;
        if let NlPayload::Payload(p) = header.nl_payload() {
            if header.nl_type() != &Rtm::Newaddr {
                return Err(Box::new(MsgError::new(
                    "Netlink error retrieving IP address",
                )));
            }
            if p.ifa_scope() != &RtScope::Universe {
                continue;
            }
            for rtattr in p.rtattrs().iter() {
                if rtattr.rta_type() == &Ifa::Local {
                    addrs.push(Ipv4Addr::from(u32::from_be(
                        rtattr.get_payload_as::<u32>()?,
                    )));
                }
            }
        }
    }

    println!("Local IPv4 addresses:");
    for addr in addrs {
        println!("{}", addr);
    }

    Ok(())
}
