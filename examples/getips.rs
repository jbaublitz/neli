use std::net::Ipv4Addr;

use neli::{
    attr::Attribute,
    consts::{
        nl::NlmF,
        rtnl::{Ifa, RtAddrFamily, RtScope, Rtm},
        socket::NlFamily,
    },
    err::NlError,
    iter::IterationBehavior,
    nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder},
    rtnl::{Ifaddrmsg, IfaddrmsgBuilder},
    socket::NlSocketHandle,
    utils::Groups,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut rtnl = NlSocketHandle::connect(NlFamily::Route, None, Groups::empty())?;
    let ifaddrmsg = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet)
        .ifa_prefixlen(0)
        .ifa_scope(RtScope::Universe)
        .ifa_index(0)
        .build()?;
    let nl_header = NlmsghdrBuilder::default()
        .nl_type(Rtm::Getaddr)
        .nl_flags(NlmF::REQUEST | NlmF::ROOT)
        .nl_payload(NlPayload::Payload(ifaddrmsg))
        .build()?;
    rtnl.send(nl_header)?;
    let mut addrs = Vec::<Ipv4Addr>::with_capacity(1);
    for response in rtnl.recv(IterationBehavior::EndMultiOnDone) {
        let header: Nlmsghdr<Rtm, Ifaddrmsg> = response?;
        if let NlPayload::Payload(p) = header.nl_payload() {
            if header.nl_type() != &Rtm::Newaddr {
                return Err(Box::new(NlError::msg(
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
