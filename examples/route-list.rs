use std::{
    collections::HashMap,
    error::Error,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use neli::{
    consts::{nl::*, rtnl::*, socket::*},
    err::{MsgError, RouterError},
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::NlRouter,
    rtnl::*,
    types::Buffer,
    utils::Groups,
};

fn parse_route_table(
    ifs: &HashMap<IpAddr, String>,
    rtm: Nlmsghdr<NlTypeWrapper, Rtmsg>,
) -> Result<(), RouterError<u16, Buffer>> {
    if let Some(payload) = rtm.get_payload() {
        // This sample is only interested in the main table.
        if payload.rtm_table() == &RtTable::Main {
            let mut src = None;
            let mut dst = None;
            let mut gateway = None;

            for attr in payload.rtattrs().iter() {
                fn to_addr(b: &[u8]) -> Option<IpAddr> {
                    use std::convert::TryFrom;
                    if let Ok(tup) = <&[u8; 4]>::try_from(b) {
                        Some(IpAddr::from(*tup))
                    } else if let Ok(tup) = <&[u8; 16]>::try_from(b) {
                        Some(IpAddr::from(*tup))
                    } else {
                        None
                    }
                }

                match attr.rta_type() {
                    Rta::Dst => dst = to_addr(attr.rta_payload().as_ref()),
                    Rta::Prefsrc => src = to_addr(attr.rta_payload().as_ref()),
                    Rta::Gateway => gateway = to_addr(attr.rta_payload().as_ref()),
                    _ => (),
                }
            }

            if let Some(dst) = dst {
                print!("{}/{} ", dst, payload.rtm_dst_len());
            } else {
                print!("default ");
                if let Some(gateway) = gateway {
                    print!("via {} ", gateway);
                }
            }

            if let Some(src) = src {
                print!("dev {}", ifs.get(&src).expect("Should be present"));
            }

            if payload.rtm_scope() != &RtScope::Universe {
                print!(
                    " proto {:?}  scope {:?} ",
                    payload.rtm_protocol(),
                    payload.rtm_scope()
                )
            }
            if let Some(src) = src {
                print!(" src {} ", src);
            }
            println!();
        }
    }

    Ok(())
}

/// This sample is a simple imitation of the `ip route` command, to demonstrate interaction
/// with the rtnetlink subsystem.  
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let (socket, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();

    let ifmsg = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Unspecified)
        .ifa_prefixlen(0)
        .ifa_scope(RtScope::Universe)
        .ifa_index(0)
        .build()?;
    let recv = socket.send::<_, _, NlTypeWrapper, _>(
        Rtm::Getaddr,
        NlmF::DUMP,
        NlPayload::Payload(ifmsg),
    )?;

    let mut ifs = HashMap::new();
    for msg in recv {
        let msg = msg?;
        if let NlPayload::<_, Ifaddrmsg>::Payload(p) = msg.nl_payload() {
            let handle = p.rtattrs().get_attr_handle();
            let addr = {
                if let Ok(mut ip_bytes) =
                    handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifa::Address)
                {
                    if ip_bytes.len() == 4 {
                        let mut bytes = [0u8; 4];
                        ip_bytes.read_exact(&mut bytes)?;
                        Some(IpAddr::from(Ipv4Addr::from(
                            u32::from_ne_bytes(bytes).to_be(),
                        )))
                    } else if ip_bytes.len() == 16 {
                        let mut bytes = [0u8; 16];
                        ip_bytes.read_exact(&mut bytes)?;
                        Some(IpAddr::from(Ipv6Addr::from(
                            u128::from_ne_bytes(bytes).to_be(),
                        )))
                    } else {
                        return Err(Box::new(MsgError::new(format!(
                            "Unrecognized address length of {} found",
                            ip_bytes.len()
                        ))));
                    }
                } else {
                    None
                }
            };
            let name = handle
                .get_attr_payload_as_with_len::<String>(Ifa::Label)
                .ok();
            if let (Some(addr), Some(name)) = (addr, name) {
                ifs.insert(addr, name);
            }
        }
    }

    let rtmsg = RtmsgBuilder::default()
        .rtm_family(RtAddrFamily::Inet)
        .rtm_dst_len(0)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Unspec)
        .rtm_protocol(Rtprot::Unspec)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unspec)
        .build()?;
    let recv = socket.send(Rtm::Getroute, NlmF::DUMP, NlPayload::Payload(rtmsg))?;

    for rtm_result in recv {
        let rtm = rtm_result?;
        if let NlTypeWrapper::Rtm(_) = rtm.nl_type() {
            parse_route_table(&ifs, rtm)?;
        }
    }
    Ok(())
}
