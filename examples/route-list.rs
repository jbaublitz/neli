use std::{
    collections::HashMap,
    error::Error,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use neli::{
    consts::{nl::*, rtnl::*, socket::*},
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::*,
    socket::*,
    types::RtBuffer,
};

fn parse_route_table(
    ifs: &HashMap<IpAddr, String>,
    rtm: Nlmsghdr<NlTypeWrapper, Rtmsg>,
) -> Result<(), NlError> {
    let payload = rtm.get_payload()?;
    // This sample is only interested in the main table.
    if payload.rtm_table == RtTable::Main {
        let mut src = None;
        let mut dst = None;
        let mut gateway = None;

        for attr in payload.rtattrs.iter() {
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

            match attr.rta_type {
                Rta::Dst => dst = to_addr(attr.rta_payload.as_ref()),
                Rta::Prefsrc => src = to_addr(attr.rta_payload.as_ref()),
                Rta::Gateway => gateway = to_addr(attr.rta_payload.as_ref()),
                _ => (),
            }
        }

        if let Some(dst) = dst {
            print!("{}/{} ", dst, payload.rtm_dst_len);
        } else {
            print!("default ");
            if let Some(gateway) = gateway {
                print!("via {} ", gateway);
            }
        }

        if let Some(src) = src {
            print!("dev {}", ifs.get(&src).expect("Should be present"));
        }

        if payload.rtm_scope != RtScope::Universe {
            print!(
                " proto {:?}  scope {:?} ",
                payload.rtm_protocol, payload.rtm_scope
            )
        }
        if let Some(src) = src {
            print!(" src {} ", src);
        }
        println!();
    }

    Ok(())
}

/// This sample is a simple imitation of the `ip route` command, to demonstrate interaction
/// with the rtnetlink subsystem.  
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();

    let ifmsg = Ifaddrmsg {
        ifa_family: RtAddrFamily::Unspecified,
        ifa_prefixlen: 0,
        ifa_flags: IfaFFlags::empty(),
        ifa_scope: 0,
        ifa_index: 0,
        rtattrs: RtBuffer::new(),
    };
    let nlhdr = Nlmsghdr::new(
        None,
        Rtm::Getaddr,
        NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
        None,
        None,
        NlPayload::Payload(ifmsg),
    );
    socket.send(nlhdr)?;

    let mut ifs_v = Vec::new();
    for msg in socket.iter::<Rtm, _>(false) {
        let msg = msg?;
        if let NlPayload::Payload(p) = msg.nl_payload {
            ifs_v.push(p);
        }
    }
    let ifs = ifs_v
        .into_iter()
        .try_fold(HashMap::new(), |mut hm, payload: Ifaddrmsg| {
            let handle = payload.rtattrs.get_attr_handle();
            let addr = {
                if let Ok(mut ip_bytes) = handle.get_attr_payload_as_with_len::<&[u8]>(Ifa::Address)
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
                        return Err(NlError::new(format!(
                            "Unrecognized address length of {} found",
                            ip_bytes.len()
                        )));
                    }
                } else {
                    None
                }
            };
            let name = handle
                .get_attr_payload_as_with_len::<String>(Ifa::Label)
                .ok();
            if let (Some(addr), Some(name)) = (addr, name) {
                hm.insert(addr, name);
            }
            Result::<_, NlError>::Ok(hm)
        })?;

    let rtmsg = Rtmsg {
        rtm_family: RtAddrFamily::Inet,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Unspec,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unspec,
        rtm_flags: RtmFFlags::empty(),
        rtattrs: RtBuffer::new(),
    };
    let nlhdr = {
        let len = None;
        let nl_type = Rtm::Getroute;
        let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
        let seq = None;
        let pid = None;
        let payload = rtmsg;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, NlPayload::Payload(payload))
    };
    socket.send(nlhdr).unwrap();

    for rtm_result in socket.iter(false) {
        let rtm = rtm_result?;
        if let NlTypeWrapper::Rtm(_) = rtm.nl_type {
            parse_route_table(&ifs, rtm)?;
        }
    }
    Ok(())
}
