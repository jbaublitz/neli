extern crate neli;

use std::{convert::TryInto, error::Error, net::IpAddr};

use neli::{
    consts::{nl::*, rtnl::*, socket::*},
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::*,
    socket::*,
    types::RtBuffer,
};

fn index_to_interface(index: u32) -> String {
    let mut buff = [0i8; 16];
    let buff: [u8; 16] = unsafe {
        libc::if_indextoname(index, &mut buff[0]);
        std::mem::transmute(buff)
    };
    std::str::from_utf8(&buff)
        .unwrap()
        .trim_matches(char::from(0))
        .to_string()
}

fn parse_route_table(rtm: Nlmsghdr<NlTypeWrapper, Rtmsg>) -> Result<(), NlError> {
    let payload = rtm.get_payload()?;
    // This sample is only interested in the main table.
    if payload.rtm_table == RtTable::Main {
        let mut src = None;
        let mut dst = None;
        let mut gateway = None;
        let mut name = None;

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
                Rta::Oif => {
                    name = Some(index_to_interface(u32::from_le_bytes(
                        attr.rta_payload.as_ref().try_into().unwrap(),
                    )))
                }
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

        if let Some(name) = name {
            print!("dev {} ", name);
        }

        if payload.rtm_scope != RtScope::Universe {
            print!(
                "proto {:?} scope {:?} ",
                payload.rtm_protocol, payload.rtm_scope
            )
        }
        if let Some(src) = src {
            print!("src {} ", src);
        }
        println!();
    }

    Ok(())
}

/// This sample is a simple imitation of the `ip route` command, to demonstrate interaction
/// with the rtnetlink subsystem.  
fn main() -> Result<(), Box<dyn Error>> {
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();

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
            parse_route_table(rtm)?;
        }
    }
    Ok(())
}
