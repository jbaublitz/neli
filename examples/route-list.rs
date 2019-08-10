extern crate neli;

use std::error::Error;
use std::net::IpAddr;

use neli::consts::*;
use neli::err::NlError;
use neli::nl::Nlmsghdr;
use neli::rtnl::*;
use neli::socket::*;

fn parse_route_table(rtm: Nlmsghdr<Rtm, Rtmsg<Rta>>) {
    // This sample is only interested in the main table.
    if rtm.nl_payload.rtm_table == RtTable::Main {
        let mut src = None;
        let mut dst = None;
        let mut gateway = None;

        for attr in &rtm.nl_payload.rtattrs {
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
                Rta::Dst => dst = to_addr(&attr.rta_payload),
                Rta::Prefsrc => src = to_addr(&attr.rta_payload),
                Rta::Gateway => gateway = to_addr(&attr.rta_payload),
                _ => (),
            }
        }

        if let Some(dst) = dst {
            print!("{}/{} ", dst, rtm.nl_payload.rtm_dst_len);
        } else {
            print!("default ");
            if let Some(gateway) = gateway {
                print!("via {} ", gateway);
            }
        }

        if rtm.nl_payload.rtm_scope != RtScope::Universe {
            print!(
                " proto {:?}  scope {:?} ",
                rtm.nl_payload.rtm_protocol, rtm.nl_payload.rtm_scope
            )
        }
        if let Some(src) = src {
            print!(" src {} ", src);
        }
        println!();
    }
}

/// This sample is a simple imitation of the `ip route` command, to demonstrate interaction
/// with the rtnetlink subsystem.  
fn main() -> Result<(), Box<dyn Error>> {
    let mut socket = NlSocket::connect(NlFamily::Route, None, None, true).unwrap();

    let rtmsg: Rtmsg<Rta> = Rtmsg {
        rtm_family: RtAddrFamily::Inet,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Unspec,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unspec,
        rtm_flags: vec![],
        rtattrs: vec![],
    };
    let nlhdr = {
        let len = None;
        let nl_type = Rtm::Getroute;
        let flags = vec![NlmF::Request, NlmF::Dump];
        let seq = None;
        let pid = None;
        let payload = rtmsg;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };
    socket.send_nl(nlhdr).unwrap();

    // Provisionally deserialize as a Nlmsg first.
    let nl = socket.recv_nl::<Rtm, Rtmsg<Rta>>(None)?;
    let multi_msg = nl.nl_flags.contains(&NlmF::Multi);
    parse_route_table(nl);
    if multi_msg {
        while let Ok(nl) = socket.recv_nl::<u16, Rtmsg<Rta>>(None) {
            match Nlmsg::from(nl.nl_type) {
                Nlmsg::Done => return Ok(()),
                Nlmsg::Error => return Err(Box::new(NlError::new("rtnetlink error."))),
                _ => {
                    let rtm = Nlmsghdr {
                        nl_len: nl.nl_len,
                        nl_type: Rtm::from(nl.nl_type),
                        nl_flags: nl.nl_flags,
                        nl_seq: nl.nl_seq,
                        nl_pid: nl.nl_pid,
                        nl_payload: nl.nl_payload,
                    };

                    // Some other message type, so let's try to deserialize as a Rtm.
                    parse_route_table(rtm)
                }
            }
        }
    }
    Ok(())
}
