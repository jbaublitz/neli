extern crate buffering;
extern crate neli;

use buffering::StreamReadBuffer;
use neli::consts::*;
use neli::nl::NlEmpty;
use neli::nl::Nlmsghdr;
use neli::rtnl::*;
use neli::socket::*;
use neli::Nl;
use neli::MAX_NL_LENGTH;
use std::net::IpAddr;


///
/// This sample is a simple imitation of the `ip route` command, to demonstrate interaction with the rtnetlink subsystem.  
/// 
fn main() {
    let mut socket = NlSocket::connect(NlFamily::Route, None, None, true).unwrap();

    let rtmsg : Rtmsg<Rta> = Rtmsg {
        rtm_family: libc::AF_INET as u8,
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
        let flags = vec![NlmF::Request, NlmF::Root, NlmF::Match];
        let seq = None;
        let pid = None;
        let payload = rtmsg;
        Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
    };
    socket.send_nl(nlhdr).unwrap();

    'socket_read: loop {
        let mut mem = vec![0u8; MAX_NL_LENGTH];
        match socket.recv(&mut mem, 0) {
            Err(e) => {
                println!("Error: could not read from netlink socket: {}", e);
                break;
            }
            Ok(x) if x <= 0 => {
                println!("Error: could not read from netlink socket: {}", x);
                break;
            }
            Ok(read_len) => mem.truncate(read_len as usize),
        }
        let mut buf = StreamReadBuffer::new(&mem[..]);

        while !buf.at_end() {
            // Provisionally deserialize as a Nlmsg first.
            let mut nl_reader = StreamReadBuffer::new(buf.as_ref());
            let nl = Nlmsghdr::<Nlmsg, NlEmpty>::deserialize(&mut nl_reader)
                .expect("Error deserializing Nlmsghdr");
            match nl.nl_type {
                Nlmsg::Done => break 'socket_read,
                Nlmsg::Error => {
                    println!("rtnetlink error.");
                    break 'socket_read;
                }
                _ => {
                    // Some other message type, so let's try to deserialize as a Rtm.
                    let rtm = Nlmsghdr::<Rtm, Rtmsg<Rta>>::deserialize(&mut buf)
                        .expect("Error deserializing Rtmsg");

                    // This sample is only interested in the main table.
                    if rtm.nl_payload.rtm_table == RtTable::Main {
                        let mut src = None;
                        let mut dst = None;
                        let mut gateway = None;

                        for attr in &rtm.nl_payload.rtattrs {
                            fn to_addr(b: &[u8]) -> Option<IpAddr> {
                                use std::convert::TryFrom;
                                if let Ok(tup) = <&[u8; 4]>::try_from(b) {
                                    Some(IpAddr::from(tup.clone()))
                                } else if let Ok(tup) = <&[u8; 16]>::try_from(b) {
                                    Some(IpAddr::from(tup.clone()))
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
            }
        }
    }
}
