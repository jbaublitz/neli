//! This example connects to the netfilter logging facility, group 10 (arbitrarily chosen number),
//! on INET (IPv4).
//!
//! If you want to see it work, log some packets, for example by adding this into the iptables:
//!
//! ```sh
//! iptables -I INPUT -j NFLOG --nflog-group 10 --nflog-prefix "A packet"
//! ```
//!
//! Both this example and the above command needs to be run as root.
extern crate neli;

use neli::consts::netfilter::{LogCmd, LogCopyMode, NetfilterMsg, NfLogCfg};
use neli::consts::{NlFamily, NlmF};
use neli::netfilter::{LogConfigMode, LogConfigReq, LogPacket};
use neli::nl::Nlmsghdr;
use neli::nlattr::Nlattr;
use neli::socket::NlSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First, let's create a socket to the netfilter.
    let mut socket = NlSocket::connect(NlFamily::Netfilter, None, None, false)?;

    // Then, ask the kernel to send the relevant packets into it. Unfortunately, the documentation
    // of the functionality is kind of sparse, so there are some unknowns, like why do we have to
    // do the PfUnbind first (every other example out there on the Internet does that and doesn't
    // explain it).
    let cmds = vec![
        Nlattr::new(None, NfLogCfg::Cmd, LogCmd::PfUnbind)?,
        // This one says we are interested in the first 50 bytes of each packet. If not included,
        // it'll send us the whole packets.
        Nlattr::new(
            None,
            NfLogCfg::Mode,
            LogConfigMode {
                copy_mode: LogCopyMode::Packet,
                copy_range: 50,
            },
        )?,
        Nlattr::new(None, NfLogCfg::Cmd, LogCmd::PfBind)?,
        Nlattr::new(None, NfLogCfg::Cmd, LogCmd::Bind)?,
    ];
    let req = LogConfigReq::new(libc::AF_INET, 10, cmds);
    let flags = vec![NlmF::Request, NlmF::Ack];
    let msg = Nlmsghdr::new(None, NetfilterMsg::LogConfig, flags, None, None, req);
    // Send the request to the kernel
    socket.send_nl(msg)?;
    // And check it succeeds.
    socket.recv_ack()?;

    // Now, let's start getting the packets. A real world application would do something more
    // useful with them then just print them, but hey, this is an example.
    for pkt in socket.iter::<NetfilterMsg, LogPacket>() {
        let pkt = pkt?;
        match pkt.nl_type {
            NetfilterMsg::LogPacket => println!("{:?}", pkt.nl_payload),
            // TODO: Does anyone have any idea what these messages are and why we get them?
            _ => println!("Some other message received"),
        }
    }
    Ok(())
}
