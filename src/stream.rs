use std::io;

use consts::NlFamily;
use err::NlError;
use socket::NlSocket;

/// Builder for netlink stream
pub struct NetlinkStreamConnector {
    sock: NlSocket,
    mcast_ids: Vec<u32>,
}

impl NetlinkStreamConnector {
    /// Create builder for netlink stream
    pub fn new(proto: NlFamily, pid: Option<u32>) -> Result<Self, io::Error> {
        Ok(NetlinkStreamConnector { sock: NlSocket::connect(proto, pid, None)?,
                                    mcast_ids: Vec::new(), } )
    }

    /// Add a multicast group subscription by family and group name
    pub fn add_mcast_group(&mut self, family: &str, mcast_group: &str) -> Result<(), NlError> {
        self.mcast_ids.push(self.sock.resolve_nl_mcast_group(family, mcast_group)?);
        Ok(())
    }

    /// Create socket from connector
    pub fn build(self) -> Result<NetlinkStream, io::Error> {
        let (mut sock, grps) = (self.sock, self.mcast_ids);
        sock.add_mcast_membership(grps)?;
        Ok(NetlinkStream::new_with_socket(sock, None))
    }
}

/// High level API for receiving a stream of netlink messages
pub struct NetlinkStream {
    sock: NlSocket,
    pid: Option<u32>,
    seq: Option<u32>,
}

impl NetlinkStream {
    /// Create new netlink stream
    pub fn new(proto: NlFamily, pid: Option<u32>, groups: Option<Vec<u32>>)
            -> Result<Self, io::Error> {
        Ok(NetlinkStream { sock: NlSocket::connect(proto, pid, groups)?, pid, seq: None })
    }

    /// Create stream from socket
    pub fn new_with_socket(sock: NlSocket, pid: Option<u32>) -> Self {
        NetlinkStream { sock, pid, seq: None }
    }
}
