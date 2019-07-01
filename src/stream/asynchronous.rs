use std::io;

use crate::{
    consts::{NlFamily, NlType},
    err::NlError,
    socket::{tokio, NlSocket},
    utils::{U32BitFlag, U32Bitmask},
    Nl,
};

/// Builder for netlink stream
pub struct NetlinkStreamConnector {
    sock: NlSocket,
    mcast_ids: U32Bitmask,
}

impl NetlinkStreamConnector {
    /// Create builder for netlink stream
    pub fn new(proto: NlFamily, pid: Option<u32>) -> Result<Self, io::Error> {
        Ok(NetlinkStreamConnector {
            sock: NlSocket::connect(proto, pid, U32Bitmask::empty())?,
            mcast_ids: U32Bitmask::empty(),
        })
    }

    /// Add a multicast group subscription by family and group name
    pub fn add_mcast_group(
        &mut self,
        family: &str,
        mcast_group: &str,
    ) -> Result<&mut Self, NlError> {
        let group_num = self.sock.resolve_nl_mcast_group(family, mcast_group)?;
        let flag = match U32BitFlag::new(group_num) {
            Ok(f) => f,
            Err(_) => {
                return Err(NlError::new(
                    "You have hit a bug - \
                     the group number that was returned is larger than what can \
                     be represented by a u32 bitmask",
                ))
            }
        };
        self.mcast_ids += flag;
        Ok(self)
    }

    /// Remove a multicast group subscription by family and group name
    pub fn remove_mcast_group(
        &mut self,
        family: &str,
        mcast_group: &str,
    ) -> Result<&mut Self, NlError> {
        let group_num = self.sock.resolve_nl_mcast_group(family, mcast_group)?;
        let flag = match U32BitFlag::new(group_num) {
            Ok(f) => f,
            Err(_) => {
                return Err(NlError::new(
                    "You have hit a bug - \
                     the group number that was returned is larger than what can \
                     be represented by a u32 bitmask",
                ))
            }
        };
        self.mcast_ids -= flag;
        Ok(self)
    }

    /// Create socket from connector
    pub fn build<T, P>(self) -> Result<NetlinkStream<T, P>, io::Error>
    where
        T: NlType,
        P: Nl,
    {
        let (mut sock, grps) = (self.sock, self.mcast_ids);
        sock.add_mcast_membership(grps)?;
        Ok(NetlinkStream::new_with_socket(
            tokio::NlSocket::new(sock)?,
            None,
        ))
    }
}

/// High level API for receiving a stream of netlink messages
pub struct NetlinkStream<T, P> {
    // Dead code allowed for CI
    #[allow(dead_code)]
    sock: tokio::NlSocket<T, P>,
    // Dead code allowed for CI
    #[allow(dead_code)]
    pid: Option<u32>,
    // Dead code allowed for CI
    #[allow(dead_code)]
    seq: Option<u32>,
}

impl<T, P> NetlinkStream<T, P>
where
    T: NlType,
    P: Nl,
{
    /// Create new netlink stream
    pub fn new(proto: NlFamily, pid: Option<u32>, groups: U32Bitmask) -> Result<Self, io::Error> {
        Ok(NetlinkStream {
            sock: tokio::NlSocket::new(NlSocket::connect(proto, pid, groups)?)?,
            pid,
            seq: None,
        })
    }

    /// Create stream from socket
    pub fn new_with_socket(sock: tokio::NlSocket<T, P>, pid: Option<u32>) -> Self {
        NetlinkStream {
            sock,
            pid,
            seq: None,
        }
    }
}
