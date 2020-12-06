use std::{
    collections::HashSet,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::ready;
use tokio::stream::Stream;

use crate::{
    consts::{nl::*, socket::*},
    err::{NlError, NlStreamError},
    nl::Nlmsghdr,
    socket::{tokio::NlSocket, NlSocketHandle},
    utils::{U32BitFlag, U32Bitmask},
    Nl,
};

enum PidChecking {
    Disabled,
    Whitelist(HashSet<u32>),
    Track(Option<u32>),
}

enum SeqChecking {
    Disabled,
    Track(Option<u32>),
}

/// Builder for netlink stream
pub struct NetlinkStreamConnector {
    sock: NlSocketHandle,
    mcast_ids: U32Bitmask,
    pid_checking: Option<PidChecking>,
    seq_checking: Option<SeqChecking>,
}

impl NetlinkStreamConnector {
    /// Create builder for netlink stream
    pub fn new(proto: NlFamily, pid: Option<u32>) -> Result<Self, io::Error> {
        Ok(NetlinkStreamConnector {
            sock: NlSocketHandle::connect(proto, pid, U32Bitmask::empty())?,
            mcast_ids: U32Bitmask::empty(),
            pid_checking: None,
            seq_checking: None,
        })
    }

    /// Provide a whitelist of PIDs that can send messages to this
    /// socket. If the response does not match any of these PIDs,
    /// discard the message.
    pub fn whitelist_pids(&mut self, pids: &[u32]) -> &mut Self {
        self.pid_checking = Some(PidChecking::Whitelist(pids.iter().copied().collect()));
        self
    }

    /// Allow any PID to send a response to this socket. If this
    /// option is enabled, you are responsible for all PID validation.
    pub fn disable_pid_checking(&mut self) -> &mut Self {
        self.pid_checking = Some(PidChecking::Disabled);
        self
    }

    /// Detect the PID contained in the first response and only
    /// accept responses from this PID after.
    pub fn track_pid(&mut self) -> &mut Self {
        self.pid_checking = Some(PidChecking::Track(None));
        self
    }

    /// Ignore sequence numbers. If this option is enabled, you are
    /// responsible for all sequence number validation.
    pub fn disable_seq_checking(&mut self) -> &mut Self {
        self.seq_checking = Some(SeqChecking::Disabled);
        self
    }

    /// Track the first sequence number received and check that each
    /// subsequent packet increments it by one.
    pub fn track_seq(&mut self) -> &mut Self {
        self.seq_checking = Some(SeqChecking::Track(None));
        self
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
                    "You have hit a bug; the group number that was
                    returned is larger than what can be represented
                    by a u32 bitmask",
                ))
            }
        };
        self.mcast_ids |= flag;
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
                    "You have hit a bug; the group number that was \
                    returned is larger than what can be represented \
                    by a u32 bitmask",
                ))
            }
        };
        self.mcast_ids &= !flag;
        Ok(self)
    }

    /// Create socket from connector
    pub fn build<T, P>(self) -> Result<NetlinkStream<T, P>, io::Error>
    where
        T: NlType,
        P: Nl,
    {
        self.sock.add_mcast_membership(self.mcast_ids)?;
        NetlinkStream::from_builder(self)
    }
}

/// High level API for receiving a stream of netlink messages
pub struct NetlinkStream<T, P> {
    sock: NlSocket<T, P>,
    pid_checking: PidChecking,
    seq_checking: SeqChecking,
}

impl<T, P> NetlinkStream<T, P>
where
    T: NlType,
    P: Nl,
{
    fn from_builder(builder: NetlinkStreamConnector) -> Result<Self, io::Error> {
        Ok(NetlinkStream {
            sock: NlSocket::new(builder.sock)?,
            pid_checking: builder.pid_checking.unwrap_or(PidChecking::Track(None)),
            seq_checking: builder.seq_checking.unwrap_or(SeqChecking::Track(None)),
        })
    }

    /// If a packet from an unrecognized source is sent and it is
    /// confirmed that this is a valid packet, this method allows
    /// users to add to the whitelist.
    pub fn add_to_pid_whitelist(&mut self, pid: u32) {
        if let PidChecking::Whitelist(ref mut wl) = self.pid_checking {
            wl.insert(pid);
        }
    }

    /// If a packet with a required sequence number is lost, you
    /// may use this method to reset the sequence counter after
    /// being notified of the error to continue using the socket.
    pub fn reset_seq_tracker(&mut self) {
        if let SeqChecking::Track(Some(_)) = self.seq_checking {
            self.seq_checking = SeqChecking::Track(None);
        }
    }
}

impl<T, P> Stream for NetlinkStream<T, P>
where
    T: NlType,
    P: Nl,
{
    type Item = Result<Nlmsghdr<T, P>, NlStreamError<T, P>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let nlmsg_opt = ready!(Pin::new(&mut self.sock).poll_next(cx));
        nlmsg_opt
            .map(|res| {
                res.map_err(|e| NlStreamError::new(e, None))
                    .and_then(|nlmsg| {
                        match self.pid_checking {
                            PidChecking::Track(ref mut opt) => {
                                if let Some(pid) = *opt {
                                    if pid != nlmsg.nl_pid {
                                        return Err(NlStreamError::new(
                                            NlError::BadPid,
                                            Some(nlmsg),
                                        ));
                                    }
                                } else {
                                    *opt = Some(nlmsg.nl_pid);
                                }
                            }
                            PidChecking::Whitelist(ref whitelist) => {
                                if !whitelist.contains(&nlmsg.nl_pid) {
                                    return Err(NlStreamError::new(NlError::BadPid, Some(nlmsg)));
                                }
                            }
                            _ => (),
                        };
                        Ok(nlmsg)
                    })
            })
            .into()
    }
}
