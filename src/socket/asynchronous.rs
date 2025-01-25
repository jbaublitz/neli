use std::{
    fmt::Debug,
    io::Cursor,
    os::unix::io::{AsRawFd, IntoRawFd, RawFd},
};

use log::{debug, trace};
use tokio::io::unix::AsyncFd;

use crate::{
    consts::{nl::*, socket::*},
    err::SocketError,
    iter::NlBufferIter,
    nl::Nlmsghdr,
    socket::shared::NlSocket,
    types::NlBuffer,
    utils::{
        asynchronous::{BufferPool, BufferPoolGuard},
        Groups, NetlinkBitArray,
    },
    FromBytesWithInput, Size, ToBytes,
};

/// Tokio-enabled Netlink socket struct
pub struct NlSocketHandle {
    pub(super) socket: AsyncFd<super::NlSocket>,
    pool: BufferPool,
    pid: u32,
}

impl NlSocketHandle {
    /// Set up asynchronous socket handle.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Groups) -> Result<Self, SocketError> {
        let socket = NlSocket::connect(proto, pid, groups)?;
        socket.nonblock()?;
        let pid = socket.pid()?;
        Ok(NlSocketHandle {
            socket: AsyncFd::new(socket)?,
            pool: BufferPool::default(),
            pid,
        })
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: Groups) -> Result<(), SocketError> {
        self.socket
            .get_ref()
            .add_mcast_membership(groups)
            .map_err(SocketError::from)
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: Groups) -> Result<(), SocketError> {
        self.socket
            .get_ref()
            .drop_mcast_membership(groups)
            .map_err(SocketError::from)
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<NetlinkBitArray, SocketError> {
        self.socket
            .get_ref()
            .list_mcast_membership()
            .map_err(SocketError::from)
    }

    /// Get the PID for the current socket.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Send a message on the socket asynchronously.
    pub async fn send<T, P>(&self, msg: &Nlmsghdr<T, P>) -> Result<(), SocketError>
    where
        T: NlType,
        P: Size + ToBytes,
    {
        let mut buffer = Cursor::new(vec![0; msg.padded_size()]);
        msg.to_bytes(&mut buffer)?;
        loop {
            let mut guard = self.socket.writable().await?;
            match guard.try_io(|socket| socket.get_ref().send(buffer.get_ref(), Msg::empty())) {
                Ok(Ok(_)) => {
                    break;
                }
                Ok(Err(e)) => return Err(SocketError::from(e)),
                Err(_) => (),
            };
        }
        Ok(())
    }

    /// Receive a message from the socket asynchronously.
    pub async fn recv<T, P>(
        &self,
    ) -> Result<(NlBufferIter<T, P, BufferPoolGuard<'_>>, Groups), SocketError>
    where
        T: NlType,
        P: Size + FromBytesWithInput<Input = usize>,
    {
        let groups;
        let mut buffer = self.pool.acquire().await;
        loop {
            let mut guard = self.socket.readable().await?;
            match guard.try_io(|socket| socket.get_ref().recv(buffer.as_mut_slice(), Msg::empty()))
            {
                Ok(Ok((bytes, group))) => {
                    buffer.reduce_size(bytes);
                    groups = group;
                    break;
                }
                Ok(Err(e)) => return Err(SocketError::from(e)),
                Err(_) => (),
            };
        }
        trace!("Buffer received: {:?}", buffer.as_ref());
        Ok((NlBufferIter::new(Cursor::new(buffer)), groups))
    }

    /// Parse all [`Nlmsghdr`][crate::nl::Nlmsghdr] structs sent in
    /// one network packet and return them all in a list.
    ///
    /// Failure to parse any packet will cause the entire operation
    /// to fail. If an error is detected at the application level,
    /// this method will discard any non-error
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] structs and only return the
    /// error. For a more granular approach, use either [`NlSocketHandle::recv`].
    pub async fn recv_all<T, P>(&self) -> Result<(NlBuffer<T, P>, Groups), SocketError>
    where
        T: NlType + Debug,
        P: Size + FromBytesWithInput<Input = usize> + Debug,
    {
        let groups;
        let mut buffer = self.pool.acquire().await;
        let bytes_read;
        loop {
            let mut guard = self.socket.readable().await?;
            match guard.try_io(|socket| socket.get_ref().recv(buffer.as_mut_slice(), Msg::empty()))
            {
                Ok(Ok((bytes, group))) => {
                    if bytes == 0 {
                        return Ok((NlBuffer::new(), Groups::empty()));
                    }
                    groups = group;
                    bytes_read = bytes;
                    buffer.reduce_size(bytes);
                    break;
                }
                Ok(Err(e)) => return Err(SocketError::from(e)),
                Err(_) => (),
            };
        }

        let vec = NlBuffer::from_bytes_with_input(&mut Cursor::new(buffer), bytes_read)?;

        debug!("Messages received: {:?}", vec);

        Ok((vec, groups))
    }

    /// If [`true`] is passed in, enable extended ACKs for this socket. If [`false`]
    /// is passed in, disable extended ACKs for this socket.
    pub fn enable_ext_ack(&self, enable: bool) -> Result<(), SocketError> {
        self.socket
            .get_ref()
            .enable_ext_ack(enable)
            .map_err(SocketError::from)
    }

    /// Return [`true`] if an extended ACK is enabled for this socket.
    pub fn get_ext_ack_enabled(&self) -> Result<bool, SocketError> {
        self.socket
            .get_ref()
            .get_ext_ack_enabled()
            .map_err(SocketError::from)
    }

    /// If [`true`] is passed in, enable strict checking for this socket. If [`false`]
    /// is passed in, disable strict checking for for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn enable_strict_checking(&self, enable: bool) -> Result<(), SocketError> {
        self.socket
            .get_ref()
            .enable_strict_checking(enable)
            .map_err(SocketError::from)
    }

    /// Return [`true`] if strict checking is enabled for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn get_strict_checking_enabled(&self) -> Result<bool, SocketError> {
        self.socket
            .get_ref()
            .get_strict_checking_enabled()
            .map_err(SocketError::from)
    }
}

impl AsRawFd for NlSocketHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.get_ref().as_raw_fd()
    }
}

impl IntoRawFd for NlSocketHandle {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_inner().into_raw_fd()
    }
}
