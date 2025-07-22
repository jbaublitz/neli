use std::{
    fmt::Debug,
    io::Cursor,
    os::unix::io::{AsRawFd, IntoRawFd, RawFd},
};

use log::trace;

use crate::{
    FromBytesWithInput, Size, ToBytes,
    consts::{nl::*, socket::*},
    err::SocketError,
    iter::NlBufferIter,
    nl::Nlmsghdr,
    socket::shared::NlSocket,
    types::NlBuffer,
    utils::{
        Groups, NetlinkBitArray,
        synchronous::{BufferPool, BufferPoolGuard},
    },
};

/// Higher level handle for socket operations.
pub struct NlSocketHandle {
    pub(super) socket: NlSocket,
    pid: u32,
    pool: BufferPool,
}

impl NlSocketHandle {
    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Groups) -> Result<Self, SocketError> {
        let socket = NlSocket::connect(proto, pid, groups)?;
        socket.block()?;
        let pid = socket.pid()?;
        Ok(NlSocketHandle {
            socket,
            pid,
            pool: BufferPool::default(),
        })
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: Groups) -> Result<(), SocketError> {
        self.socket
            .add_mcast_membership(groups)
            .map_err(SocketError::from)
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: Groups) -> Result<(), SocketError> {
        self.socket
            .drop_mcast_membership(groups)
            .map_err(SocketError::from)
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<NetlinkBitArray, SocketError> {
        self.socket
            .list_mcast_membership()
            .map_err(SocketError::from)
    }

    /// Get the PID for the current socket.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Convenience function to send an [`Nlmsghdr`] struct
    pub fn send<T, P>(&self, msg: &Nlmsghdr<T, P>) -> Result<(), SocketError>
    where
        T: NlType + Debug,
        P: Size + ToBytes + Debug,
    {
        trace!("Message sent:\n{msg:?}");

        let mut buffer = Cursor::new(vec![0; msg.padded_size()]);
        msg.to_bytes(&mut buffer)?;
        trace!("Buffer sent: {:?}", buffer.get_ref());
        self.socket.send(buffer.get_ref(), Msg::empty())?;

        Ok(())
    }

    /// Convenience function to send multiple [`Nlmsghdr`] structs
    pub fn send_batch<T, P>(&self, msgs: &[Nlmsghdr<T, P>]) -> Result<(), SocketError>
    where
        T: NlType + Debug,
        P: Size + ToBytes + Debug,
    {
        debug!("Messages sent:\n{:?}", msgs);

        let size = msgs.iter().map(|msg| msg.padded_size()).sum();

        let mut buffer = Cursor::new(vec![0; size]);

        msgs.iter().try_for_each(|msg| msg.to_bytes(&mut buffer))?;
        trace!("Buffer sent: {:?}", buffer.get_ref());
        self.socket.send(buffer.get_ref(), Msg::empty())?;

        Ok(())
    }

    /// Convenience function to read a stream of [`Nlmsghdr`]
    /// structs one by one using an iterator.
    ///
    /// Returns [`None`] when the stream of messages has been completely processed in
    /// the current buffer resulting from a single
    /// [`NlSocket::recv`][crate::socket::NlSocket::recv] call.
    ///
    /// See [`NlBufferIter`] for more detailed information.
    pub fn recv<T, P>(
        &self,
    ) -> Result<(NlBufferIter<T, P, BufferPoolGuard<'_>>, Groups), SocketError>
    where
        T: NlType + Debug,
        P: Size + FromBytesWithInput<Input = usize> + Debug,
    {
        let mut buffer = self.pool.acquire();
        let (mem_read, groups) = self.socket.recv(&mut buffer, Msg::empty())?;
        buffer.reduce_size(mem_read);
        trace!("Buffer received: {:?}", buffer.as_ref());
        Ok((NlBufferIter::new(Cursor::new(buffer)), groups))
    }

    /// Parse all [`Nlmsghdr`] structs sent in
    /// one network packet and return them all in a list.
    ///
    /// Failure to parse any packet will cause the entire operation
    /// to fail. If an error is detected at the application level,
    /// this method will discard any non-error
    /// [`Nlmsghdr`] structs and only return the
    /// error. For a more granular approach, use [`NlSocketHandle::recv`].
    pub fn recv_all<T, P>(&self) -> Result<(NlBuffer<T, P>, Groups), SocketError>
    where
        T: NlType + Debug,
        P: Size + FromBytesWithInput<Input = usize> + Debug,
    {
        let mut buffer = self.pool.acquire();
        let (mem_read, groups) = self.socket.recv(&mut buffer, Msg::empty())?;
        if mem_read == 0 {
            return Ok((NlBuffer::new(), Groups::empty()));
        }
        buffer.reduce_size(mem_read);

        let vec = NlBuffer::from_bytes_with_input(&mut Cursor::new(buffer), mem_read)?;

        trace!("Messages received: {vec:?}");

        Ok((vec, groups))
    }

    /// Set the size of the receive buffer for the socket.
    ///
    /// This can be useful when communicating with a service that sends a high volume of
    /// messages (especially multicast), and your application cannot process them fast enough,
    /// leading to the kernel dropping messages. A larger buffer may help mitigate this.
    ///
    /// The value passed is a hint to the kernel to set the size of the receive buffer.
    /// The kernel will double the value provided to account for bookkeeping overhead.
    /// The doubled value is capped by the value in `/proc/sys/net/core/rmem_max`.
    ///
    /// The default value is `/proc/sys/net/core/rmem_default`
    ///
    /// See `socket(7)` documentation for `SO_RCVBUF` for more information.
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<(), SocketError> {
        self.socket
            .set_recv_buffer_size(size)
            .map_err(SocketError::from)
    }

    /// If [`true`] is passed in, enable extended ACKs for this socket. If [`false`]
    /// is passed in, disable extended ACKs for this socket.
    pub fn enable_ext_ack(&self, enable: bool) -> Result<(), SocketError> {
        self.socket
            .enable_ext_ack(enable)
            .map_err(SocketError::from)
    }

    /// Return [`true`] if an extended ACK is enabled for this socket.
    pub fn get_ext_ack_enabled(&self) -> Result<bool, SocketError> {
        self.socket.get_ext_ack_enabled().map_err(SocketError::from)
    }

    /// If [`true`] is passed in, enable strict checking for this socket. If [`false`]
    /// is passed in, disable strict checking for for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn enable_strict_checking(&self, enable: bool) -> Result<(), SocketError> {
        self.socket
            .enable_strict_checking(enable)
            .map_err(SocketError::from)
    }

    /// Return [`true`] if strict checking is enabled for this socket.
    /// Only supported by `NlFamily::Route` sockets.
    /// Requires Linux >= 4.20.
    pub fn get_strict_checking_enabled(&self) -> Result<bool, SocketError> {
        self.socket
            .get_strict_checking_enabled()
            .map_err(SocketError::from)
    }
}

impl AsRawFd for NlSocketHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl IntoRawFd for NlSocketHandle {
    fn into_raw_fd(self) -> RawFd {
        self.socket.into_raw_fd()
    }
}
