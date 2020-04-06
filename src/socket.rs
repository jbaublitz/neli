//! This module provides code that glues all of the other modules together and allows message send
//! and receive operations. This module relies heavily on the `buffering` crate. See `buffering`
//! for more information on the serialization and deserialization implementations.
//!
//! ## Important methods
//! * `send` and `recv` methods are meant to be the most low level calls. They essentially do what
//! the C system calls `send` and `recv` do with very little abstraction.
//! * `send_nl` and `recv_nl` methods are meant to provide an interface that is more idiomatic for
//! the library. The are able to operate on any structure wrapped in an `Nlmsghdr` struct that implements
//! the `Nl` trait.
//! * `iter` provides a loop based iteration through messages that are received in a stream over
//! the socket.
//! * `recv_ack` receives an ACK message and verifies it matches the request.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use Rust's tokio for async IO.
//!
//! ## Additional methods
//!
//! There are methods for blocking and non-blocking, resolving generic netlink multicast group IDs,
//! and other convenience functions so see if your use case is supported. If it isn't, please open
//! a Github issue and submit a feature request.
//!
//! ## Design decisions
//!
//! The buffer allocated in the `NlSocket` structure should
//! be allocated on the heap. This is intentional as a buffer
//! that large could be a problem on the stack. Big thanks to
//! @vorner for the suggestion on how to minimize allocations.

use std::{
    fmt::Debug,
    io,
    marker::PhantomData,
    mem::{size_of, zeroed},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use bytes::{Bytes, BytesMut};
use libc::{self, c_int, c_void};
use smallvec::SmallVec;

#[cfg(feature = "logging")]
use crate::log;
use crate::{
    consts::{
        self, AddrFamily, CtrlAttr, CtrlAttrMcastGrp, CtrlCmd, GenlId, Index, NlAttrType, NlFamily,
        NlType, NlmF, NlmFFlags, Nlmsg,
    },
    err::{DeError, NlError, Nlmsgerr},
    genl::Genlmsghdr,
    nl::Nlmsghdr,
    nlattr::Nlattr,
    utils::{packet_length, U32Bitmask},
    Nl, NlBuffer,
};

/// Iterator over messages returned from a `recv_nl` call
pub struct NlMessageIter<'a, T, P> {
    socket_ref: &'a mut NlSocket,
    stored: NlBuffer<T, P>,
    data_type: PhantomData<T>,
    data_payload: PhantomData<P>,
}

impl<'a, T, P> NlMessageIter<'a, T, P>
where
    T: Nl + NlType,
    P: Nl,
{
    /// Construct a new iterator that yields `Nlmsghdr` structs from the provided buffer
    pub fn new(socket_ref: &'a mut NlSocket) -> Self {
        NlMessageIter {
            socket_ref,
            stored: SmallVec::new(),
            data_type: PhantomData,
            data_payload: PhantomData,
        }
    }
}

impl<'a, T, P> Iterator for NlMessageIter<'a, T, P>
where
    T: Nl + NlType + Debug,
    P: Nl + Debug,
{
    type Item = Result<Nlmsghdr<T, P>, NlError>;

    fn next(&mut self) -> Option<Result<Nlmsghdr<T, P>, NlError>> {
        if self.stored.is_empty() {
            match self.socket_ref.recv_all_nl() {
                Ok(mut rn) => {
                    while let Some(item) = rn.pop() {
                        self.stored.push(item)
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }
        self.stored.pop().map(Ok)
    }
}

/// Define the behavior on a netlink packet parsing error
pub enum OnError {
    /// Rewind the position to the beginning of the packet to try again
    Rewind,
    /// Skip to the next packet, discarding the failed packet
    FastForward,
}

/// Handle for the socket file descriptor
pub struct NlSocket {
    fd: c_int,
    buffer: BytesMut,
    position: usize,
    end: usize,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd =
            match unsafe { libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into()) }
            {
                i if i >= 0 => Ok(i),
                _ => Err(io::Error::last_os_error()),
            }?;
        Ok(NlSocket {
            fd,
            buffer: BytesMut::from(&[0u8; crate::neli_constants::MAX_NL_LENGTH] as &[u8]),
            position: 0,
            end: 0,
        })
    }

    /// Set underlying socket file descriptor to be blocking
    pub fn block(&mut self) -> Result<&mut Self, io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) & !libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(self),
        }
    }

    /// Set underlying socket file descriptor to be non blocking
    pub fn nonblock(&mut self) -> Result<&mut Self, io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(self),
        }
    }

    /// Determines if underlying file descriptor is blocking - `Stream` feature will throw an
    /// error if this function returns false
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        let is_blocking = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            i if i >= 0 => i & libc::O_NONBLOCK == 0,
            _ => return Err(io::Error::last_os_error()),
        };
        Ok(is_blocking)
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    ///
    /// The pid parameter sets PID checking.
    /// * `None` means checking is off.
    /// * `Some(0)` turns checking on, but takes the PID from the first received message.
    /// * `Some(pid)` uses the given PID.
    pub fn bind(&mut self, pid: Option<u32>, groups: U32Bitmask) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::c_int::from(AddrFamily::Netlink) as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = 0;
        match unsafe {
            libc::bind(
                self.fd,
                &nladdr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            )
        } {
            i if i >= 0 => (),
            _ => return Err(io::Error::last_os_error()),
        };
        if !groups.is_empty() {
            self.add_mcast_membership(groups)?;
        }
        Ok(())
    }

    /// Set multicast groups for socket
    #[deprecated(since = "0.5.0", note = "Use add_multicast_membership instead")]
    pub fn set_mcast_groups(&mut self, groups: U32Bitmask) -> Result<(), io::Error> {
        self.add_mcast_membership(groups)
    }

    /// Join multicast groups for a socket
    pub fn add_mcast_membership(&mut self, groups: U32Bitmask) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_ADD_MEMBERSHIP,
                &*groups as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Leave multicast groups for a socket
    pub fn drop_mcast_membership(&mut self, groups: U32Bitmask) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_DROP_MEMBERSHIP,
                &*groups as *const _ as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// List joined groups for a socket
    pub fn list_mcast_membership(&mut self) -> Result<U32Bitmask, io::Error> {
        let mut grps = 0u32;
        let mut len = size_of::<u32>() as libc::socklen_t;
        match unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                &mut grps as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(U32Bitmask::from(grps)),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`neli::nl::Nlmsghdr`)
    pub fn send<B>(&self, buf: B, flags: i32) -> Result<libc::size_t, io::Error>
    where
        B: AsRef<[u8]>,
    {
        match unsafe {
            libc::send(
                self.fd,
                buf.as_ref() as *const _ as *const c_void,
                buf.as_ref().len(),
                flags,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket
    pub fn recv<B>(&self, mut buf: B, flags: i32) -> Result<libc::size_t, io::Error>
    where
        B: AsMut<[u8]>,
    {
        match unsafe {
            libc::recv(
                self.fd,
                buf.as_mut() as *mut _ as *mut c_void,
                buf.as_mut().len(),
                flags,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: U32Bitmask,
    ) -> Result<Self, io::Error> {
        let mut s = NlSocket::new(proto)?;
        s.bind(pid, groups)?;
        Ok(s)
    }

    fn get_genl_family<T>(
        &mut self,
        family_name: &str,
    ) -> Result<NlBuffer<GenlId, Genlmsghdr<CtrlCmd, T>>, NlError>
    where
        T: NlAttrType + Debug,
    {
        let mut attrs = SmallVec::new();
        attrs.push(Nlattr::new(None, CtrlAttr::FamilyName, family_name)?);
        let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            genlhdr,
        );
        self.send_nl(nlhdr)?;

        let msg = self.recv_all_nl()?;
        self.recv_ack(OnError::FastForward)?;
        Ok(msg)
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_genl_family(&mut self, family_name: &str) -> Result<u16, NlError> {
        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs.iter() {
            let handle = nlhdr.nl_payload.get_attr_handle();
            if let Ok(u) = handle.get_attr_payload_as::<u16>(CtrlAttr::FamilyId) {
                return Ok(u);
            }
        }
        Err(NlError::new(format!(
            "Generic netlink family {} was not found",
            family_name
        )))
    }

    /// Convenience function for resolving a `&str` containing the multicast group name to a
    /// numeric netlink ID
    pub fn resolve_nl_mcast_group(
        &mut self,
        family_name: &str,
        mcast_name: &str,
    ) -> Result<u32, NlError> {
        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs {
            let mut handle = nlhdr.nl_payload.get_attr_handle();
            let mcast_groups = handle.get_nested_attributes::<Index>(CtrlAttr::McastGroups)?;
            if let Some(id) = mcast_groups
                .iter()
                .filter_map(|item| {
                    let nested_attrs = item.get_attr_handle::<CtrlAttrMcastGrp>().ok()?;
                    let string = nested_attrs
                        .get_attr_payload_as::<String>(CtrlAttrMcastGrp::Name)
                        .ok()?;
                    if string.as_str() == mcast_name {
                        nested_attrs
                            .get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id)
                            .ok()
                    } else {
                        None
                    }
                })
                .next()
            {
                return Ok(id);
            }
        }
        Err(NlError::new("Failed to resolve multicast group ID"))
    }

    /// Look up netlink family and multicast group name by ID
    pub fn lookup_id(&mut self, id: u32) -> Result<(String, String), NlError> {
        let attrs = SmallVec::new();
        let genlhdr = Genlmsghdr::<CtrlCmd, CtrlAttrMcastGrp>::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
            None,
            None,
            genlhdr,
        );

        self.send_nl(nlhdr)?;
        for res_msg in self.iter::<Nlmsg, Genlmsghdr<u8, CtrlAttr>>() {
            let msg = res_msg?;
            if msg.nl_type == Nlmsg::Done {
                break;
            }

            let mut attributes = msg.nl_payload.get_attr_handle();
            let name = attributes.get_attr_payload_as::<String>(CtrlAttr::FamilyName)?;
            let groups = match attributes.get_nested_attributes::<Index>(CtrlAttr::McastGroups) {
                Ok(grps) => grps,
                Err(_) => continue,
            };
            for group_by_index in groups.iter() {
                let attributes = group_by_index.get_attr_handle::<CtrlAttrMcastGrp>()?;
                if let Ok(mcid) = attributes.get_attr_payload_as::<u32>(CtrlAttrMcastGrp::Id) {
                    if mcid == id {
                        let mcast_name =
                            attributes.get_attr_payload_as::<String>(CtrlAttrMcastGrp::Name)?;
                        return Ok((name, mcast_name));
                    }
                }
            }
        }

        Err(NlError::new("ID does not correspond to a multicast group"))
    }

    /// Convenience function to send an `Nlmsghdr` struct
    pub fn send_nl<T, P>(&mut self, msg: Nlmsghdr<T, P>) -> Result<(), NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        #[cfg(feature = "logging")]
        log!("Message sent:\n{:#?}", msg);

        let mut mem = BytesMut::from(vec![0; msg.asize()]);
        mem = msg.serialize(mem)?;
        self.send(mem, 0)?;

        Ok(())
    }

    /// Convenience function to begin receiving a stream of `Nlmsghdr` structs
    pub fn recv_nl<T, P>(&mut self, on_error: OnError) -> Result<Nlmsghdr<T, P>, NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        if self.end == self.position {
            let mut buffer = self.buffer.split_off(0);
            // Read the buffer from the socket and fail if nothing
            // was read.
            let mem_read = self.recv(buffer.as_mut(), 0)?;
            self.buffer.unsplit(buffer);
            if mem_read == 0 {
                return Err(NlError::new("No data could be read from the socket"));
            }
        }

        // Get the next packet length at the current position of the
        // buffer for the next read operation.
        let next_packet_len = packet_length(self.buffer.as_ref(), self.position);
        // If the packet extends past the end of the number of bytes
        // read into the buffer, return an error; something
        // has gone wrong.
        if self.position + next_packet_len > self.end {
            return Err(NlError::De(DeError::UnexpectedEOB));
        }

        // Deserialize the next Nlmsghdr struct.
        let deserialized_packet_result = Nlmsghdr::<T, P>::deserialize(Bytes::from(
            &self.buffer.as_ref()[self.position..self.position + next_packet_len],
        ));

        let packet = match deserialized_packet_result {
            // If successful, forward the position of the buffer
            // for the next read.
            Ok(packet) => {
                self.position += next_packet_len;
                packet
            }
            // If failed, choose the handling of the buffer state.
            Err(e) => {
                match on_error {
                    // Leave the position as is; the user will
                    // be able to retry the deserialize operation
                    // again on the same data.
                    OnError::Rewind => return Err(NlError::from(e)),
                    // Move the position of the buffer to the next
                    // packet essentially skipping all of the data
                    // that could not be parsed properly.
                    OnError::FastForward => {
                        self.position += next_packet_len;
                        return Err(NlError::from(e));
                    }
                }
            }
        };

        // If the position has reached the end of the read bytes,
        // reset the end and position to zero to trigger a new
        // socket read on the next invocation.
        if self.position == self.end {
            self.position = 0;
            self.end = 0;
        }
        Ok(packet)
    }

    /// Parse all `Nlmsghdr` structs sent in one network packet
    /// and return them all in a list.
    ///
    /// Failure to parse any packet will cause the entire operation
    /// to fail. For a more granular approach, use either
    /// `NlSocket::recv_nl` or `NlSocket::iter`.
    pub fn recv_all_nl<T, P>(&mut self) -> Result<NlBuffer<T, P>, NlError>
    where
        T: Nl + NlType,
        P: Nl,
    {
        if self.position == self.end {
            let mut buffer = self.buffer.split_off(0);
            let mem_read = self.recv(buffer.as_mut(), 0)?;
            self.buffer.unsplit(buffer);
            if mem_read == 0 {
                return Err(NlError::new("No data could be read from the socket"));
            }
            self.end = mem_read;
        }
        let vec = NlBuffer::deserialize(Bytes::from(&self.buffer.as_ref()[0..self.end]))?;
        self.position = 0;
        self.end = 0;
        Ok(vec)
    }

    /// Consume an ACK and return an error if an ACK is not found
    pub fn recv_ack(&mut self, on_error: OnError) -> Result<(), NlError> {
        if let Ok(ack) = self.recv_nl::<consts::Nlmsg, Nlmsgerr<consts::Nlmsg>>(on_error) {
            if ack.nl_type == consts::Nlmsg::Error {
                if ack.nl_payload.error == 0 {
                    // PID check done as part of recv_nl already
                    return Ok(());
                } else {
                    let err = std::io::Error::from_raw_os_error(-ack.nl_payload.error as _);
                    return Err(NlError::Msg(err.to_string()));
                }
            }
        }

        Err(NlError::NoAck)
    }

    /// Return an iterator object
    pub fn iter<T, P>(&mut self) -> NlMessageIter<T, P>
    where
        T: NlType,
        P: Nl,
    {
        NlMessageIter::new(self)
    }
}

impl AsRawFd for NlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for NlSocket {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl FromRawFd for NlSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NlSocket {
            fd,
            buffer: BytesMut::new(),
            end: 0,
            position: 0,
        }
    }
}

#[cfg(feature = "async")]
pub mod tokio {
    //! Tokio-specific features for neli
    //!
    //! This module contains a struct that wraps `NlSocket` for async IO.
    use super::*;

    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use ::tokio::{
        io::{AsyncRead, PollEvented},
        stream::Stream,
    };
    use mio::{self, Evented};

    use crate::neli_constants::MAX_NL_LENGTH;

    fn poll_read_priv(
        socket: &mut PollEvented<super::NlSocket>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(socket).poll_read(cx, buf)
    }

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket<T, P> {
        socket: PollEvented<super::NlSocket>,
        buffer: NlBuffer<T, P>,
    }

    impl<'a, T, P> NlSocket<T, P>
    where
        T: NlType,
    {
        /// Setup NlSocket for use with tokio - set to nonblocking state and wrap in polling mechanism
        pub fn new(mut socket: super::NlSocket) -> io::Result<Self> {
            if socket.is_blocking()? {
                socket.nonblock()?;
            }
            Ok(NlSocket {
                socket: PollEvented::new(socket)?,
                buffer: SmallVec::new(),
            })
        }

        /// Check if underlying received message buffer is empty
        pub fn empty(&self) -> bool {
            self.buffer.is_empty()
        }
    }

    impl io::Read for super::NlSocket {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.is_blocking()? {
                self.nonblock()?;
            }
            self.recv(buf, 0).map(|i| i as usize)
        }
    }

    impl io::Write for super::NlSocket {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.is_blocking()? {
                self.nonblock()?;
            }
            self.send(buf, 0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<T, P> AsyncRead for NlSocket<T, P> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut mut_ref = self.as_mut();
            poll_read_priv(&mut mut_ref.socket, cx, buf)
        }
    }

    impl<T, P> Stream for NlSocket<T, P>
    where
        T: NlType,
        P: Nl,
    {
        type Item = std::io::Result<Nlmsghdr<T, P>>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            if self.empty() {
                let mut mem = vec![0; MAX_NL_LENGTH];
                let mut mut_ref = self.as_mut();
                let bytes_read = match poll_read_priv(&mut mut_ref.socket, cx, &mut mem) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(None),
                    Poll::Ready(Ok(i)) => i,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                };
                mem.truncate(bytes_read);
                self.buffer = NlBuffer::<T, P>::deserialize(Bytes::from(mem))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            }

            Poll::Ready(self.buffer.pop().map(Ok))
        }
    }

    impl<T, P> Unpin for NlSocket<T, P> {}

    impl Evented for super::NlSocket {
        fn register(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            poll.register(
                &mio::unix::EventedFd(&self.as_raw_fd()),
                token,
                interest,
                opts,
            )
        }

        fn reregister(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            poll.reregister(
                &mio::unix::EventedFd(&self.as_raw_fd()),
                token,
                interest,
                opts,
            )
        }

        fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
            poll.deregister(&mio::unix::EventedFd(&self.as_raw_fd()))
        }
    }

    impl Evented for &mut super::NlSocket {
        fn register(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            <super::NlSocket as Evented>::register(self, poll, token, interest, opts)
        }

        fn reregister(
            &self,
            poll: &mio::Poll,
            token: mio::Token,
            interest: mio::Ready,
            opts: mio::PollOpt,
        ) -> io::Result<()> {
            <super::NlSocket as Evented>::reregister(self, poll, token, interest, opts)
        }

        fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
            <super::NlSocket as Evented>::deregister(self, poll)
        }
    }

    #[cfg(test)]
    mod test {
        use std::io::Read;

        use crate::socket::NlSocket;

        use super::*;

        #[test]
        fn test_socket_nonblock() {
            let mut s = NlSocket::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
            s.nonblock().unwrap();
            assert_eq!(s.is_blocking().unwrap(), false);
            let buf = &mut [0; 4];
            match s.read(buf) {
                Err(e) => {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        panic!("Error: {}", e);
                    }
                }
                Ok(_) => {
                    panic!("Should not return data");
                }
            }
        }
    }
}

impl Drop for NlSocket {
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{consts::Nlmsg, err::SerError};

    #[test]
    fn multi_msg_iter() -> Result<(), SerError> {
        let nl1 = Nlmsghdr::new(
            None,
            Nlmsg::Noop,
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            Genlmsghdr::new(
                CtrlCmd::Unspec,
                2,
                SmallVec::from_vec(vec![
                    Nlattr::new(None, CtrlAttr::FamilyId, 5u32).unwrap(),
                    Nlattr::new(None, CtrlAttr::FamilyName, "my_family_name").unwrap(),
                ]),
            ),
        );
        let nl2 = Nlmsghdr::new(
            None,
            Nlmsg::Noop,
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            Genlmsghdr::new(
                CtrlCmd::Unspec,
                2,
                SmallVec::from(vec![
                    Nlattr::new(None, CtrlAttr::FamilyId, 6u32).unwrap(),
                    Nlattr::new(None, CtrlAttr::FamilyName, "my_other_family_name").unwrap(),
                ]),
            ),
        );
        let v = NlBuffer::<Nlmsg, Genlmsghdr<CtrlCmd, CtrlAttr>>::from(vec![nl1, nl2]);
        let mut bytes = BytesMut::from(vec![0; v.asize()]);
        bytes = v.serialize(bytes)?;

        let bytes_len = bytes.len();
        let mut s = NlSocket {
            fd: -1,
            buffer: bytes,
            position: 0,
            end: bytes_len,
        };
        let mut iter = s.iter();
        if let Some(Ok(nl_next)) = iter.next() {
            assert_eq!(nl_next, v[0]);
        } else {
            panic!("Expected message not found");
        }
        if let Some(Ok(nl_next)) = iter.next() {
            assert_eq!(nl_next, v[1]);
        } else {
            panic!("Expected message not found");
        }
        Ok(())
    }
}
