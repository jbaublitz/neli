//! This module provides code that glues all of the other modules
//! together and allows message send and receive operations.
//!
//! ## Important methods
//! * [`NlSocket::send`] and [`NlSocket::recv`] methods are meant to
//! be the most low level calls. They essentially do what the C
//! system calls `send` and `recv` do with very little abstraction.
//! * [`NlSocketHandle::send`] and [`NlSocketHandle::recv`] methods
//! are meant to provide an interface that is more idiomatic for
//! the library. The are able to operate on any structure wrapped in
//! an [`Nlmsghdr`][crate::nl::Nlmsghdr] struct that implements
//! the [`Nl`] trait.
//! * [`NlSocketHandle::iter`] provides a loop based iteration
//! through messages that are received in a stream over the socket.
//!
//! ## Features
//! The `async` feature exposed by `cargo` allows the socket to use
//! Rust's [tokio](https://tokio.rs) for async IO.
//!
//! ## Additional methods
//!
//! There are methods for blocking and non-blocking, resolving
//! generic netlink multicast group IDs, and other convenience
//! functions so see if your use case is supported. If it isn't,
//! please open a Github issue and submit a feature request.
//!
//! ## Design decisions
//!
//! The buffer allocated in the [`NlSocketHandle`] structure should
//! be allocated on the heap. This is intentional as a buffer
//! that large could be a problem on the stack. Big thanks to
//! [@vorner](https://github.com/vorner) for the suggestion on how
//! to minimize allocations.

use std::{
    fmt::Debug,
    io,
    mem::{size_of, zeroed},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use libc::{self, c_int, c_void};

#[cfg(feature = "logging")]
use crate::log;
use crate::{
    consts::{genl::*, nl::*, socket::*},
    err::{DeError, NlError},
    genl::{Genlmsghdr, Nlattr},
    iter::{IterationBehavior, NlMessageIter},
    nl::{NlPayload, Nlmsghdr},
    parse::packet_length_u32,
    types::{GenlBuffer, NlBuffer, SockBuffer},
    utils::U32Bitmask,
    Nl,
};

/// Low level access to a netlink socket.
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the
    /// netlink-specific information.
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd =
            match unsafe { libc::socket(AddrFamily::Netlink.into(), libc::SOCK_RAW, proto.into()) }
            {
                i if i >= 0 => Ok(i),
                _ => Err(io::Error::last_os_error()),
            }?;
        Ok(NlSocket { fd })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: U32Bitmask,
    ) -> Result<Self, io::Error> {
        let s = NlSocket::new(proto)?;
        s.bind(pid, groups)?;
        Ok(s)
    }

    /// Set underlying socket file descriptor to be blocking.
    pub fn block(&self) -> Result<(), io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) & !libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Set underlying socket file descriptor to be non blocking.
    pub fn nonblock(&self) -> Result<(), io::Error> {
        match unsafe {
            libc::fcntl(
                self.fd,
                libc::F_SETFL,
                libc::fcntl(self.fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
            )
        } {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    /// Determines if underlying file descriptor is blocking.
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        let is_blocking = match unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) } {
            i if i >= 0 => i & libc::O_NONBLOCK == 0,
            _ => return Err(io::Error::last_os_error()),
        };
        Ok(is_blocking)
    }

    /// Use this function to bind to a netlink ID and subscribe to
    /// groups. See netlink(7) man pages for more information on
    /// netlink IDs and groups.
    pub fn bind(&self, pid: Option<u32>, groups: U32Bitmask) -> Result<(), io::Error> {
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

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
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

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
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

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<U32Bitmask, io::Error> {
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

    /// Send message encoded as byte slice to the netlink ID
    /// specified in the netlink header
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr]
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

    /// Receive message encoded as byte slice from the netlink socket.
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

    /// Get the current pid address from sock name (useful when the pid passed was None)
    pub fn get_pid_from_sock(&self) -> Result<u32, io::Error> {
        let mut addr = std::mem::MaybeUninit::uninit();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        match unsafe {
            libc::getsockname(self.fd, addr.as_mut_ptr() as *mut libc::sockaddr, &mut len)
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }?;
        let filled_addr: &libc::sockaddr_storage = unsafe { &addr.assume_init() };
        let filled_len: usize = len as usize;
        if filled_len > std::mem::size_of::<libc::sockaddr_un>() {
            return Err(io::Error::last_os_error());
        }
        if filled_len < std::mem::size_of_val(&filled_addr.ss_family) {
            return Err(io::Error::last_os_error());
        }
        match libc::c_int::from(filled_addr.ss_family) {
            libc::AF_NETLINK => {
                let snl: *const libc::sockaddr_nl =
                    filled_addr as *const _ as *const libc::sockaddr_nl;
                let pid: u32 = unsafe { (*snl).nl_pid };
                Ok(pid)
            }
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}

impl From<NlSocketHandle> for NlSocket {
    fn from(s: NlSocketHandle) -> Self {
        s.socket
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
        NlSocket { fd }
    }
}

impl Drop for NlSocket {
    /// Closes underlying file descriptor to avoid file descriptor
    /// leaks.
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Higher level handle for socket operations.
pub struct NlSocketHandle {
    socket: NlSocket,
    buffer: SockBuffer,
    position: usize,
    end: usize,
    needs_ack: bool,
}

impl NlSocketHandle {
    /// Wrapper around `socket()` syscall filling in the
    /// netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        Ok(NlSocketHandle {
            socket: NlSocket::new(proto)?,
            buffer: SockBuffer::new(),
            position: 0,
            end: 0,
            needs_ack: false,
        })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(
        proto: NlFamily,
        pid: Option<u32>,
        groups: U32Bitmask,
    ) -> Result<Self, io::Error> {
        Ok(NlSocketHandle {
            socket: NlSocket::connect(proto, pid, groups)?,
            buffer: SockBuffer::new(),
            position: 0,
            end: 0,
            needs_ack: false,
        })
    }

    /// Set underlying socket file descriptor to be blocking.
    pub fn block(&self) -> Result<(), io::Error> {
        self.socket.block()
    }

    /// Set underlying socket file descriptor to be non blocking.
    pub fn nonblock(&self) -> Result<(), io::Error> {
        self.socket.nonblock()
    }

    /// Determines if underlying file descriptor is blocking.
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        self.socket.is_blocking()
    }

    /// Get the pid from the socket after binding (useful when the pid passed was None)
    pub fn get_pid(&self) -> Result<u32, io::Error> {
        self.socket.get_pid_from_sock()
    }

    /// Use this function to bind to a netlink ID and subscribe to
    /// groups. See netlink(7) man pages for more information on
    /// netlink IDs and groups.
    pub fn bind(&self, pid: Option<u32>, groups: U32Bitmask) -> Result<(), io::Error> {
        self.socket.bind(pid, groups)
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
        self.socket.add_mcast_membership(groups)
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: U32Bitmask) -> Result<(), io::Error> {
        self.socket.drop_mcast_membership(groups)
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<U32Bitmask, io::Error> {
        self.socket.list_mcast_membership()
    }

    fn get_genl_family<T>(
        &mut self,
        family_name: &str,
    ) -> Result<NlBuffer<NlTypeWrapper, Genlmsghdr<CtrlCmd, T>>, NlError>
    where
        T: NlAttrType + Debug,
    {
        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(
            None,
            false,
            false,
            CtrlAttr::FamilyName,
            family_name,
        )?);
        let genlhdr = Genlmsghdr::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Request, NlmF::Ack]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );
        self.send(nlhdr)?;

        let mut buffer = NlBuffer::new();
        for msg in self.iter(false) {
            buffer.push(msg?);
        }
        Ok(buffer)
    }

    /// Convenience function for resolving a [`str`] containing the
    /// generic netlink family name to a numeric generic netlink ID.
    pub fn resolve_genl_family(&mut self, family_name: &str) -> Result<u16, NlError> {
        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs.into_iter() {
            let attrs = nlhdr
                .nl_payload
                .get_payload()
                .ok_or_else(|| NlError::new("No attributes were returned in this message."))?;
            let handle = attrs.get_attr_handle();
            if let Ok(u) = handle.get_attr_payload_as::<u16>(CtrlAttr::FamilyId) {
                return Ok(u);
            }
        }
        Err(NlError::new(format!(
            "Generic netlink family {} was not found",
            family_name
        )))
    }

    /// Convenience function for resolving a [`str`] containing the
    /// multicast group name to a numeric multicast group ID.
    pub fn resolve_nl_mcast_group(
        &mut self,
        family_name: &str,
        mcast_name: &str,
    ) -> Result<u32, NlError> {
        let nlhdrs = self.get_genl_family(family_name)?;
        for nlhdr in nlhdrs {
            let attrs = nlhdr
                .nl_payload
                .get_payload()
                .ok_or_else(|| NlError::new("No attributes were returned in this message."))?;
            let mut handle = attrs.get_attr_handle();
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

    /// Look up netlink family and multicast group name by ID.
    pub fn lookup_id(&mut self, id: u32) -> Result<(String, String), NlError> {
        let attrs = GenlBuffer::new();
        let genlhdr = Genlmsghdr::<CtrlCmd, CtrlAttrMcastGrp>::new(CtrlCmd::Getfamily, 2, attrs);
        let nlhdr = Nlmsghdr::new(
            None,
            GenlId::Ctrl,
            NlmFFlags::new(&[NlmF::Ack, NlmF::Request, NlmF::Dump]),
            None,
            None,
            NlPayload::Payload(genlhdr),
        );

        self.send(nlhdr)?;
        for res_msg in self.iter::<Genlmsghdr<u8, CtrlAttr>>(false) {
            let msg = res_msg?;

            let mut attributes = msg
                .nl_payload
                .get_payload()
                .ok_or_else(|| NlError::new("No attributes returned in this message."))?
                .get_attr_handle();
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

    /// Convenience function to send an [`Nlmsghdr`] struct
    pub fn send<T, P>(&mut self, msg: Nlmsghdr<T, P>) -> Result<(), NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        #[cfg(feature = "logging")]
        log!("Message sent:\n{:#?}", msg);

        if msg.nl_flags.contains(&NlmF::Ack) {
            self.needs_ack = true;
        }

        let mut buffer = vec![0; msg.asize()];
        msg.serialize(buffer.as_mut_slice()).map_err(NlError::new)?;
        self.socket.send(buffer, 0)?;

        Ok(())
    }

    /// Convenience function to begin receiving a stream of
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] structs.
    pub fn recv<T, P>(&mut self) -> Result<Option<Nlmsghdr<T, P>>, NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        if self.end == self.position {
            // Borrow buffer for writing.
            let mut_buffer = self.buffer.get_mut().expect("Caller borrows mutable self");

            // Read the buffer from the socket and fail if nothing
            // was read.
            let mem_read_res = self.socket.recv(mut_buffer, 0);
            if let Err(ref e) = mem_read_res {
                if e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
            }
            let mem_read = mem_read_res?;
            if mem_read == 0 {
                return Ok(None);
            }
            self.position = 0;
            self.end = mem_read;
        }

        let (packet_res, next_packet_len) = {
            let buffer = self.buffer.get_ref().expect("Caller borrows mutable self");
            let end = buffer.as_ref().len();
            // Get the next packet length at the current position of the
            // buffer for the next read operation.
            if self.position == end {
                return Ok(None);
            }
            let next_packet_len = packet_length_u32(buffer.as_ref(), self.position);
            // If the packet extends past the end of the number of bytes
            // read into the buffer, return an error; something
            // has gone wrong.
            if self.position + next_packet_len > end {
                return Err(NlError::new(DeError::UnexpectedEOB));
            }

            // Deserialize the next Nlmsghdr struct.
            let deserialized_packet_result = Nlmsghdr::<T, P>::deserialize(
                &buffer.as_ref()[self.position..self.position + next_packet_len],
            );

            (deserialized_packet_result, next_packet_len)
        };

        let packet = packet_res
            .map(|packet| {
                // If successful, forward the position of the buffer
                // for the next read.
                self.position += next_packet_len;

                packet
            })
            .map_err(NlError::new)?;

        #[cfg(feature = "logging")]
        log!("Message received: {:#?}", packet);

        if let NlPayload::Err(e) = packet.nl_payload {
            return Err(NlError::Nlmsgerr(e));
        }

        if self.needs_ack
            && (!packet.nl_flags.contains(&NlmF::Multi)
                || packet.nl_type.into() == Nlmsg::Done.into())
        {
            let is_blocking = self.is_blocking()?;
            self.nonblock()?;
            self.needs_ack = false;
            let potential_ack = self.recv::<T, P>()?;
            if let Some(NlPayload::Payload(_))
            | Some(NlPayload::Empty)
            | Some(NlPayload::Err(_))
            | None = potential_ack.as_ref().map(|p| &p.nl_payload)
            {
                return Err(NlError::NoAck);
            }
            if is_blocking {
                self.block()?;
            }
        }

        Ok(Some(packet))
    }

    /// Parse all [`Nlmsghdr`][crate::nl::Nlmsghdr] structs sent in
    /// one network packet and return them all in a list.
    ///
    /// Failure to parse any packet will cause the entire operation
    /// to fail. If an error is detected at the application level,
    /// this method will discard any non-error
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr] structs and only return the
    /// error. This method checks for ACKs. For a more granular
    /// approach, use either [`NlSocketHandle::recv`] or
    /// [`NlSocketHandle::iter`].
    pub fn recv_all<T, P>(&mut self) -> Result<NlBuffer<T, P>, NlError>
    where
        T: Nl + NlType + Debug,
        P: Nl + Debug,
    {
        if self.position == self.end {
            let mut_buffer = self.buffer.get_mut().expect("Caller borrows mutable self");
            let mem_read = self.socket.recv(mut_buffer, 0)?;
            if mem_read == 0 {
                return Err(NlError::new("No data could be read from the socket"));
            }
            self.end = mem_read;
        }

        let buffer = self.buffer.get_ref().expect("Caller borrows mutable self");
        let vec = NlBuffer::deserialize(&buffer.as_ref()[0..self.end]).map_err(NlError::new)?;

        #[cfg(feature = "logging")]
        log!("Messages received: {:#?}", vec);

        self.position = 0;
        self.end = 0;
        Ok(vec)
    }

    /// Return an iterator object
    ///
    /// The argument `iterate_indefinitely` is documented
    /// in more detail in [`NlMessageIter`]
    pub fn iter<P>(&mut self, iter_indefinitely: bool) -> NlMessageIter<NlTypeWrapper, P>
    where
        P: Nl + Debug,
    {
        let behavior = if iter_indefinitely {
            IterationBehavior::IterIndefinitely
        } else {
            IterationBehavior::EndMultiOnDone
        };
        NlMessageIter::new(self, behavior)
    }

    /// Return an iterator object.
    ///
    /// This method allows more flexibility than
    /// `NlSocketHandle::iter()` and allows specifying what the
    /// type of the netlink packets should be as well as the
    /// payload.
    ///
    /// The argument `iterate_indefinitely` is documented
    /// in more detail in [`NlMessageIter`]
    pub fn iter2<T, P>(&mut self, iter_indefinitely: bool) -> NlMessageIter<T, P>
    where
        T: NlType + Debug,
        P: Nl + Debug,
    {
        let behavior = if iter_indefinitely {
            IterationBehavior::IterIndefinitely
        } else {
            IterationBehavior::EndMultiOnDone
        };
        NlMessageIter::new(self, behavior)
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

impl FromRawFd for NlSocketHandle {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NlSocketHandle {
            socket: NlSocket::from_raw_fd(fd),
            buffer: SockBuffer::new(),
            end: 0,
            position: 0,
            needs_ack: false,
        }
    }
}

#[cfg(all(feature = "async", not(no_std)))]
pub mod tokio {
    //! Tokio-specific features for neli
    //!
    //! This module contains a struct that wraps [`NlSocket`] for
    //! async IO.
    use super::*;

    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use ::tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};
    use futures_util::ready;
    use tokio_stream::Stream;

    use crate::neli_constants::MAX_NL_LENGTH;

    fn poll_read_priv(
        async_fd: &AsyncFd<super::NlSocket>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<usize>> {
        let mut guard = ready!(async_fd.poll_read_ready(cx))?;
        guard.clear_ready();
        let socket = async_fd.get_ref();
        let bytes_read = socket.recv(buf.initialized_mut(), 0)?;
        buf.advance(bytes_read);
        Poll::Ready(Ok(bytes_read))
    }

    fn poll_write_priv(
        async_fd: &AsyncFd<super::NlSocket>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = ready!(async_fd.poll_write_ready(cx))?;
        guard.clear_ready();
        let socket = async_fd.get_ref();
        Poll::Ready(socket.send(buf, 0))
    }

    /// Tokio-enabled Netlink socket struct
    pub struct NlSocket<T, P> {
        socket: Arc<AsyncFd<super::NlSocket>>,
        parsed_packets: NlBuffer<T, P>,
    }

    impl<'a, T, P> NlSocket<T, P>
    where
        T: NlType,
    {
        /// Set up [`NlSocket`][crate::socket::NlSocket] for use
        /// with tokio; set to nonblocking state and wrap in polling
        /// mechanism.
        pub fn new<S>(s: S) -> io::Result<Self>
        where
            S: Into<super::NlSocket>,
        {
            let socket = s.into();
            if socket.is_blocking()? {
                socket.nonblock()?;
            }
            Ok(NlSocket {
                socket: Arc::new(AsyncFd::new(socket)?),
                parsed_packets: NlBuffer::new(),
            })
        }

        /// Check if underlying received message buffer is empty
        pub fn empty(&self) -> bool {
            self.parsed_packets.is_empty()
        }
    }

    impl<T, P> AsyncRead for NlSocket<T, P> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf,
        ) -> Poll<io::Result<()>> {
            let _ = ready!(poll_read_priv(&self.socket, cx, buf))?;
            Poll::Ready(Ok(()))
        }
    }

    impl<T, P> AsyncWrite for NlSocket<T, P> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            poll_write_priv(&self.socket, cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl<T, P> Stream for NlSocket<T, P>
    where
        T: NlType,
        P: Nl,
    {
        type Item = Result<Nlmsghdr<T, P>, NlError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
            let packets = if self.empty() {
                let mut mem = vec![0; MAX_NL_LENGTH];
                let mut buf = ReadBuf::new(mem.as_mut_slice());
                let bytes_read = match poll_read_priv(&self.socket, cx, &mut buf) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(None),
                    Poll::Ready(Ok(i)) => i,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(NlError::from(e)))),
                };
                mem.truncate(bytes_read);
                Some(NlBuffer::deserialize(mem.as_slice())?)
            } else {
                None
            };

            if let Some(p) = packets {
                for packet in p.into_iter().rev() {
                    self.parsed_packets.push(packet);
                }
            }

            Poll::Ready(self.parsed_packets.pop().map(Ok))
        }
    }

    impl<T, P> Unpin for NlSocket<T, P> {}

    #[cfg(test)]
    mod test {
        use super::*;

        use ::tokio::runtime::Runtime;
        use tokio_stream::StreamExt;

        use crate::socket::{self, tokio::NlSocket};

        #[test]
        fn test_socket_send() {
            let s =
                socket::NlSocket::connect(NlFamily::Generic, None, U32Bitmask::empty()).unwrap();
            let runtime = Runtime::new().unwrap();
            runtime
                .block_on(async move {
                    let mut async_s = NlSocket::<NlTypeWrapper, u8>::new(s).unwrap();
                    ::tokio::task::spawn(async move {
                        let _ = async_s.try_next();
                    })
                    .await
                })
                .unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{consts::nl::Nlmsg, utils::serialize};

    #[test]
    fn multi_msg_iter() {
        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(None, false, false, CtrlAttr::FamilyId, 5u32).unwrap());
        attrs
            .push(Nlattr::new(None, false, false, CtrlAttr::FamilyName, "my_family_name").unwrap());
        let nl1 = Nlmsghdr::new(
            None,
            NlTypeWrapper::Nlmsg(Nlmsg::Noop),
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            NlPayload::Payload(Genlmsghdr::new(CtrlCmd::Unspec, 2, attrs)),
        );

        let mut attrs = GenlBuffer::new();
        attrs.push(Nlattr::new(None, false, false, CtrlAttr::FamilyId, 6u32).unwrap());
        attrs.push(
            Nlattr::new(
                None,
                false,
                false,
                CtrlAttr::FamilyName,
                "my_other_family_name",
            )
            .unwrap(),
        );
        let nl2 = Nlmsghdr::new(
            None,
            NlTypeWrapper::Nlmsg(Nlmsg::Noop),
            NlmFFlags::new(&[NlmF::Multi]),
            None,
            None,
            NlPayload::Payload(Genlmsghdr::new(CtrlCmd::Unspec, 2, attrs)),
        );
        let mut v = NlBuffer::new();
        v.push(nl1);
        v.push(nl2);
        let bytes = serialize(&v, true).unwrap();

        let bytes_len = bytes.len();
        let mut s = NlSocketHandle {
            socket: unsafe { NlSocket::from_raw_fd(-1) },
            buffer: SockBuffer::from(bytes.as_ref()),
            needs_ack: false,
            position: 0,
            end: bytes_len,
        };
        let mut iter = s.iter(false);
        let nl_next1 = if let Some(Ok(nl_next)) = iter.next() {
            nl_next
        } else {
            panic!("Expected message not found");
        };
        let nl_next2 = if let Some(Ok(nl_next)) = iter.next() {
            nl_next
        } else {
            panic!("Expected message not found");
        };
        let mut nl = NlBuffer::new();
        nl.push(nl_next1);
        nl.push(nl_next2);
        assert_eq!(nl, v);
    }
}
