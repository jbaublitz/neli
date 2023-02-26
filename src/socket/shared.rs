use std::{
    io,
    mem::{size_of, zeroed, MaybeUninit},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use libc::{c_int, c_void};

use crate::{
    consts::socket::*,
    socket::synchronous::NlSocketHandle,
    utils::{Groups, NetlinkBitArray},
};

/// Low level access to a netlink socket.
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the
    /// netlink-specific information.
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let fd = match unsafe {
            libc::socket(
                AddrFamily::Netlink.into(),
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                proto.into(),
            )
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }?;
        Ok(NlSocket { fd })
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Groups) -> Result<Self, io::Error> {
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
    pub fn bind(&self, pid: Option<u32>, groups: Groups) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = c_int::from(AddrFamily::Netlink) as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = groups.as_bitmask();
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
        Ok(())
    }

    /// Join multicast groups for a socket.
    pub fn add_mcast_membership(&self, groups: Groups) -> Result<(), io::Error> {
        for group in groups.as_groups() {
            match unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_ADD_MEMBERSHIP,
                    &group as *const _ as *const libc::c_void,
                    size_of::<u32>() as libc::socklen_t,
                )
            } {
                i if i == 0 => (),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        Ok(())
    }

    /// Leave multicast groups for a socket.
    pub fn drop_mcast_membership(&self, groups: Groups) -> Result<(), io::Error> {
        for group in groups.as_groups() {
            match unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_DROP_MEMBERSHIP,
                    &group as *const _ as *const libc::c_void,
                    size_of::<u32>() as libc::socklen_t,
                )
            } {
                i if i == 0 => (),
                _ => return Err(io::Error::last_os_error()),
            }
        }
        Ok(())
    }

    /// List joined groups for a socket.
    pub fn list_mcast_membership(&self) -> Result<NetlinkBitArray, io::Error> {
        let mut bit_array = NetlinkBitArray::new(4);
        let mut len = bit_array.len();
        if unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_LIST_MEMBERSHIPS,
                bit_array.as_mut_slice() as *mut _ as *mut libc::c_void,
                &mut len as *mut _ as *mut libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if len > bit_array.len() {
            bit_array.resize(len);
            if unsafe {
                libc::getsockopt(
                    self.fd,
                    libc::SOL_NETLINK,
                    libc::NETLINK_LIST_MEMBERSHIPS,
                    bit_array.as_mut_slice() as *mut _ as *mut libc::c_void,
                    &mut len as *mut _ as *mut libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(bit_array)
    }

    /// Send message encoded as byte slice to the netlink ID
    /// specified in the netlink header
    /// [`Nlmsghdr`][crate::nl::Nlmsghdr]
    pub fn send<B>(&self, buf: B, flags: Msg) -> Result<libc::size_t, io::Error>
    where
        B: AsRef<[u8]>,
    {
        match unsafe {
            libc::send(
                self.fd,
                buf.as_ref() as *const _ as *const c_void,
                buf.as_ref().len(),
                flags.bits() as i32,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket.
    pub fn recv<B>(&self, mut buf: B, flags: Msg) -> Result<libc::size_t, io::Error>
    where
        B: AsMut<[u8]>,
    {
        match unsafe {
            libc::recv(
                self.fd,
                buf.as_mut() as *mut _ as *mut c_void,
                buf.as_mut().len(),
                flags.bits() as i32,
            )
        } {
            i if i >= 0 => Ok(i as libc::size_t),
            i if i == -libc::EWOULDBLOCK as isize => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Get the PID for this socket.
    pub fn pid(&self) -> Result<u32, io::Error> {
        let mut sock_len = size_of::<libc::sockaddr_nl>() as u32;
        let mut sock_addr: MaybeUninit<libc::sockaddr_nl> = MaybeUninit::uninit();
        match unsafe {
            libc::getsockname(
                self.fd,
                sock_addr.as_mut_ptr() as *mut _,
                &mut sock_len as *mut _,
            )
        } {
            i if i >= 0 => Ok(unsafe { sock_addr.assume_init() }.nl_pid),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// If [`true`] is passed in, enable extended ACKs for this socket. If [`false`]
    /// is passed in, disable extended ACKs for this socket.
    pub fn enable_ext_ack(&self, enable: bool) -> Result<(), io::Error> {
        match unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_NETLINK,
                libc::NETLINK_EXT_ACK,
                &i32::from(enable) as *const _ as *const libc::c_void,
                size_of::<i32>() as libc::socklen_t,
            )
        } {
            i if i == 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::test::setup;

    #[test]
    fn real_test_pid() {
        setup();

        let s = NlSocket::connect(NlFamily::Generic, Some(5555), Groups::empty()).unwrap();
        assert_eq!(s.pid().unwrap(), 5555);
    }
}
