//! # Socket code around `libc`
//! 
//! ## Notes
//! 
//! This module provides a low level one-to-one mapping between `libc` system call wrappers
//! with defaults specific to netlink sockets as well as a higher level API for simplification
//! of netlink code.

use std::io;
use std::os::unix::io::{AsRawFd,IntoRawFd,RawFd};
use std::mem::{zeroed,size_of};

use libc::{self,c_int,c_void};

use {Nl,NlSerState,NlDeState};
use err::NlError;
use ffi::NlFamily;
use nlhdr::NlHdr;

/// Handle for the socket file descriptor
pub struct NlSocket {
    fd: c_int,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: NlFamily) -> Result<Self, io::Error> {
        let proto_u32: u32 = proto.into();
        let fd = match unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto_u32 as libc::c_int)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        };
        Ok(NlSocket { fd: try!(fd) })
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    pub fn bind(&mut self, pid: Option<u32>, groups: Option<u32>) -> Result<(), io::Error> {
        let mut nladdr = unsafe { zeroed::<libc::sockaddr_nl>() };
        nladdr.nl_family = libc::AF_NETLINK as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        nladdr.nl_groups = groups.unwrap_or(0);
        match unsafe {
            libc::bind(self.fd, &nladdr as *const _ as *const libc::sockaddr,
                       size_of::<libc::sockaddr_nl>() as u32)
        } {
            i if i >= 0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Send message encoded as byte slice to the netlink ID specified in the netlink header
    /// (`nl::nlhdr::NlHdr`).
    pub fn send(&mut self, buf: &[u8], flags: i32) -> Result<isize, io::Error> {
        match unsafe {
            libc::send(self.fd, buf as *const _ as *const c_void, buf.len(), flags)
        } {
            i if i >= 0 => Ok(i),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Receive message encoded as byte slice from the netlink socket.
    pub fn recv(&mut self, len: Option<usize>, flags: i32) -> Result<Vec<u8>, io::Error> {
        let mut v = match len {
            Some(l) => vec![0; l],
            None => Vec::new(),
        };
        match unsafe {
            libc::recv(self.fd, v.as_mut_slice() as *mut _ as *mut c_void, v.len(), flags)
        } {
            i if i >= 0 => {
                v.truncate(i as usize);
                Ok(v)
            },
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: NlFamily, pid: Option<u32>, groups: Option<u32>)
                   -> Result<Self, io::Error> {
        let mut s = try!(NlSocket::new(proto));
        try!(s.bind(pid, groups));
        Ok(s)
    }

    /// Serialize and send Rust `NlMsg` type
    pub fn sendmsg<I: Nl, T: Nl>(&mut self, mut msg: NlHdr<I, T>, flags: i32)
                                        -> Result<isize, NlError> {
        let mut state = NlSerState::new();
        try!(msg.serialize(&mut state));
        let len = try!(self.send(state.into_inner().as_slice(), flags));
        Ok(len)
    }

    /// Receive and deserialize Rust `NlMsg` type
    pub fn recvmsg<I: Nl, T: Nl>(&mut self, len: Option<usize>, flags: i32)
                                       -> Result<NlHdr<I, T>, NlError> {
        let mut buf = try!(self.recv(len, flags));
        let msg = try!(<NlHdr<I, T> as Nl>::deserialize(&mut NlDeState::new(buf.as_mut_slice())));
        Ok(msg)
    }
}

impl AsRawFd for NlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for NlSocket {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

impl Drop for NlSocket {
    /// Closes underlying file descriptor to avoid file descriptor leaks.
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_socket_creation() {
        match NlSocket::connect(NlFamily::Generic, None, None) {
            Err(_) => panic!(),
            _ => (),
        }
    }
}
