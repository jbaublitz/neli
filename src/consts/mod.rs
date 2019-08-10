//! # High level notes
//!
//! The items in this module are created by macros, which give them the traits necessary to be
//! serialized into Netlink compatible types. The macros are exported - you can use them too!
//! See `impl_var`, `impl_trait`, and `impl_var_trait`.
//!
//! Note that most of these constants come from the Linux kernel headers, which can be found
//! in `/usr/include/linux` on many distros. You can also see `man 3 netlink`, `man 7 netlink`,
//! and `man 7 rtnetlink` for more information.
//!
//! # Design decisions
//!
//! * Macros are exported so that these conventions are extensible and usable for data types
//!   implemented by the user in the case of new netlink families (which is supported by the
//!   protocol). In this case, there is no way in which I can support every custom netlink family
//!   but my aim is to make this library as flexible as possible so that it is painless to hook
//!   your custom netlink data type into the existing library support.
//! * Enums are used so that:
//!   * Values can be checked based on a finite number of inputs as opposed to the range of
//!     whatever integer data type C defines as the struct member type. This hopefully makes it
//!     easier to catch garbage responses and corruption when an invalid netlink message is sent to
//!     the kernel.
//!   * Only the enum or an enum implementing a marker trait in the case of generics can be used
//!     in the appropriate places when constructing netlink messages. This takes guess work out
//!     of which constants can be used where. Netlink documentation is not always complete
//!     and sometimes takes a bit of trial and error actually sending messages to the kernel
//!     to figure out if you are using the correct constants. This setup should let you know at
//!     compile time if you are doing something you should not be doing.
//! * `UnrecognizedVariant` is included in each enum because completeness cannot be guaranteed for
//!   every constant for every protocol. This allows you to inspect the integer value returned
//!   and if you are sure that it is correct, you can use it. If it is a garbage value, this can
//!   also be useful for error reporting.

#[macro_use]
mod macros;

/// Constants related to generic netlink
pub mod genl;
pub use crate::consts::genl::*;
/// Constants related to generic netlink attributes
pub mod nlattr;
pub use crate::consts::nlattr::*;
/// Constants related to generic netlink top level headers 
pub mod nl;
pub use crate::consts::nl::*;
/// Constants related to rtnetlink
pub mod rtnl;
pub use crate::consts::rtnl::*;
/// Constants related to netlink socket operations
pub mod socket;
pub use crate::consts::socket::*;

/// Reimplementation of alignto macro in C
pub fn alignto(len: usize) -> usize {
    (len + libc::NLA_ALIGNTO as usize - 1) & !(libc::NLA_ALIGNTO as usize - 1)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_documented_conversions() {
        let unspec: u8 = CtrlCmd::Unspec.into();
        assert_eq!(unspec, libc::CTRL_CMD_UNSPEC as u8);

        let unspec_variant = CtrlCmd::from(libc::CTRL_CMD_UNSPEC as u8);
        assert_eq!(unspec_variant, CtrlCmd::Unspec);
    }
}
