# Changelog

## 0.6.1
### Bug fixes
* Bug fix for `RtBuffer` and `GenlBuffer` size calculation
* Bug fix for `Rtattr` size calculation
* Bug fixes in tokio usage
* Bug fix where padding at the end of an empty netlink packet caused errors

### Improvements
* Better debug logging

See all pull requests and issues that went into this release [here!](https://github.com/jbaublitz/neli/milestone/12?closed=1)

## 0.6.0
### Bug fixes
* Fixed problem where `Tcmsg` could not be created due to padding.
* Fixed problem with listing multicast groups.

### Additions
* Addition of `neli-proc-macros` crate to handle most of trait
generation.
* More testing!

### Breaking changes
* Changed the core traits from `Nl` to a number of different, more
granular traits.
* Consolidated `iter()` and `iter2()`.
* Major changes to async module.
* Changes to how bit flag sets are handled.

## 0.5.3
### Bug fixes
* Bug fix for `Ifinfomsg.ifi_change` being serialized twice.
* Bug fix for `Ndmsg` where it could not be constructed due to
  private padding fields.
* Bug fix for `Ifinfomsg.ifi_change`. This should be of type
 `IffFlags`, not `Iff`.
* Fixed assumption in `NlSocketHandle::recv()` where this method
  never expected an ACK to be returned with no data.
  * The behavior of `NlSocketHandle::recv()` has changed slightly.
    It will now return ACKs and only returns `None` when nonblocking.
    Use `NlSocketHandle::iter()` for handling of streams of messages.
* Fixed bug for deserialization of errors returned at the
  application level.
* Fixed bug in subscription to multicast groups.
  * The API has been changed and `U32Bitmask` has been replaced by
    `NetlinkBitArray`.

### Additions
* More constants in `Arphrd`.
* More constants in `Ifla`.
* Addition of `NlSocketHandle::iter2()` that does not restrict
  users to the `NlWrapperType` type for packet parsing.
* Addition of convenience methods on `RtBuffer` and `GenlBuffer`
  types to make parsing nested attributes easier.

### Dependency updates
* Update to tokio 1.0.

## 0.5.2
### Bug fixes
* Fixed bug in `Ifaddrmsg` serialization and deserialization.
  Thanks, [`@joshtriplett`](https://github.com/joshtriplett)!

## 0.5.1
### Bug fixes
* Fixed bug in ACK handling.
  * This change makes `NlSocketHandle` exclusively responsible
    for handling ACKs.

## 0.5.0
### Breaking changes
* Change from `buffering` structs for serialization to regular slices
  to allow buffer size tracking for each layer of serialization
  and deserialization and easy slicing into smaller, sized pieces.
* Change `stream` feature to `async` for clarity with higher level
  API.
* Remove `seq` and `pid` tracking. This will eventually be added to
  higher level APIs.
* Make `NlSocket::send`/`::recv` take an immutable reference due to
  the case made for message vs. stream based sockets.
* Remove universal exports of constants from the `consts` module.
* Update to tokio 0.3.
* Split lower level and higher level synchronous netlink socket calls
  across two structs, `NlSocket` and `NlSocketHandle`.
* Factor out parsing code so that it can be used across multiple
  socket types.
* Add nested netlink attribute parsing for routing netlink attributes. 
* Changes to the `Nlmsg` struct to support handling application
  errors returned by the kernel. Previously, there was no easy way
  to handle application errors returned inside of an `Nlmsg` packet.
* Added the ability to define the visibility for constants defined by
  the `consts` macros.

### Additions
* Add genetlink ID to family name/multicast group name lookup.
* Add `Index` type for nested attributes returned as a numbered list.
* `NlSocket` functions to leave/list multicast groups.
* Macro infrastructure for generating `serialize` and `deserialize`
  methods safely.
* `attr` module for shared attribute code.
* Debug logging enabled through the `logging` feature.

### Deprecations
* `Nlattr.get_nested_attributes()` in favor of `.get_attr_handle()`
* `NlSocket.set_mcast_groups()` in favor of `.add_multicast_membership()`

### Bug fixes
* Bug fixes for rtnetlink

### Documentation
* Updates to the documentation.
* More examples.
* Links to the referenced data structures.

## 0.5.0-rc1
### Additions
* Feature flagged NFLOG support, in the `netfilter` module.

### Resolved issues
* Resolved issue relating to allowing documentation annotations in
  macros for enum variants representing netlink constants.

## 0.4.3
### Breaking changes
* Change `Nlattr.add_nested_attribute()` to take a reference

### Additions
* Support `RTM_*` constants in `consts.rs`
* Fix length calculation errors
* Add methods to Nl trait with default implementations - does not break API
* Additional tests for padding
* Add design decision documentation for new padding handling

### Deprecations
* Deprecate `.size()` usage for `Vec<Nlattr>` - use `.asize()` instead

### Structure changes
* `consts.rs` is now `consts/` with a corresponding submodule for each category of constant -
not a breaking change
* Start enforcing rustfmt in CI and use cargo fmt to switch over to new formatting

### Fixes
* Merge PR fixing rtnetlink support

## 0.4.2
### Dependencies
* Update buffering to 0.3.4 minimum to force stable channel support for neli

## 0.4.1
### Breaking changes
* Revert to builder pattern for creating/parsing generic netlink messages with attributes
  * Particular notable changes for nested attribute handling

## 0.4.0
### Breaking changes
* Rework API in a number of places:
  * Tokio support for sockets
  * Many socket functions
  * Generic netlink

### Additions
* Support for rtnetlink
* Iterative message parsing from `NlSocket`

### Bug fixes
* Support parsing multiple netlink messages returned in the same socket read buffer
* Missing documentation added
* Fix alignment bugs when serializing netlink attributes

## 0.3.1
### Breaking changes
* Migration to buffering crate for buffer operations - _this does change the API_

# NOTE:
For record keeping it should be noted that semantic versioning was misused here. 0.3.0-r1 and
0.3.0-r2 should have been 0.3.1 and 0.3.2 respectively.

## 0.3.0-r2
### Bug fixes
* Fix documentation bug

## 0.3.0-r1
### Bug fixes
* After looking at tokio's `File` implementation, the file descriptor should block for
the `Stream` implementation

## 0.3.0
### Breaking changes
* Type signature of `bind` and `connect` calls' `groups` parameter was changed to be a `Vec<u32>`
which will allow specifying a list of IDs and the group bitmask will be calculated for the user.
* `poll` implementation of for `NlSocket` for `tokio::prelude::Stream` trait will now return
`io::ErrorKind::InvalidData` if the socket file descriptor is not set to non-blocking
before polling. This is intentional as Tokio docs rely on polls being non-blocking and my
implementation requires a read that either returns an `io::ErrorKind::WouldBlock` value or
the desired data.
* There is now an `nlattr` module to group together all of the netlink attribute code.

### Additions
* A function `block` was added to allow reversing `nonblock` function on `NlSocket`.
* `is_blocking` was added and returns a `bool` indicating whether reads will block on this socket.

### Deprecations
* `get_payload_as` was deprecated in favor of `get_payload_with`.

### Removed
None

## Versions prior to 0.3.0 are not included in the CHANGELOG
