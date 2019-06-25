# Changelog

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
