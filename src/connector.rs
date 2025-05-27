//! Connector module for netlink messages.

use crate::nl::NlmsghdrBuilderError;
use crate::{Header, Size, ToBytes};
use derive_builder::{Builder, UninitializedFieldError};
use getset::Getters;

use crate as neli;

/// Netlink connector message header and payload.
#[derive(
    Builder, Getters, Clone, Debug, PartialEq, Eq, Size, ToBytes, FromBytesWithInput, Header,
)]
#[neli(from_bytes_bound = "P: Size + FromBytesWithInput<Input = usize>")]
#[builder(build_fn(skip))]
#[builder(pattern = "owned")]
pub struct CnMsg<P> {
    /// Index of the connector (idx)
    #[getset(get = "pub")]
    idx: u32,
    /// Value (val)
    #[getset(get = "pub")]
    val: u32,
    /// Sequence number
    #[getset(get = "pub")]
    seq: u32,
    /// Acknowledgement number
    #[getset(get = "pub")]
    ack: u32,
    /// Length of the payload
    #[builder(setter(skip))]
    #[getset(get = "pub")]
    len: u16,
    /// Flags
    #[getset(get = "pub")]
    flags: u16,
    /// Payload of netlink message
    #[neli(size = "len as usize")]
    #[neli(input = "(len as usize)")]
    #[getset(get = "pub")]
    pub(crate) payload: P,
}

use std::mem::size_of;

impl<P: Size> CnMsgBuilder<P> {
    /// Build [`CnMsg`].
    pub fn build(self) -> Result<CnMsg<P>, NlmsghdrBuilderError> {
        let idx = self
            .idx
            .ok_or_else(|| NlmsghdrBuilderError::from(UninitializedFieldError::new("idx")))?;
        let val = self
            .val
            .ok_or_else(|| NlmsghdrBuilderError::from(UninitializedFieldError::new("val")))?;
        let seq = self.seq.unwrap_or(0);
        let ack = self.ack.unwrap_or(0);
        let flags = self.flags.unwrap_or(0);
        let payload = self.payload.ok_or_else(|| {
            NlmsghdrBuilderError::from(UninitializedFieldError::new("payload"))
        })?;

        let cn_msg = CnMsg {
            idx,
            val,
            seq,
            ack,
            len: size_of::<P>() as u16,
            flags,
            payload,
        };
        Ok(cn_msg)
    }
}

use crate::FromBytesWithInput;
use byteorder::{NativeEndian, ReadBytesExt};
use std::io::Read;

/// Process event type as reported by the kernel connector.
#[neli::neli_enum(serialized_type = "u32")]
pub enum ProcEventType {
    None = 0x00000000,
    Fork = 0x00000001,
    Exec = 0x00000002,
    Uid = 0x00000004,
    Gid = 0x00000040,
    Sid = 0x00000080,
    Ptrace = 0x00000100,
    Comm = 0x00000200,
    NonzeroExit = 0x20000000,
    Coredump = 0x40000000,
    Exit = 0x80000000,
}

/// Ergonomic enum for process event data.
#[derive(Debug, Size, Copy, Clone)]
pub enum ProcEvent {
    Ack {
        err: u32,
    },
    Fork {
        parent_pid: i32,
        parent_tgid: i32,
        child_pid: i32,
        child_tgid: i32,
    },
    Exec {
        process_pid: i32,
        process_tgid: i32,
    },
    Uid {
        process_pid: i32,
        process_tgid: i32,
        ruid: u32,
        euid: u32,
    },
    Gid {
        process_pid: i32,
        process_tgid: i32,
        rgid: u32,
        egid: u32,
    },
    Sid {
        process_pid: i32,
        process_tgid: i32,
    },
    Ptrace {
        process_pid: i32,
        process_tgid: i32,
        tracer_pid: i32,
        tracer_tgid: i32,
    },
    Comm {
        process_pid: i32,
        process_tgid: i32,
        comm: [u8; 16],
    },
    Coredump {
        process_pid: i32,
        process_tgid: i32,
        parent_pid: i32,
        parent_tgid: i32,
    },
    Exit {
        process_pid: i32,
        process_tgid: i32,
        exit_code: u32,
        exit_signal: u32,
        parent_pid: i32,
        parent_tgid: i32,
    },
}

/// Header for process event messages.
#[derive(Debug, Size)]
pub struct ProcEventHeader {
    pub what: ProcEventType,
    pub cpu: u32,
    pub timestamp_ns: u64,
    pub event: ProcEvent,
}

use crate::err::{DeError, MsgError};
use log::trace;
use std::io::Cursor;

impl FromBytesWithInput for ProcEventHeader {
    type Input = usize;

    fn from_bytes_with_input(
        buffer: &mut Cursor<impl AsRef<[u8]>>,
        input: Self::Input,
    ) -> Result<Self, DeError> {
        let start = buffer.position() as usize;
        let bytes = buffer.get_ref().as_ref();

        trace!(
            "Parsing ProcEventHeader at position {} with input size {}",
            start,
            input
        );

        // Minimum size for header (16) + smallest event (ack: 4) is 20. Header alone is 16.
        if input < 16 || bytes.len() < start + input {
            return Err(DeError::InvalidInput(input));
        }

        // Read header fields: what (u32), cpu (u32), timestamp_ns (u64)
        let what_val = buffer.read_u32::<NativeEndian>()?;
        let what = ProcEventType::from(what_val);
        let cpu = buffer.read_u32::<NativeEndian>()?;
        let timestamp_ns = buffer.read_u64::<NativeEndian>()?;

        let event = match what {
            ProcEventType::None => {
                let err = buffer.read_u32::<NativeEndian>()?;
                ProcEvent::Ack { err }
            }
            ProcEventType::Fork => {
                let parent_pid = buffer.read_i32::<NativeEndian>()?;
                let parent_tgid = buffer.read_i32::<NativeEndian>()?;
                let child_pid = buffer.read_i32::<NativeEndian>()?;
                let child_tgid = buffer.read_i32::<NativeEndian>()?;
                ProcEvent::Fork {
                    parent_pid,
                    parent_tgid,
                    child_pid,
                    child_tgid,
                }
            }
            ProcEventType::Exec => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                ProcEvent::Exec {
                    process_pid,
                    process_tgid,
                }
            }
            ProcEventType::Uid => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let ruid = buffer.read_u32::<NativeEndian>()?;
                let euid = buffer.read_u32::<NativeEndian>()?;
                ProcEvent::Uid {
                    process_pid,
                    process_tgid,
                    ruid,
                    euid,
                }
            }
            ProcEventType::Gid => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let rgid = buffer.read_u32::<NativeEndian>()?;
                let egid = buffer.read_u32::<NativeEndian>()?;
                ProcEvent::Gid {
                    process_pid,
                    process_tgid,
                    rgid,
                    egid,
                }
            }
            ProcEventType::Sid => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                ProcEvent::Sid {
                    process_pid,
                    process_tgid,
                }
            }
            ProcEventType::Ptrace => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let tracer_pid = buffer.read_i32::<NativeEndian>()?;
                let tracer_tgid = buffer.read_i32::<NativeEndian>()?;
                ProcEvent::Ptrace {
                    process_pid,
                    process_tgid,
                    tracer_pid,
                    tracer_tgid,
                }
            }
            ProcEventType::Comm => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let mut comm = [0u8; 16];
                buffer.read_exact(&mut comm)?;
                ProcEvent::Comm {
                    process_pid,
                    process_tgid,
                    comm,
                }
            }
            ProcEventType::Coredump => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let parent_pid = buffer.read_i32::<NativeEndian>()?;
                let parent_tgid = buffer.read_i32::<NativeEndian>()?;
                ProcEvent::Coredump {
                    process_pid,
                    process_tgid,
                    parent_pid,
                    parent_tgid,
                }
            }
            ProcEventType::Exit | ProcEventType::NonzeroExit => {
                let process_pid = buffer.read_i32::<NativeEndian>()?;
                let process_tgid = buffer.read_i32::<NativeEndian>()?;
                let exit_code = buffer.read_u32::<NativeEndian>()?;
                let exit_signal = buffer.read_u32::<NativeEndian>()?;
                let parent_pid = buffer.read_i32::<NativeEndian>()?;
                let parent_tgid = buffer.read_i32::<NativeEndian>()?;
                ProcEvent::Exit {
                    process_pid,
                    process_tgid,
                    exit_code,
                    exit_signal,
                    parent_pid,
                    parent_tgid,
                }
            }
            ProcEventType::UnrecognizedConst(i) => {
                return Err(DeError::Msg(MsgError::new(format!(
                    "Unrecognized Proc event type: {i} (raw value: {what_val})"
                ))));
            }
        };

        Ok(ProcEventHeader {
            what,
            cpu,
            timestamp_ns,
            event,
        })
    }
}
