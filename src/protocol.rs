use bitflags::bitflags;
use std::io::{Read, Write};
use zerocopy::{
    AlignmentError, ConvertError, Immutable, IntoBytes, KnownLayout, SizeError, TryFromBytes,
    ValidityError,
};

pub trait ProtocolComponent {
    fn from_stream(stream: &mut impl Read) -> anyhow::Result<Self>
    where
        Self: Sized;
    fn to_stream(&self, stream: &mut impl Write) -> anyhow::Result<usize>;
}

fn _from_stream_generic<'a, T>(stream: &mut impl Read, buf: &mut [u8]) -> anyhow::Result<T>
where
    T: Copy + TryFromBytes + KnownLayout,
{
    stream.read_exact(buf)?;

    let header: Result<
        &mut T,
        ConvertError<
            AlignmentError<&mut [u8], T>,
            SizeError<&mut [u8], T>,
            ValidityError<&mut [u8], T>,
        >,
    > = T::try_mut_from_bytes(buf);
    if let Err(e) = header {
        return Err(anyhow::anyhow!(format!("Error reading header: {:?}", e)));
    }
    let header = header.unwrap();
    Ok(*header)
}

fn _to_stream_generic<T: Clone + IntoBytes + Immutable>(
    data: &T,
    stream: &mut impl Write,
) -> anyhow::Result<usize> {
    let buf = data.clone();
    let buf = buf.as_bytes();
    stream.write_all(buf)?;
    Ok(buf.len())
}

macro_rules! impl_protocol_component {
    ($type:ty, $buf_size:expr) => {
        impl ProtocolComponent for $type {
            fn from_stream(stream: &mut impl Read) -> anyhow::Result<Self> {
                _from_stream_generic::<$type>(stream, &mut [0u8; $buf_size])
            }

            fn to_stream(&self, stream: &mut impl Write) -> anyhow::Result<usize> {
                _to_stream_generic(self, stream)
            }
        }
    };
}

pub const PROTOCOL_VERSION: u32 = 0x0d000001;
pub const PROTOCOL_BUF_SIZE: usize = 1024 * 1024; // 1MB

bitflags! {
    pub struct Flags:u32 {
        const OVERWRITE = 1 << 31;
        const RECEIVE = 1 << 0;
    }
}

impl Flags {
    pub fn has_overwrite(&self) -> bool {
        self.contains(Self::OVERWRITE)
    }

    pub fn has_receive(&self) -> bool {
        self.contains(Self::RECEIVE)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, TryFromBytes, IntoBytes, Immutable)]
pub struct Header {
    pub version: u32,    // 0 .. 4
    pub token: [u8; 32], // 4 .. 36
    pub flag: u32,       // 36 .. 40
    pub reserved_1: u32, // 40 .. 44
    pub path_len: u32,   // 44 .. 48
    pub data_len: u64,   // 48 .. 56
}
impl_protocol_component!(Header, 56);

bitflags! {
    pub struct Status:u32 {
        const CONTINUE = 1 << 1;
        const OK = 1;
    }
}

#[repr(u32)]
pub enum ResponseError {
    _Undefined = 0,
    VersionMismatch = 0x0001_0001,
    TokenMismatch = 0x0001_0002,
    PathLengthInvalid = 0x0002_0001,
    FileExists = 0x0003_0001,
    FileNotFound = 0x0003_0002,
}

impl Status {
    pub fn is_ok(&self) -> bool {
        self.contains(Self::OK) || self.contains(Self::CONTINUE)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, TryFromBytes, IntoBytes, Immutable)]
pub struct Response {
    pub status: u32,
    pub error: u32,
    pub len: u64,
}
impl_protocol_component!(Response, 16);
