use std::fs::{File, OpenOptions};

use log::trace;
use sha2::{Digest, Sha256};

pub fn str_to_sha256(s: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

pub fn copy_stream(
    src: &mut impl std::io::Read,
    dst: &mut impl std::io::Write,
    buf_size: usize,
    expected_size: usize,
) -> anyhow::Result<usize> {
    trace!(
        "copy_stream: buf_size: {}, expected_size: {}",
        buf_size,
        expected_size
    );
    let mut buf = vec![0u8; buf_size];
    let mut recv = 0 as usize;
    loop {
        if expected_size - recv <= 0 {
            trace!("copy_stream: Done");
            break;
        }
        let n = src.read(&mut buf)?;
        trace!("copy_stream: Read {} bytes", n);
        if n == 0 {
            trace!("copy_stream: EOF reached");
            break;
        }
        dst.write_all(&buf[..n])?;
        recv += n;
    }
    Ok(recv)
}

pub fn to_hex_string(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
}

#[derive(Debug)]
pub enum OpenFileOperation {
    ReadOnly,
    CreateAllowOverwrite,
    CreateNotOverwrite,
}

pub fn open_file(path: &str, op: OpenFileOperation) -> anyhow::Result<File> {
    trace!("open_file: path: {}, op: {:?}", path, op);
    match op {
        OpenFileOperation::ReadOnly => Ok(OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .create_new(false)
            .truncate(false)
            .open(path)?),
        OpenFileOperation::CreateAllowOverwrite => Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .create_new(false)
            .truncate(true)
            .open(path)?),
        OpenFileOperation::CreateNotOverwrite => Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .create_new(true)
            .truncate(false)
            .open(path)?),
    }
}
