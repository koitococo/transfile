use std::{io::Write, os::unix::net::UnixStream};

use log::{debug, error, info};

use crate::{
    protocol::{
        Flags, Header, ProtocolComponent, Response, Status, PROTOCOL_BUF_SIZE, PROTOCOL_VERSION,
    },
    utils::{copy_stream, open_file, OpenFileOperation},
};

pub(crate) fn recv_main(
    listen: String,
    token: [u8; 32],
    local_file: String,
    remote_file: String,
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    info!("Receive file from remote");

    let mut fd = open_file(
        local_file.as_str(),
        if allow_overwrite {
            OpenFileOperation::CreateAllowOverwrite
        } else {
            OpenFileOperation::CreateNotOverwrite
        },
    )?;

    let remote_path_buf = remote_file.as_bytes();
    let header = Header {
        version: PROTOCOL_VERSION,
        flag: Flags::empty().bits(),
        token,
        path_len: remote_file.len() as u32,
        data_len: 0,
        reserved_1: 0,
    };

    let mut stream = UnixStream::connect(listen.clone())?;
    debug!("Connected to: {}", listen);
    header.to_stream(&mut stream)?;
    stream.write_all(remote_path_buf)?;
    debug!("Remote path sent: {}", remote_file);

    let response = Response::from_stream(&mut stream)?;
    let status = Status::from_bits_truncate(response.status);
    if !status.is_ok() {
        error!("Got status: {:?}", response.status);
        return Err(anyhow::anyhow!("Error"));
    }
    info!("Got file size: {}", response.len);
    copy_stream(
        &mut stream,
        &mut fd,
        PROTOCOL_BUF_SIZE,
        response.len as usize,
    )?;
    fd.flush()?;
    info!("File received");
    Ok(())
}

pub(crate) fn send_main(
    listen: String,
    token: [u8; 32],
    local_file: String,
    remote_file: String,
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    let mut fd = open_file(
        local_file.as_str(),
        crate::utils::OpenFileOperation::ReadOnly,
    )?;
    let file_len = fd.metadata()?.len() as usize;
    let remote_path_buf = remote_file.as_bytes();
    let header = Header {
        version: PROTOCOL_VERSION,
        flag: (if allow_overwrite {
            Flags::OVERWRITE | Flags::RECEIVE
        } else {
            Flags::RECEIVE
        })
        .bits(),
        token,
        path_len: remote_file.len() as u32,
        data_len: file_len as u64,
        reserved_1: 0,
    };

    let mut stream = UnixStream::connect(listen.clone())?;
    header.to_stream(&mut stream)?;
    stream.write_all(remote_path_buf)?;
    let response = Response::from_stream(&mut stream)?;
    let status = Status::from_bits_truncate(response.status);
    if !status.is_ok() {
        return Err(anyhow::anyhow!("Error"));
    }
    copy_stream(&mut fd, &mut stream, PROTOCOL_BUF_SIZE, file_len)?;
    Ok(())
}
