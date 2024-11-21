use crate::{
    protocol::{
        Flags, Header, ProtocolComponent, Response, ResponseError, Status, PROTOCOL_BUF_SIZE,
        PROTOCOL_VERSION,
    },
    utils::{copy_stream, open_file, OpenFileOperation},
};
use anyhow::Ok;
use log::{debug, error, info, warn};
use std::{
    io::Read,
    os::unix::net::UnixStream,
    path::Path,
};
use tokio::{
    net::UnixListener,
    signal::unix::SignalKind,
};

fn check_protocol_version(stream: &mut UnixStream, header: &Header) -> anyhow::Result<()> {
    if header.version != PROTOCOL_VERSION {
        Response {
            status: Status::empty().bits(),
            error: ResponseError::VersionMismatch as u32,
            len: 0,
        }
        .to_stream(stream)?;
        warn!("Invalid version");
        return Err(anyhow::anyhow!("Invalid version"));
    }
    Ok(())
}

fn check_token(stream: &mut UnixStream, header: &Header, token: &[u8; 32]) -> anyhow::Result<()> {
    if header.token != *token {
        Response {
            status: Status::empty().bits(),
            error: ResponseError::TokenMismatch as u32,
            len: 0,
        }
        .to_stream(stream)?;
        warn!("Invalid token");
        return Err(anyhow::anyhow!("Invalid token"));
    }
    Ok(())
}

fn check_path_len(stream: &mut UnixStream, header: &Header) -> anyhow::Result<()> {
    if header.path_len == 0 || header.path_len > 1024 {
        Response {
            status: Status::empty().bits(),
            error: ResponseError::PathLengthInvalid as u32,
            len: 0,
        }
        .to_stream(stream)?;
        warn!("Invalid path length");
        return Err(anyhow::anyhow!("Invalid path length"));
    }
    Ok(())
}

fn check_file_recv(
    stream: &mut UnixStream,
    flag: &Flags,
    path: &str,
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    if Path::new(path).exists() {
        if allow_overwrite && flag.has_overwrite() {
            return Ok(());
        }
        Response {
            status: Status::empty().bits(),
            error: ResponseError::FileExists as u32,
            len: 0,
        }
        .to_stream(stream)?;
        warn!("File exists");
        return Err(anyhow::anyhow!("File exists"));
    }
    Ok(())
}

fn check_file_send(stream: &mut UnixStream, path: &str) -> anyhow::Result<()> {
    if !Path::new(path).exists() {
        Response {
            status: Status::empty().bits(),
            error: ResponseError::FileNotFound as u32,
            len: 0,
        }
        .to_stream(stream)?;
        warn!("File not found");
        return Err(anyhow::anyhow!("File not found"));
    }
    Ok(())
}

fn send_continue(stream: &mut UnixStream, data: u64) -> anyhow::Result<()> {
    Response {
        status: Status::CONTINUE.bits(),
        error: 0,
        len: data,
    }
    .to_stream(stream)?;
    debug!("Send continue");
    Ok(())
}

fn recv_main(
    stream: &mut UnixStream,
    path: String,
    flag: Flags,
    data_len: usize,
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    info!("Receiving file");
    check_file_recv(stream, &flag, path.as_str(), allow_overwrite)?;
    send_continue(stream, 0)?;
    let mut fd = open_file(
        path.as_str(),
        if allow_overwrite {
            OpenFileOperation::CreateAllowOverwrite
        } else {
            OpenFileOperation::CreateNotOverwrite
        },
    )?;
    info!("Copying stream data");
    copy_stream(stream, &mut fd, PROTOCOL_BUF_SIZE, data_len)?;
    Ok(())
}

fn send_main(stream: &mut UnixStream, path: String) -> anyhow::Result<()> {
    info!("Sending file");
    check_file_send(stream, path.as_str())?;
    let mut fd = open_file(path.as_str(), OpenFileOperation::ReadOnly)?;
    let file_len = fd.metadata()?.len();
    send_continue(stream, file_len)?;
    info!("Copying stream data");
    copy_stream(&mut fd, stream, PROTOCOL_BUF_SIZE, file_len as usize)?;
    Ok(())
}

fn main(
    stream: tokio::net::UnixStream,
    token: [u8; 32],
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    let mut stream: UnixStream = stream.into_std()?;
    let header = Header::from_stream(&mut stream)?;
    check_protocol_version(&mut stream, &header)?;
    check_token(&mut stream, &header, &token)?;
    check_path_len(&mut stream, &header)?;

    let mut path_buf = vec![0; header.path_len as usize];
    stream.read_exact(&mut path_buf)?;
    let path = String::from_utf8(path_buf)?;
    debug!("Requested path: {}", path);

    let flag = Flags::from_bits_truncate(header.flag);
    if let Err(e) = if flag.has_receive() {
        recv_main(
            &mut stream,
            path,
            flag,
            header.data_len as usize,
            allow_overwrite,
        )
    } else {
        send_main(&mut stream, path)
    } {
        error!("Error while transfer file: {:?}", e);
        Err(e)
    } else {
        info!("Transfer completed");
        Ok(())
    }
}

fn handle(
    r: (tokio::net::UnixStream, tokio::net::unix::SocketAddr),
    token: [u8; 32],
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    let (stream, addr) = r;
    info!("Accepted connection from: {:?}", addr);
    tokio::spawn(async move {
        if let Err(e) = main(stream, token, allow_overwrite) {
            error!("Error while processing request: {:?}", e);
        }
    });
    Ok(())
}

pub(crate) async fn daemon_main(
    listen: String,
    token: [u8; 32],
    allow_overwrite: bool,
) -> anyhow::Result<()> {
    debug!("Setting up daemon");
    let sock = UnixListener::bind(listen)?;
    let mut signals = tokio::signal::unix::signal(SignalKind::interrupt())?;
    let mut running = true;
    info!("Running as daemon");
    while running {
        tokio::select! {
            _ = signals.recv() => {
                info!("Received signal, exiting");
                running = false;
            }
            r  =  sock.accept() => {
                handle(r?,token,allow_overwrite)?;
            }
        }
    }
    Ok(())
}
