mod cli;
mod client;
mod daemon;
mod protocol;
mod utils;

use clap::Parser;
use log::debug;

use crate::cli::{Args, SubCommand};
use crate::client::{recv_main, send_main};
use crate::utils::to_hex_string;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    let args = Args::parse();
    debug!("Run with args: {:?}", args);
    let listen = args.listen.unwrap_or("/tmp/transfile.sock".to_string());
    debug!("Listen on: {}", listen);
    let token = utils::str_to_sha256(args.token.unwrap_or_default().as_str());
    debug!("Token: {:?}", to_hex_string(&token));

    match args.subcommand {
        SubCommand::Daemon => daemon::daemon_main(listen, token, args.allow_overwrite).await,
        SubCommand::Push {
            local_file,
            remote_file,
        } => send_main(listen, token, local_file, remote_file, args.allow_overwrite),
        SubCommand::Pull {
            remote_file,
            local_file,
        } => recv_main(listen, token, local_file, remote_file, args.allow_overwrite),
    }
}
