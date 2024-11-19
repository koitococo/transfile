use clap::Parser;

#[derive(Parser, Debug)]
pub(crate) enum SubCommand {
    #[command(name = "daemon", about = "Run the local daemon")]
    Daemon,

    #[command(name = "push", about = "Push a file to daemon")]
    Push {
        /// local file to push
        #[arg(name = "local_file")]
        local_file: String,

        /// remote path to save file
        #[arg(name = "remote_file")]
        remote_file: String,
    },

    #[command(name = "pull", about = "Pull a file from daemon")]
    Pull {
        /// remote file to pull
        #[arg(name = "remote_file")]
        remote_file: String,

        /// local path to save the file
        #[arg(name = "local_file")]
        local_file: String,
    },
}

#[derive(Parser, Debug)]
#[command(name = "transfile", version = "0.1")]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) subcommand: SubCommand,

    /// The local unix socket to listen on or connect to
    #[arg(short, long, env = "TRANSFILE_LISTEN")]
    pub(crate) listen: Option<String>,

    /// The token to use for authentication
    #[arg(short, long, env = "TRANSFILE_TOKEN")]
    pub(crate) token: Option<String>,

    /// Whether to allow overwriting files
    #[arg(short, long, env = "TRANSFILE_ALLOW_OVERWRITE")]
    pub(crate) allow_overwrite: bool,
}