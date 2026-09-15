//! Command-line entry point for read-only preflight and offline experiments.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use psky::{
    lab, server,
    settings::{ConfigStore, Settings},
};
use psky_hypersnap::{Network, PreflightClient, PreflightConfig};

#[derive(Parser)]
#[command(
    version,
    about = "PurpleSky: Hypersnap preflight and offline ATProto reconstruction"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read node information and optional public FID state. Never sends writes.
    Preflight(Peers),
    /// Reconstruct two revisions on two independent fixture workers.
    Lab {
        /// New output directory. Parent must exist; existing paths are rejected.
        #[arg(long)]
        output: PathBuf,
    },
    /// Print an existing local console token for the operator. Keep it private.
    AdminToken {
        /// Existing node data directory. This command never initializes a node.
        #[arg(long, default_value = "tmp/psky")]
        data_dir: PathBuf,
    },
    /// Run the localhost console and a public API with production writes disabled.
    Serve {
        /// Initial loopback address. Saved console settings win on later starts.
        #[arg(long, default_value = "127.0.0.1:8788")]
        admin_bind: SocketAddr,
        /// Initial public API address. Saved console settings win on later starts.
        #[arg(long, default_value = "127.0.0.1:8787")]
        public_bind: SocketAddr,
        /// Local settings, operator token, and disposable experiment outputs.
        #[arg(long, default_value = "tmp/psky")]
        data_dir: PathBuf,
        /// Initially enable fixture CAR export. Editable in the console later.
        #[arg(long)]
        serve_fixture: bool,
        #[command(flatten)]
        peers: Peers,
    },
}

#[derive(Args)]
struct Peers {
    /// Hypersnap URL; repeat for every node. HTTPS except HTTP loopback fixtures.
    #[arg(long)]
    endpoint: Vec<String>,
    /// Expected Farcaster network (mainnet, testnet, devnet).
    #[arg(long, default_value = "mainnet")]
    network: Network,
    /// Optional FID for public message-network and storage checks.
    #[arg(long)]
    fid: Option<u64>,
}

impl Peers {
    fn config(self) -> Result<PreflightConfig> {
        Ok(PreflightConfig::new(self.endpoint, self.network, self.fid)?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Preflight(peers) => {
            let report = PreflightClient::new(peers.config()?)?.run().await;
            println!("{}", serde_json::to_string_pretty(&report)?);
            // Success means compatible observed responses, never storage proof.
            if !report.compatible {
                std::process::exit(2);
            }
        }
        Command::Lab { output } => {
            println!("{}", serde_json::to_string_pretty(&lab::run(&output)?)?);
        }
        Command::AdminToken { data_dir } => println!("{}", server::read_admin_token(&data_dir)?),
        Command::Serve {
            admin_bind,
            public_bind,
            data_dir,
            serve_fixture,
            peers,
        } => {
            let initial = Settings {
                admin_bind,
                public_bind,
                serve_fixture,
                endpoints: peers.endpoint,
                network: peers.network,
                test_fid: peers.fid,
                ..Settings::default()
            };
            let store = ConfigStore::open(&data_dir, initial)?;
            let saved = store.snapshot().settings;
            let admin = tokio::net::TcpListener::bind(saved.admin_bind).await?;
            let public = tokio::net::TcpListener::bind(saved.public_bind).await?;
            let token = server::load_admin_token(&data_dir)?;
            let admin_addr = admin.local_addr()?;
            let public_addr = public.local_addr()?;
            let state = server::ConsoleState::new(server::ConsoleConfig {
                admin_addr,
                public_addr,
                data_dir: data_dir.clone(),
                token,
                store,
            })?;
            eprintln!("Console: http://{admin_addr}");
            eprintln!(
                "Admin token file: {}",
                data_dir.join("admin.token").display()
            );
            eprintln!("Public API: http://{public_addr} (production PDS unavailable)");
            if saved.serve_fixture {
                eprintln!("Offline fixture CAR enabled; no network-backed repositories");
            }
            tokio::try_join!(
                axum::serve(admin, server::admin_router(state.clone()))
                    .with_graceful_shutdown(shutdown(state.clone())),
                axum::serve(public, server::public_router(state.clone()))
                    .with_graceful_shutdown(shutdown(state)),
            )?;
        }
    }
    Ok(())
}

async fn shutdown(state: std::sync::Arc<server::ConsoleState>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install termination handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    state.drain().await;
}
