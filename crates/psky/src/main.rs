//! Command-line entry point for read-only preflight and offline experiments.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};
use psky::{lab, server};
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
    /// Run the localhost console and a public API with production writes disabled.
    Serve {
        /// Loopback address for the management console.
        #[arg(long, default_value = "127.0.0.1:8788")]
        admin_bind: SocketAddr,
        /// Separate public API address. Loopback is the development default.
        #[arg(long, default_value = "127.0.0.1:8787")]
        public_bind: SocketAddr,
        /// Local operator token and disposable experiment outputs.
        #[arg(long, default_value = "tmp/psky")]
        data_dir: PathBuf,
        /// Explicitly serve the offline fixture CAR at getRepo.
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
        Command::Serve {
            admin_bind,
            public_bind,
            data_dir,
            serve_fixture,
            peers,
        } => {
            ensure!(
                admin_bind.ip().is_loopback(),
                "admin listener must bind loopback"
            );
            let preflight = if peers.endpoint.is_empty() {
                None
            } else {
                Some(peers.config()?)
            };
            // Bind both before creating local state, so a port conflict fails early.
            let admin = tokio::net::TcpListener::bind(admin_bind).await?;
            let public = tokio::net::TcpListener::bind(public_bind).await?;
            let token = server::load_admin_token(&data_dir)?;
            let admin_addr = admin.local_addr()?;
            let public_addr = public.local_addr()?;
            let state = server::ConsoleState::new(server::ConsoleConfig {
                admin_addr,
                data_dir: data_dir.clone(),
                token,
                preflight,
            })?;
            eprintln!("Console: http://{admin_addr}");
            eprintln!(
                "Admin token file: {}",
                data_dir.join("admin.token").display()
            );
            eprintln!("Public API: http://{public_addr} (production PDS unavailable)");
            if serve_fixture {
                eprintln!("Offline fixture CAR enabled; no network-backed repositories");
            }
            tokio::try_join!(
                axum::serve(admin, server::admin_router(state)).with_graceful_shutdown(shutdown()),
                axum::serve(public, server::public_router(serve_fixture))
                    .with_graceful_shutdown(shutdown()),
            )?;
        }
    }
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install termination handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
