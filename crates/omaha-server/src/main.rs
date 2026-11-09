//! `omaha-server`: answers update checks from a signed release index.

use clap::{Args, Parser, Subcommand};
use hyper_util::service::TowerToHyperService;
use object_store::path::Path as StorePath;
use object_store::{ObjectStore, ObjectStoreExt};
use omaha_server::index::MAX_ENVELOPE_LEN;
use omaha_server::index::aws_lc::EcdsaKey;
use omaha_server::{Endpoint, Replaced, ServeOptions, StaticIndex};
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use tokio::net::TcpListener;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Serve Chromium's update protocols from a signed release index.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Answer Omaha 4 and update2 requests on every path, from the index
    /// at `--index`, reloaded on a timer.
    Serve(ServeArgs),
}

#[derive(Args)]
struct ServeArgs {
    /// The signed index: `https://…/index.json`, `s3://bucket/…/index.json`
    /// (configured through the usual `AWS_*` variables) or
    /// `file:///…/index.json`.
    #[arg(long)]
    index: String,
    /// A public key (SPKI PEM) the index must be signed by. Repeat to
    /// accept several.
    #[arg(long, required = true)]
    trust: Vec<PathBuf>,
    /// Where clients download files from, tried in order. Defaults to the
    /// index's directory when `--index` is an HTTP(S) URL.
    #[arg(long)]
    base: Vec<String>,
    /// Sign responses with this CUP key: `<version>=<key.pem>`, an
    /// ML-DSA-44 or ECDSA P-256 PKCS#8 key. Repeat for several.
    #[arg(long)]
    cup_key: Vec<String>,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Connections served at once; more wait to be accepted.
    #[arg(long, default_value_t = 512)]
    max_connections: usize,
    /// Seconds between index reloads.
    #[arg(long, default_value_t = 300)]
    reload: u64,
    /// The `server` value in responses.
    #[arg(long)]
    server_name: Option<String>,
    /// Serve Prometheus metrics on this address, e.g. 127.0.0.1:9100.
    #[arg(long)]
    metrics: Option<SocketAddr>,
    /// Count daily roll calls and active reports from the dates clients
    /// send, without identifying them.
    #[arg(long)]
    count_activity: bool,
}

fn read_pem(path: &Path, label: &str) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (found, der) =
        pem_rfc7468::decode_vec(text.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;

    if found != label {
        return Err(format!("{}: expected {label}, found {found}", path.display()).into());
    }

    Ok(der)
}

fn cup_server(keys: &[String]) -> Result<Option<cup2::Server>> {
    if keys.is_empty() {
        return Ok(None);
    }

    let mut server = cup2::Server::new();

    for key in keys {
        let (version, path) = key
            .split_once('=')
            .ok_or_else(|| format!("--cup-key {key}: expected <version>=<key.pem>"))?;
        let version: u32 = version
            .parse()
            .map_err(|_| format!("--cup-key {key}: invalid version"))?;
        let der = read_pem(Path::new(path), "PRIVATE KEY")?;
        server = server.with(
            cup2::aws_lc::AnySigner::from_pkcs8(version, &der)
                .map_err(|e| format!("--cup-key {key}: {e}"))?,
        );
    }

    Ok(Some(server))
}

fn open(index: &str) -> Result<(Box<dyn ObjectStore>, StorePath)> {
    let url = url::Url::parse(index).map_err(|e| format!("--index {index}: {e}"))?;
    let options = std::env::vars().filter(|(key, _)| key.starts_with("AWS_"));
    Ok(object_store::parse_url_opts(&url, options)?)
}

/// The index's directory, without credentials, query or fragment, when
/// it's an HTTP(S) URL.
fn default_bases(index: &str) -> Vec<String> {
    let Ok(mut url) = url::Url::parse(index) else {
        return Vec::new();
    };

    if !matches!(url.scheme(), "http" | "https") {
        return Vec::new();
    }

    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);

    match url.as_str().rsplit_once('/') {
        Some((dir, _)) => vec![format!("{dir}/")],
        None => Vec::new(),
    }
}

async fn reload(store: &dyn ObjectStore, path: &StorePath, index: &StaticIndex, url: &str) {
    let bytes = match store.get(path).await {
        Ok(result) if result.meta.size > MAX_ENVELOPE_LEN => Err(format!(
            "{} bytes is too large for an index",
            result.meta.size
        )),
        Ok(result) => result.bytes().await.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };

    match bytes.and_then(|b| index.replace(&b).map_err(|e| e.to_string())) {
        Ok(Replaced::Loaded { serial }) => {
            eprintln!("loaded index serial {serial}");
            metrics::gauge!("omaha_index_serial").set(serial as f64);

            if let Some(loaded) = index.current() {
                metrics::gauge!("omaha_index_expires_timestamp_seconds").set(loaded.expires as f64);
            }
        }
        Ok(Replaced::Unchanged) => {}
        Err(e) => {
            eprintln!("{url}: {e}");
            metrics::counter!("omaha_index_reload_failures_total").increment(1);
        }
    }

    if index.is_stale() {
        eprintln!("{url}: the loaded index has expired; serving it until a newer one loads");
    }
}

async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }

    let _ = tokio::signal::ctrl_c().await;
}

fn install_metrics(addr: SocketAddr) -> Result<()> {
    use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets_for_metric(
            Matcher::Full("omaha_request_duration_seconds".into()),
            &[
                0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0,
            ],
        )?
        .install()?;
    eprintln!("metrics on {addr}");
    Ok(())
}

async fn serve(args: ServeArgs) -> Result<()> {
    let ServeArgs {
        index,
        trust,
        base,
        cup_key,
        listen,
        max_connections,
        reload: reload_secs,
        server_name,
        metrics: metrics_addr,
        count_activity,
    } = args;
    let bases = if base.is_empty() {
        default_bases(&index)
    } else {
        base
    };

    if bases.is_empty() {
        return Err("--base is required unless --index is an HTTP(S) URL".into());
    }

    let mut builder = StaticIndex::builder(bases);

    for path in &trust {
        builder = builder.trust(EcdsaKey::from_spki(&read_pem(path, "PUBLIC KEY")?)?);
    }

    if let Some(addr) = metrics_addr {
        install_metrics(addr)?;
    }

    let source = builder.build();
    let mut endpoint = Endpoint::builder()
        .fallback(source.clone())
        .count_activity(count_activity);

    if let Some(cup) = cup_server(&cup_key)? {
        endpoint = endpoint.cup(cup);
    }

    if let Some(name) = server_name {
        endpoint = endpoint.server_name(name);
    }

    let endpoint = endpoint.build();
    let (store, path) = open(&index)?;
    reload(store.as_ref(), &path, &source, &index).await;

    let reloader = source.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(reload_secs.max(1)));
        interval.tick().await;

        loop {
            interval.tick().await;
            reload(store.as_ref(), &path, &reloader, &index).await;
        }
    });

    let listener = TcpListener::bind(listen).await?;
    eprintln!("listening on {}", listener.local_addr()?);
    let options = ServeOptions::default()
        .max_connections(max_connections)
        .connection_timeout(Some(CONNECTION_TIMEOUT));
    omaha_server::serve(
        listener,
        TowerToHyperService::new(endpoint),
        options,
        shutdown(),
    )
    .await;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("omaha-server: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_the_index_directory_over_http() {
        assert_eq!(
            default_bases("https://crls.example/feed/standard/index.json"),
            ["https://crls.example/feed/standard/"]
        );
        assert_eq!(
            default_bases("https://user:token@crls.example/feed/index.json?sig=a/b#x"),
            ["https://crls.example/feed/"]
        );
        assert!(default_bases("s3://bucket/feed/index.json").is_empty());
        assert!(default_bases("file:///srv/feed/index.json").is_empty());
    }
}
