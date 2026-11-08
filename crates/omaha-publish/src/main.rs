//! The `omaha-publish` command: packs directories into signed CRXs and
//! publishes them, with patches and a signed index, to a feed in object
//! storage.

use clap::{Args, Parser, Subcommand};
use object_store::ObjectStore;
use object_store::local::LocalFileSystem;
use object_store::prefix::PrefixStore;
use omaha_diff::Differ;
use omaha_protocol::Version;
use omaha_publish::Store;
use omaha_publish::archive::{self, Compression};
use omaha_publish::release::{Options, Policy};
use omaha_server::index::aws_lc::{EcdsaKey, EcdsaSigner};
use omaha_server::index::{Requirements, Signer, Verifier};
use std::error::Error;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Publish signed CRX feeds for Chromium's update protocol.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an ECDSA P-256 index signing key (PKCS#8 PEM) and print its
    /// public key.
    Keygen { out: PathBuf },
    /// Print the public key (SPKI PEM) of an index signing key.
    PublicKey { key: PathBuf },
    /// Pack a directory into a signed CRX.
    Pack {
        /// The CRX signing key, RSA or ECDSA P-256 (PKCS#8 PEM). Its hash is
        /// the app ID.
        #[arg(long)]
        key: PathBuf,
        /// Store entries uncompressed.
        #[arg(long)]
        stored: bool,
        dir: PathBuf,
        out: PathBuf,
    },
    /// Print the app ID and key hash a CRX signing key (PKCS#8 PEM) gives.
    Id { key: PathBuf },
    /// Verify a CRX's proofs the way Chromium does, and optionally that it
    /// packs exactly the files in a directory.
    Verify {
        /// Also require a proof by the key with this SHA-256 (hex). Repeat
        /// to require several.
        #[arg(long)]
        key_hash: Vec<String>,
        /// Rebuild the archive from this directory and require the CRX's to
        /// be identical, as `pack` would make it.
        #[arg(long)]
        files: Option<PathBuf>,
        /// The archive was packed with `--stored`.
        #[arg(long)]
        stored: bool,
        crx: PathBuf,
    },
    /// Add a CRX to a feed: upload it, patches to it, and a new index.
    Publish {
        #[command(flatten)]
        feed: Feed,
        /// Make puffin patches with this binary.
        #[arg(long)]
        puffin: Option<PathBuf>,
        /// Make zucchini patches with this binary.
        #[arg(long)]
        zucchini: Option<PathBuf>,
        /// Offer the release only to browsers at least this version.
        #[arg(long)]
        prodversionmin: Option<Version>,
        /// Offer the release only on these operating systems.
        #[arg(long)]
        os: Vec<String>,
        /// Offer the release only to these browser architectures.
        #[arg(long)]
        arch: Vec<String>,
        /// Releases to keep per app.
        #[arg(long, default_value_t = 5)]
        keep: usize,
        /// Earlier releases to make patches from.
        #[arg(long, default_value_t = 3)]
        patch_from: usize,
        crx: PathBuf,
    },
    /// Re-sign the index with a new expiry, so it doesn't expire.
    Refresh {
        #[command(flatten)]
        feed: Feed,
    },
    /// Print the current index.
    Show {
        #[command(flatten)]
        feed: Feed,
    },
}

#[derive(Args)]
struct Feed {
    /// Where the feed lives: `file:///path` or `s3://bucket/prefix`. S3 is
    /// configured through the usual `AWS_*` variables, e.g.
    /// `AWS_ENDPOINT` for R2.
    #[arg(long)]
    store: String,
    /// The index's path in the store.
    #[arg(long, default_value = "index.json")]
    index: String,
    /// The index signing key (PKCS#8 PEM).
    #[arg(long)]
    key: PathBuf,
    /// Also accept indexes signed by this public key (SPKI PEM), e.g. a
    /// previous key.
    #[arg(long)]
    trust: Vec<PathBuf>,
    /// Days a newly signed index stays valid.
    #[arg(long, default_value_t = 14)]
    lifetime_days: u64,
}

struct Opened {
    store: Store,
    signer: EcdsaSigner,
    trusted: Vec<EcdsaKey>,
    policy: Policy,
}

impl Opened {
    fn trusted(&self) -> Vec<&dyn Verifier> {
        self.trusted.iter().map(|k| k as &dyn Verifier).collect()
    }
}

impl Feed {
    fn open(&self) -> Result<Opened> {
        let signer = EcdsaSigner::from_pkcs8(&read_pem(&self.key, "PRIVATE KEY")?)?;
        let mut trusted = vec![EcdsaKey::from_spki(signer.public_key())?];

        for path in &self.trust {
            trusted.push(EcdsaKey::from_spki(&read_pem(path, "PUBLIC KEY")?)?);
        }

        let policy = Policy {
            lifetime: Duration::from_secs(self.lifetime_days.saturating_mul(86400)),
            ..Policy::default()
        };
        Ok(Opened {
            store: Store::new(object_store(&self.store)?, &self.index)?,
            signer,
            trusted,
            policy,
        })
    }
}

fn object_store(url: &str) -> Result<Arc<dyn ObjectStore>> {
    if let Some(path) = url.strip_prefix("file://") {
        std::fs::create_dir_all(path)?;
        return Ok(Arc::new(LocalFileSystem::new_with_prefix(path)?));
    }

    #[cfg(feature = "s3")]
    if let Some(rest) = url.strip_prefix("s3://") {
        use object_store::aws::{AmazonS3Builder, S3ConditionalPut};

        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let s3 = AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .build()?;
        let prefix = prefix.trim_end_matches('/');

        if prefix.is_empty() {
            return Ok(Arc::new(s3));
        }

        return Ok(Arc::new(PrefixStore::new(s3, prefix)));
    }

    Err(format!("unsupported store {url:?}").into())
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

fn write_pem(label: &str, der: &[u8]) -> Result<String> {
    Ok(pem_rfc7468::encode_string(
        label,
        pem_rfc7468::LineEnding::LF,
        der,
    )?)
}

fn compression(stored: bool) -> Compression {
    if stored {
        Compression::Stored
    } else {
        Compression::Deflated
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn crx_signer(path: &Path) -> Result<Box<dyn crx3::Signer>> {
    let der = read_pem(path, "PRIVATE KEY")?;

    if let Ok(rsa) = crx3::aws_lc::RsaSigner::from_pkcs8(&der) {
        return Ok(Box::new(rsa));
    }

    Ok(Box::new(crx3::aws_lc::EcdsaSigner::from_pkcs8(&der)?))
}

fn create_private(path: &Path, contents: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

    options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .write_all(contents.as_bytes())?;
    Ok(())
}

async fn run(command: Command) -> Result<()> {
    match command {
        Command::Keygen { out } => {
            let key = EcdsaSigner::generate()?;
            create_private(&out, &write_pem("PRIVATE KEY", &key.to_pkcs8()?)?)?;
            print!("{}", write_pem("PUBLIC KEY", key.public_key())?);
        }
        Command::PublicKey { key } => {
            let key = EcdsaSigner::from_pkcs8(&read_pem(&key, "PRIVATE KEY")?)?;
            print!("{}", write_pem("PUBLIC KEY", key.public_key())?);
        }
        Command::Id { key } => {
            let signer = crx_signer(&key)?;
            let spki = signer.public_key();
            println!("app ID: {}", crx3::id_from_public_key(spki));
            println!("key SHA-256: {}", hex(crx3::key_hash(spki).as_bytes()));
        }
        Command::Verify {
            key_hash,
            files,
            stored,
            crx,
        } => {
            let bytes = std::fs::read(&crx).map_err(|e| format!("{}: {e}", crx.display()))?;
            let required = key_hash
                .iter()
                .map(|h| {
                    h.parse::<omaha_protocol::Sha256>()
                        .map(|h| crx3::KeyHash::from_bytes(*h.as_bytes()))
                        .map_err(|_| format!("--key-hash {h}: expected 64 hex digits"))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let policy = crx3::Policy {
                required_keys: &required,
                any_of: &[],
            };
            let verified = crx3::verify(&bytes, &policy)?;

            if let Some(dir) = &files {
                let files = archive::read_dir(dir)?;
                let rebuilt = archive::archive(
                    files.iter().map(|(p, d)| (p.as_str(), d.as_slice())),
                    compression(stored),
                )?;

                if crx3::split(&bytes)?.archive != rebuilt.as_slice() {
                    return Err(format!(
                        "{}: the archive differs from what {} packs to",
                        crx.display(),
                        dir.display()
                    )
                    .into());
                }

                println!("{} ok, archive matches", verified.id);
            } else {
                println!("{} ok", verified.id);
            }
        }
        Command::Pack {
            key,
            stored,
            dir,
            out,
        } => {
            let files = archive::read_dir(&dir)?;
            let zip = archive::archive(
                files.iter().map(|(p, d)| (p.as_str(), d.as_slice())),
                compression(stored),
            )?;
            let signer = crx_signer(&key)?;
            let crx = crx3::Builder::new().signer(signer.as_ref()).build(&zip)?;
            std::fs::write(&out, &crx)?;
            let verified = crx3::verify(&crx, &crx3::Policy::default())?;
            println!("{} {} bytes", verified.id, crx.len());
        }
        Command::Publish {
            feed,
            puffin,
            zucchini,
            prodversionmin,
            os,
            arch,
            keep,
            patch_from,
            crx,
        } => {
            let mut opened = feed.open()?;
            opened.policy.keep = keep;
            opened.policy.patch_from = patch_from;
            let differs: Vec<Differ> = puffin
                .map(Differ::puffin)
                .into_iter()
                .chain(zucchini.map(Differ::zucchini))
                .collect();
            let options = Options {
                requires: Requirements {
                    prodversionmin,
                    os,
                    arch,
                },
                ..Options::default()
            };
            let crx = std::fs::read(&crx).map_err(|e| format!("{}: {e}", crx.display()))?;
            let plan = opened
                .store
                .publish(
                    crx,
                    options,
                    &[&opened.signer],
                    &opened.trusted(),
                    &differs,
                    &opened.policy,
                    SystemTime::now(),
                )
                .await?;

            for upload in &plan.uploads {
                println!("uploaded {} ({} bytes)", upload.path, upload.bytes.len());
            }

            println!("index serial {}", plan.index.serial);
        }
        Command::Refresh { feed } => {
            let opened = feed.open()?;
            let index = opened
                .store
                .refresh(
                    &[&opened.signer],
                    &opened.trusted(),
                    &opened.policy,
                    SystemTime::now(),
                )
                .await?;
            println!("index serial {}, expires {}", index.serial, index.expires);
        }
        Command::Show { feed } => {
            let opened = feed.open()?;
            let current = opened
                .store
                .current(&opened.trusted())
                .await?
                .ok_or("no index yet")?;
            std::io::stdout().write_all(&current.index.to_json()?)?;
            println!();
        }
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("omaha-publish: {e}");
            ExitCode::FAILURE
        }
    }
}
