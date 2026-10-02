use std::process::ExitCode;
use std::sync::Arc;

use log::{info, LevelFilter};
use marksocks::Config;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};

const DEFAULT_CONFIG: &str = "/etc/marksocks/config.toml";
const USAGE: &str = "\
usage: marksocks [--config <path>] [--check]

  --config <path>  TOML config file (default: /etc/marksocks/config.toml)
  --check          validate the config file, print `config ok` and exit
  -h, --help       print this help
  -V, --version    print the version";

#[derive(Debug, PartialEq)]
enum Cli {
    Run { config: String, check: bool },
    Help,
    Version,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let mut config = DEFAULT_CONFIG.to_string();
    let mut check = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = args.next().ok_or("--config needs a path")?,
            "--check" => check = true,
            "-h" | "--help" => return Ok(Cli::Help),
            "-V" | "--version" => return Ok(Cli::Version),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(Cli::Run { config, check })
}

fn main() -> ExitCode {
    let (path, check) = match parse_args(std::env::args().skip(1)) {
        Ok(Cli::Run { config, check }) => (config, check),
        Ok(Cli::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Version) => {
            println!("marksocks {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("marksocks: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // Fatal startup errors go to stderr directly, not through the (possibly off) logger.
    let cfg = match std::fs::read_to_string(&path) {
        Ok(text) => Config::from_toml(&text).map_err(|e| format!("{path}: {e}")),
        Err(e) => Err(format!("reading {path}: {e}")),
    };
    let cfg = match cfg {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("marksocks: {e}");
            return ExitCode::from(2);
        }
    };
    if check {
        println!("config ok");
        return ExitCode::SUCCESS;
    }

    init_logger(cfg.log_level);
    let result = tokio::runtime::Runtime::new()
        .map_err(|e| format!("starting runtime: {e}"))
        .and_then(|rt| rt.block_on(run(cfg)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("marksocks: {e}");
            ExitCode::FAILURE
        }
    }
}

fn init_logger(level: LevelFilter) {
    env_logger::Builder::new()
        .filter_level(level)
        // fast-socks5 logs username/password bytes at DEBUG: never let that through.
        .filter_module("fast_socks5", level.min(LevelFilter::Info))
        .init();
}

async fn run(cfg: Config) -> Result<(), String> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("binding {}: {e}", cfg.listen))?;
    let mut term = signal(SignalKind::terminate()).map_err(|e| format!("SIGTERM handler: {e}"))?;
    info!(
        "listening on {}, mark {}, auth {}, udp {}",
        cfg.listen,
        cfg.mark.map_or("off".into(), |m| format!("{m:#x}")),
        if cfg.skip_auth {
            "skipped"
        } else if cfg.auth.is_some() {
            "password"
        } else {
            "none"
        },
        if cfg.allow_udp { "on" } else { "off" },
    );
    let shutdown = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("SIGINT received"),
            _ = term.recv() => info!("SIGTERM received"),
        }
    };
    marksocks::serve(listener, Arc::new(cfg), shutdown).await;
    info!("stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn args() {
        let run = |config: &str, check| {
            Ok(Cli::Run {
                config: config.into(),
                check,
            })
        };
        assert_eq!(parse(&[]), run(DEFAULT_CONFIG, false));
        assert_eq!(parse(&["--check"]), run(DEFAULT_CONFIG, true));
        assert_eq!(
            parse(&["--config", "/tmp/c.toml", "--check"]),
            run("/tmp/c.toml", true)
        );
        assert_eq!(parse(&["--help"]), Ok(Cli::Help));
        assert_eq!(parse(&["-V"]), Ok(Cli::Version));
        assert!(parse(&["--config"]).is_err());
        assert!(parse(&["--listen", "0.0.0.0:1080"]).is_err());
        assert!(parse(&["--password", "x"]).is_err());
    }
}
