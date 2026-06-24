use std::env;
use std::path::PathBuf;

/// Process-level environment for the CLI.
#[derive(Debug, Clone)]
pub struct CliEnvironment {
    pub cwd: PathBuf,
    pub config_dir: PathBuf,
    pub now: Option<String>,
}

impl CliEnvironment {
    /// Build a CLI environment from process env vars.
    pub fn from_process() -> Self {
        let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let config_dir = env::var_os("FBRAIN_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|home| PathBuf::from(home).join(".finitebrain/fbrain"))
            })
            .unwrap_or_else(|| cwd.join(".fbrain"));
        let now = env::var("FBRAIN_NOW").ok();
        Self {
            cwd,
            config_dir,
            now,
        }
    }
}
