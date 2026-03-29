use std::path::{Path, PathBuf};

fn config_base_dir(xdg_config_home: Option<&Path>, home: Option<&Path>) -> PathBuf {
    match xdg_config_home {
        Some(base) => base.to_path_buf(),
        None => {
            let home_dir = match home {
                Some(path) => path.to_path_buf(),
                None => {
                    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
                }
            };
            home_dir.join(".config")
        }
    }
}

pub(crate) fn named_config_toml_path(
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
    domain: &str,
    name: &str,
) -> PathBuf {
    config_base_dir(xdg_config_home, home)
        .join("noscope")
        .join(domain)
        .join(format!("{}.toml", name))
}
