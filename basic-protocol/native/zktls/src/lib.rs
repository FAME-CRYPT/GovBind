use std::{fs::OpenOptions, io::Write, path::Path};

use anyhow::{Context, Result, bail};

pub const EDEVLET_DOMAIN: &str = "www.turkiye.gov.tr";
pub const EDEVLET_PDF_TARGET: &str = "/belge-dogrulama?belge=goster&goster=1&display=display";
pub const MAX_PDF_BYTES: usize = 4 * 1024 * 1024;

pub fn reject_header_injection(name: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        bail!("{name} contains a forbidden line break");
    }
    Ok(())
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
