/*
 * Copyright (C) 2026 OpenHelloMiddle Contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let self_path = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());

    let mut files = Vec::new();

    for entry in WalkDir::new(root).follow_links(false).into_iter() {
        match entry {
            Ok(e) if e.file_type().is_file() => {
                if let Some(self_p) = &self_path
                    && std::fs::canonicalize(e.path()).ok().as_ref() == Some(self_p) {
                        continue;
                    }
                files.push(e.into_path());
            }
            Ok(_) => continue,
            Err(e) => {
                let path_str = e.path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                eprintln!("Warning: Skipping '{}': {}", path_str, e);
            }
        }
    }

    Ok(files)
}
