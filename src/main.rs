/*
 * Copyright (C) 2026 OpenHelloMiddle Contributors
 * SPDX-License-Identifier: MIT
 */
use clap::Parser;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

mod random;
mod file_ops;
mod walker;

use random::RandomSource;

#[derive(Parser, Debug)]
#[command(name = "randfill", about = "Overwrite files with cryptographically secure random data", version)]
struct Args {
    #[arg(required = true)]
    targets: Vec<PathBuf>,

    #[arg(short, long, default_value_t = 0)]
    threads: usize,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(long, default_value_t = false)]
    urandom: bool,

    #[arg(long, default_value_t = false, help = "Simulate operation without writing data")]
    dry_run: bool,
}

fn process_file(path: &Path, verbose: bool, random_source: RandomSource, dry_run: bool) -> Result<()> {
    if verbose { println!("Processing: {}", path.display()); }

    let meta = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {}", path.display()))?;

    let size = meta.len();
    if size == 0 {
        if verbose { println!("Skipped (empty): {}", path.display()); }
        return Ok(());
    }

    if !dry_run {
        file_ops::overwrite_with_random(path, size, random_source)
            .with_context(|| format!("Failed to overwrite {}", path.display()))?;
    }

    if verbose { println!("Successful {}", path.display()); }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.dry_run { eprintln!("[!] DRY-RUN MODE: No data will be written.") }
    let random_source = if args.urandom { RandomSource::Urandom } else { RandomSource::Random };

    let mut files = Vec::new();
    for target in &args.targets {
        if target.is_dir() {
            let mut dir_files = walker::collect_files(target)
                .with_context(|| format!("Failed to walk directory '{}'", target.display()))?;
            files.append(&mut dir_files);
        } else if target.is_file() {
            files.push(target.clone());
        } else {
            eprintln!("Warning: '{}' not found or not a file/directory, skipping", target.display());
        }
    }

    if files.is_empty() {
        eprintln!("No files to process.");
        return Ok(());
    }

    let threads = if args.threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    } else {
        args.threads.max(1)
    };

    println!("Processing {} files with {} threads...", files.len(), threads);

    let failed = AtomicUsize::new(0);
    let errors = std::sync::Mutex::new(Vec::<(PathBuf, String)>::new());

    let pb = if args.verbose {
        None
    } else {
        let bar = ProgressBar::new(files.len() as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("##-"),
        );
        Some(bar)
    };
    files.par_iter().for_each(|path| {
        let res = process_file(path, args.verbose, random_source, args.dry_run);

        if let Err(e) = res {
            failed.fetch_add(1, Ordering::Relaxed);
            let err_msg = e.to_string();
            if let Ok(mut lock) = errors.lock() {
                lock.push((path.clone(), err_msg.clone()));
            }
            if let Some(bar) = &pb {
                bar.println(format!("Failed: {} -> {}", path.display(), err_msg));
            }
        }

        if let Some(bar) = &pb {
            bar.inc(1);
        }
    });

    if let Some(bar) = &pb {
        bar.finish();
    }

    let success = files.len() - failed.load(Ordering::Relaxed);
    println!("\nSuccessful: {} | Failure: {}", success, failed.load(Ordering::Relaxed));

    if failed.load(Ordering::Relaxed) > 0 {
        println!("\nFailed:");
        for (path, err) in errors.lock().unwrap().iter() {
            println!("  {}: {}", path.display(), err);
        }
        std::process::exit(1);
    }

    Ok(())
}
