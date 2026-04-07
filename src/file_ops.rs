/*
 * Copyright (C) 2026 OpenHelloMiddle Contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
use anyhow::{Context, Result};
use std::{
    fs::OpenOptions,
    io::{Write, Seek, SeekFrom},
    path::Path,
    time::SystemTime,
};
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, MetadataExt};
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
};

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub modified: SystemTime,
    pub accessed: SystemTime,
    #[cfg(unix)]
    pub permissions: u32,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    #[cfg(windows)]
    pub is_readonly: bool,
}

struct MetadataGuard<'a> {
    path: &'a Path,
    meta: &'a FileMetadata,
    active: bool,
}
impl Drop for MetadataGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = restore_metadata(self.path, self.meta);
        }
    }
}

pub fn backup_metadata(path: &Path) -> Result<FileMetadata> {
    let meta = std::fs::metadata(path).context("Failed to read metadata")?;
    Ok(FileMetadata {
       modified: meta.modified().context("Failed to get modified time")?,
       accessed: meta.accessed().context("Failed to get accessed time")?,
       #[cfg(unix)]
       permissions: meta.permissions().mode(),
       #[cfg(unix)]
       uid: meta.uid(),
       #[cfg(unix)]
       gid: meta.gid(),
       #[cfg(windows)]
       is_readonly: {
           use std::os::windows::ffi::OsStrExt;
           let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
           // SAFETY: `wide` is a valid null-terminated UTF-16 string. `GetFileAttributesW` only reads it.
           let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
           attrs != 0xFFFFFFFF && (attrs & FILE_ATTRIBUTE_READONLY) != 0
       },
    })
}

#[cfg(unix)]
fn ensure_writable(path: &Path, meta: &FileMetadata) -> Result<()> {
    if meta.permissions & 0o200 != 0 { return Ok(()); }
    let perms = Permissions::from_mode(meta.permissions | 0o200);
    std::fs::set_permissions(path, perms)
        .context("Failed to add owner write permission")
}

#[cfg(windows)]
fn ensure_writable(path: &Path, meta: &FileMetadata) -> Result<()> {
    let _ = meta;
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is valid and null-terminated. Pointer outlives both calls.
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == 0xFFFFFFFF {
        return Err(anyhow::anyhow!("Failed to get file attributes"));
    }
    if (attrs & FILE_ATTRIBUTE_READONLY) != 0 {
        if unsafe { SetFileAttributesW(wide.as_ptr(), attrs & !FILE_ATTRIBUTE_READONLY) } == 0 {
            return Err(anyhow::anyhow!("Failed to clear readonly attribute (requires admin privileges)"));
        }
    }
    Ok(())
}

pub fn restore_metadata(path: &Path, meta: &FileMetadata) -> Result<()> {
    filetime::set_file_times(
        path,
        filetime::FileTime::from_system_time(meta.accessed),
                             filetime::FileTime::from_system_time(meta.modified),
    ).context("Failed to restore timestamps")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, Permissions::from_mode(meta.permissions))
            .context("Failed to restore permissions")?;
        if let Err(e) = nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(meta.uid)),
                                           Some(nix::unistd::Gid::from_raw(meta.gid)),
        ) {
            eprintln!("Warning: Failed to restore ownership for {}: {}", path.display(), e);
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is valid. `attrs` is safely masked before being passed back.
        let mut attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs != 0xFFFFFFFF {
            if meta.is_readonly {
                attrs |= FILE_ATTRIBUTE_READONLY;
            } else {
                attrs &= !FILE_ATTRIBUTE_READONLY;
            }
            unsafe { SetFileAttributesW(wide.as_ptr(), attrs) };
        }
    }
    Ok(())
}

pub fn overwrite_with_random(path: &Path, size: u64, random_source: crate::random::RandomSource) -> Result<()> {
    const CHUNK: usize = 64 * 1024;
    let meta = backup_metadata(path)?;

    let mut guard = MetadataGuard { path, meta: &meta, active: true };

    ensure_writable(path, &meta).context("Failed to make file writable")?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(false)
        .truncate(false)
        .open(path)
        .context("Failed to open file for writing")?;

    file.seek(SeekFrom::Start(0)).context("Seek failed")?;

    let mut buf = vec![0u8; CHUNK];
    let mut remaining = size;

    while remaining > 0 {
        let n = std::cmp::min(remaining as usize, CHUNK);
        crate::random::fill_random_bytes(&mut buf[..n], random_source)
            .context("Failed to generate random data")?;
        file.write_all(&buf[..n]).context("Write failed")?;
        remaining -= n as u64;
    }

    file.sync_all().context("Sync failed")?;

    guard.active = false;
    restore_metadata(path, &meta).context("Failed to restore metadata after overwrite")
}
