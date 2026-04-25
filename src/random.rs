/*
 * Copyright (C) 2026 OpenHelloMiddle Contributors
 * SPDX-License-Identifier: MIT
 */
use anyhow::Result;
#[cfg(unix)]
use anyhow::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomSource {
    Random,
    Urandom,
}

pub fn fill_random_bytes(buf: &mut [u8], source: RandomSource) -> Result<()> {
    if buf.is_empty() { return Ok(()); }

    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::{Read, ErrorKind};

        let path = match source {
            RandomSource::Random => "/dev/random",
            RandomSource::Urandom => "/dev/urandom",
        };

        let mut dev = File::open(path)
            .with_context(|| format!("Failed to open {}", path))?;

        let mut offset = 0;
        while offset < buf.len() {
            match dev.read(&mut buf[offset..]) {
                Ok(0) => return Err(anyhow::anyhow!("Unexpected EOF from {}", path)),
                Ok(n) => offset += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(anyhow::anyhow!("Read error from {}: {}", path, e)),
            }
        }
    }

    #[cfg(windows)]
    {
        let _ = source;
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        // SAFETY: `buf` is valid, mutable, and lives long enough. Null provider is safe with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(anyhow::anyhow!("BCryptGenRandom failed with status: {}", status));
        }
    }

    Ok(())
}
