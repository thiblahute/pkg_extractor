// Copyright (C) 2026 Thibault Saunier <tsaunier@igalia.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use apple_flat_package::reader::{PkgFlavor, PkgReader};
use apple_xar::reader::XarReader;
use cpio_archive::{CpioReader as _, OdcReader};
use log::{debug, error, info, warn};
use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

mod pbzx;

const GZIP_MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];

pub struct PkgExtractor<R: Read + Seek + Sized + Debug> {
    reader: Option<R>,
    output_dir: PathBuf,
    // Retained for backward-compatible `new_with_file_path` API; no longer
    // used internally now that we no longer shell out to `xar`.
    #[allow(dead_code)]
    pkg_file_path: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
enum FileType {
    Directory,
    Regular,
    Symlink,
    Other,
}

impl FileType {
    fn from_mode(mode: u32) -> Self {
        match mode & 0o170000 {
            0o040000 => FileType::Directory,
            0o100000 => FileType::Regular,
            0o120000 => FileType::Symlink,
            _ => FileType::Other,
        }
    }
}

impl<R: Read + Seek + Sized + Debug> PkgExtractor<R> {
    pub fn new(reader: R, output_dir: Option<PathBuf>) -> Self {
        let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("extracted_pkg"));

        Self {
            reader: Some(reader),
            output_dir,
            pkg_file_path: None,
        }
    }

    pub fn new_with_file_path(
        reader: R,
        output_dir: Option<PathBuf>,
        pkg_file_path: PathBuf,
    ) -> Self {
        let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("extracted_pkg"));

        Self {
            reader: Some(reader),
            output_dir,
            pkg_file_path: Some(pkg_file_path),
        }
    }

    pub fn extract(mut self) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(&self.output_dir)?;

        let reader = self.reader.take().unwrap();

        // `PkgReader` gives us the flavor and wraps the xar; `into_inner`
        // hands the xar back so we can read `Payload` bytes ourselves. We
        // avoid `ComponentPackageReader::payload_reader`: that helper feeds
        // the Payload through `cpio_archive::reader`, which only sniffs cpio
        // magics (`070701`/`070702`/`070707`). Real Apple pkgs wrap the cpio
        // in `pbzx`, so the helper would return `Err(BadMagic)` and we'd
        // silently produce empty output.
        let pkg_reader = PkgReader::new(reader)?;
        let flavor = pkg_reader.flavor();
        let mut xar = pkg_reader.into_inner();

        match flavor {
            PkgFlavor::Component => {
                debug!("Package type: Component");
                self.extract_root_component(&mut xar)?;
            }
            PkgFlavor::Product => {
                debug!("Package type: Product");
                self.extract_product(&mut xar)?;
            }
        }

        info!(
            "Extraction completed. Files in: {}",
            self.output_dir.display()
        );
        Ok(())
    }

    fn extract_root_component<T: Read + Seek + Sized + Debug>(
        &self,
        xar: &mut XarReader<T>,
    ) -> Result<(), Box<dyn Error>> {
        match xar.get_file_data_from_path("Payload")? {
            Some(data) => self.extract_payload_bytes(&data),
            None => {
                warn!("Component package has no Payload");
                Ok(())
            }
        }
    }

    fn extract_product<T: Read + Seek + Sized + Debug>(
        &self,
        xar: &mut XarReader<T>,
    ) -> Result<(), Box<dyn Error>> {
        // Sub-packages live at the top level of the xar as directories whose
        // name ends in `.pkg`. This matches what `PkgReader::component_packages`
        // does internally; we just read the Payload file ourselves.
        let sub_pkgs: Vec<String> = xar
            .files()?
            .into_iter()
            .filter_map(|(name, _)| {
                if name.ends_with(".pkg") && !name.contains('/') {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();

        info!("Found {} component packages", sub_pkgs.len());

        let mut extracted_any = false;
        for (i, sub_pkg) in sub_pkgs.iter().enumerate() {
            debug!(
                "Extracting component package {}/{}: {}",
                i + 1,
                sub_pkgs.len(),
                sub_pkg
            );
            let payload_path = format!("{sub_pkg}/Payload");
            match xar.get_file_data_from_path(&payload_path)? {
                Some(data) => match self.extract_payload_bytes(&data) {
                    Ok(()) => extracted_any = true,
                    Err(e) => warn!("Payload extraction failed for {sub_pkg}: {e}"),
                },
                None => debug!("Sub-package {sub_pkg} has no Payload, skipping"),
            }
        }

        if !extracted_any && !sub_pkgs.is_empty() {
            return Err("No component payload could be extracted".into());
        }
        Ok(())
    }

    /// Dispatch on the magic bytes of a `Payload` file: `pbzx`-wrapped xz
    /// (modern pkgs), gzip-compressed cpio (pre-Mavericks legacy), or raw
    /// cpio (rare but permitted).
    fn extract_payload_bytes(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        if data.len() >= 4 && &data[0..4] == b"pbzx" {
            let mut reader = pbzx::PbzxReader::new(Cursor::new(data))?;
            let mut decompressed = Vec::new();
            reader.decompress_to(&mut decompressed)?;
            debug!("pbzx decompressed {} bytes", decompressed.len());
            self.extract_cpio(&decompressed)
        } else if data.len() >= 3 && data[0..3] == GZIP_MAGIC {
            let mut decoder = libflate::gzip::Decoder::new(Cursor::new(data))?;
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            debug!("gunzipped {} bytes", decompressed.len());
            self.extract_cpio(&decompressed)
        } else {
            debug!("assuming raw cpio ({} bytes)", data.len());
            self.extract_cpio(data)
        }
    }

    /// Extract a decompressed cpio (ODC / portable-ASCII) byte stream into
    /// `self.output_dir`.
    fn extract_cpio(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let cursor = Cursor::new(data);
        let mut cpio_reader = OdcReader::new(cursor);

        let mut file_count: u64 = 0;
        let mut total_bytes: u64 = 0;

        while let Some(header) = cpio_reader.read_next()? {
            let name = header.name().to_string();
            let file_size = header.file_size();
            let mode = header.mode();

            // Apple Payload cpios prefix every name with `./`; the `.` root
            // entry is the only one we need to skip explicitly.
            if name.is_empty() || name == "." {
                continue;
            }

            let target_path = match safe_join(&self.output_dir, &name) {
                Some(p) => p,
                None => {
                    warn!(
                        "Refusing to extract entry {name:?}: resolves outside {}",
                        self.output_dir.display()
                    );
                    continue;
                }
            };
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            match FileType::from_mode(mode) {
                FileType::Directory => {
                    fs::create_dir_all(&target_path)?;
                }
                FileType::Regular => {
                    drop(header);
                    let mut outfile = create_file_with_mode(&target_path, mode)?;
                    let mut buf = vec![0u8; 8192];
                    let mut remaining = file_size;
                    while remaining > 0 {
                        let to_read = remaining.min(buf.len() as u64) as usize;
                        match cpio_reader.read(&mut buf[..to_read]) {
                            Ok(0) => break,
                            Ok(n) => {
                                outfile.write_all(&buf[..n])?;
                                remaining -= n as u64;
                                total_bytes += n as u64;
                            }
                            Err(e) => {
                                error!("Error reading cpio entry {name}: {e}");
                                break;
                            }
                        }
                    }
                    file_count += 1;
                }
                FileType::Symlink => {
                    // The link target is stored as the entry body.
                    drop(header);
                    let mut target = vec![0u8; file_size as usize];
                    cpio_reader.read_exact(&mut target)?;
                    let target_str = String::from_utf8(target)
                        .map_err(|e| format!("invalid utf-8 symlink target for {name}: {e}"))?;
                    create_symlink(&target_str, &target_path)?;
                    file_count += 1;
                }
                _ => {
                    debug!("Skipping {:?} entry: {}", FileType::from_mode(mode), name);
                }
            }
        }

        debug!("Extracted {file_count} files, {total_bytes} bytes from cpio");
        Ok(())
    }
}

/// Create (or truncate) a regular file carrying the permission bits from a
/// cpio header. On Unix, only the low 12 bits (`& 0o7777`) are used; the
/// type-of-file nibble is applied via the create call itself. On non-Unix
/// hosts we fall back to the default create mode and drop the permission
/// bits on the floor -- there is no meaningful cross-platform mapping.
fn create_file_with_mode(path: &Path, mode: u32) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(mode & 0o7777);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    options.open(path)
}

/// Join a cpio entry name onto the output directory, refusing any path
/// component that would escape the root (`..`, or an absolute path, or a
/// Windows drive prefix). Returns `None` when the entry is unsafe. Normal
/// Apple Payload entries are `./`-rooted and always resolve inside.
fn safe_join(root: &Path, entry: &str) -> Option<PathBuf> {
    let candidate = Path::new(entry);
    if candidate.is_absolute() {
        return None;
    }

    let mut out = root.to_path_buf();
    for component in candidate.components() {
        use std::path::Component;
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Create `link` as a symlink pointing at `target`. If `link` already exists
/// (e.g. a pre-existing regular file in the destination), it is removed first
/// so the symlink creation succeeds.
fn create_symlink(target: &str, link: &Path) -> std::io::Result<()> {
    if link.symlink_metadata().is_ok() {
        fs::remove_file(link)?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        // cpio doesn't tell us whether the target is a file or a directory.
        // Default to file-symlink, which is what Apple payloads ship.
        std::os::windows::fs::symlink_file(target, link)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ---- `FileType::from_mode` ----

    #[test]
    fn file_type_from_mode_regular() {
        assert_eq!(FileType::from_mode(0o100644), FileType::Regular);
        assert_eq!(FileType::from_mode(0o100755), FileType::Regular);
    }

    #[test]
    fn file_type_from_mode_directory() {
        assert_eq!(FileType::from_mode(0o040755), FileType::Directory);
    }

    #[test]
    fn file_type_from_mode_symlink() {
        assert_eq!(FileType::from_mode(0o120777), FileType::Symlink);
    }

    #[test]
    fn file_type_from_mode_other() {
        // Char device, block device, FIFO, socket -- none of these four
        // should be mistaken for a regular or symlink.
        assert_eq!(FileType::from_mode(0o020644), FileType::Other);
        assert_eq!(FileType::from_mode(0o060644), FileType::Other);
        assert_eq!(FileType::from_mode(0o010644), FileType::Other);
        assert_eq!(FileType::from_mode(0o140644), FileType::Other);
    }

    // ---- `safe_join` ----

    #[test]
    fn safe_join_accepts_relative_and_curdir_paths() {
        let root = Path::new("/out");
        assert_eq!(
            safe_join(root, "foo").as_deref(),
            Some(Path::new("/out/foo"))
        );
        assert_eq!(
            safe_join(root, "a/b/c").as_deref(),
            Some(Path::new("/out/a/b/c"))
        );
        assert_eq!(
            safe_join(root, "./foo").as_deref(),
            Some(Path::new("/out/foo"))
        );
        assert_eq!(
            safe_join(root, "./a/./b").as_deref(),
            Some(Path::new("/out/a/b"))
        );
    }

    #[test]
    fn safe_join_rejects_parent_dir_anywhere() {
        let root = Path::new("/out");
        assert_eq!(safe_join(root, ".."), None);
        assert_eq!(safe_join(root, "../etc/passwd"), None);
        assert_eq!(safe_join(root, "a/../../b"), None);
        assert_eq!(safe_join(root, "a/b/.."), None);
    }

    #[test]
    fn safe_join_rejects_absolute_paths() {
        let root = Path::new("/out");
        assert_eq!(safe_join(root, "/etc/passwd"), None);
    }

    // ---- End-to-end `extract_cpio` round-trip ----

    /// Build one ODC ("070707") cpio header-plus-body for the given entry.
    /// `name` must be valid UTF-8; the NUL terminator is added here. For
    /// symlinks, pass the link target in `body`.
    fn odc_entry(name: &str, mode: u32, body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"070707");
        for _ in 0..2 {
            buf.extend_from_slice(b"000000"); // dev, ino
        }
        buf.extend_from_slice(format!("{mode:06o}").as_bytes());
        buf.extend_from_slice(b"000000"); // uid
        buf.extend_from_slice(b"000000"); // gid
        buf.extend_from_slice(b"000001"); // nlink
        buf.extend_from_slice(b"000000"); // rdev
        buf.extend_from_slice(b"00000000000"); // mtime
        let name_bytes = name.as_bytes();
        let namesize = name_bytes.len() + 1; // includes trailing NUL
        buf.extend_from_slice(format!("{namesize:06o}").as_bytes());
        buf.extend_from_slice(format!("{:011o}", body.len()).as_bytes());
        buf.extend_from_slice(name_bytes);
        buf.push(0);
        buf.extend_from_slice(body);
        buf
    }

    fn trailer() -> Vec<u8> {
        odc_entry("TRAILER!!!", 0, b"")
    }

    fn test_extractor(out_dir: &Path) -> PkgExtractor<Cursor<Vec<u8>>> {
        PkgExtractor::new(Cursor::new(Vec::<u8>::new()), Some(out_dir.to_path_buf()))
    }

    #[test]
    fn extract_cpio_materialises_files_dirs_and_empties() {
        let tmp = tempfile::tempdir().unwrap();

        let mut cpio = Vec::new();
        cpio.extend(odc_entry("./dir", 0o040755, b""));
        cpio.extend(odc_entry("./dir/hello.txt", 0o100644, b"hello\n"));
        cpio.extend(odc_entry("./empty", 0o100644, b""));
        cpio.extend(trailer());

        test_extractor(tmp.path()).extract_cpio(&cpio).unwrap();

        let root = tmp.path();
        assert!(root.join("dir").is_dir());
        assert_eq!(fs::read(root.join("dir/hello.txt")).unwrap(), b"hello\n");
        assert!(root.join("empty").is_file());
        assert_eq!(fs::read(root.join("empty")).unwrap(), Vec::<u8>::new());
    }

    #[cfg(unix)]
    #[test]
    fn extract_cpio_preserves_unix_mode_bits() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();

        let mut cpio = Vec::new();
        cpio.extend(odc_entry("./script", 0o100755, b"#!/bin/sh\nexit 0\n"));
        cpio.extend(odc_entry("./readonly", 0o100444, b"data"));
        cpio.extend(trailer());

        test_extractor(tmp.path()).extract_cpio(&cpio).unwrap();

        let script_mode = fs::metadata(tmp.path().join("script"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(script_mode, 0o755);

        let ro_mode = fs::metadata(tmp.path().join("readonly"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(ro_mode, 0o444);
    }

    #[cfg(unix)]
    #[test]
    fn extract_cpio_materialises_symlinks() {
        let tmp = tempfile::tempdir().unwrap();

        let mut cpio = Vec::new();
        cpio.extend(odc_entry("./real.txt", 0o100644, b"target\n"));
        cpio.extend(odc_entry("./link", 0o120777, b"real.txt"));
        cpio.extend(trailer());

        test_extractor(tmp.path()).extract_cpio(&cpio).unwrap();

        let meta = fs::symlink_metadata(tmp.path().join("link")).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(
            fs::read_link(tmp.path().join("link")).unwrap(),
            Path::new("real.txt")
        );
        // Reading through the symlink yields the target's bytes.
        assert_eq!(fs::read(tmp.path().join("link")).unwrap(), b"target\n");
    }

    #[test]
    fn extract_cpio_refuses_path_traversal_but_keeps_safe_entries() {
        let tmp = tempfile::tempdir().unwrap();

        let mut cpio = Vec::new();
        cpio.extend(odc_entry("./../../evil.txt", 0o100644, b"pwned"));
        cpio.extend(odc_entry("./safe.txt", 0o100644, b"ok"));
        cpio.extend(trailer());

        test_extractor(tmp.path()).extract_cpio(&cpio).unwrap();

        // Nothing was written above the output root.
        let parent_evil = tmp
            .path()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("evil.txt");
        assert!(!parent_evil.exists());
        // The legitimate entry beside it still landed.
        assert_eq!(fs::read(tmp.path().join("safe.txt")).unwrap(), b"ok");
    }
}
