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
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::PathBuf;

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

            let target_path = self.output_dir.join(&name);
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            match FileType::from_mode(mode) {
                FileType::Directory => {
                    fs::create_dir_all(&target_path)?;
                }
                FileType::Regular if file_size > 0 => {
                    drop(header);
                    let mut outfile = File::create(&target_path)?;
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
                _ => {
                    debug!("Skipping {:?} entry: {}", FileType::from_mode(mode), name);
                }
            }
        }

        debug!("Extracted {file_count} files, {total_bytes} bytes from cpio");
        Ok(())
    }
}
