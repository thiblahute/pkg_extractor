use apple_flat_package::component_package::ComponentPackageReader;
use apple_flat_package::reader::{PkgFlavor, PkgReader};
use cpio_archive::{CpioReader as _, OdcReader};
use log::{debug, error, info, warn};
use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

mod pbzx;

pub struct PkgExtractor<R: Read + Seek + Sized + Debug> {
    reader: Option<R>,
    output_dir: PathBuf,
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

    pub fn new_with_file_path(reader: R, output_dir: Option<PathBuf>, pkg_file_path: PathBuf) -> Self {
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

        // If no file path is available, save reader data to a temp file
        // so xar fallback can work if needed
        if self.pkg_file_path.is_none() {
            let temp_file = tempfile::NamedTempFile::new()?;
            let temp_path = temp_file.path().to_path_buf();

            let mut file = File::create(&temp_path)?;
            let mut buffer = Vec::new();
            let mut reader_cursor = reader;
            reader_cursor.read_to_end(&mut buffer)?;
            file.write_all(&buffer)?;
            file.sync_all()?;
            drop(file);

            self.pkg_file_path = Some(temp_path.clone());

            let temp_file_reader = File::open(&temp_path)?;
            let mut pkg_reader = PkgReader::new(temp_file_reader)?;
            self.extract_with_pkg_reader(&mut pkg_reader)
        } else {
            let mut pkg_reader = PkgReader::new(reader)?;
            self.extract_with_pkg_reader(&mut pkg_reader)
        }
    }

    fn extract_with_pkg_reader<T: Read + Seek + Sized + Debug>(
        &self,
        pkg_reader: &mut PkgReader<T>,
    ) -> Result<(), Box<dyn Error>> {
        match pkg_reader.flavor() {
            PkgFlavor::Component => {
                debug!("Package type: Component");
                self.extract_component(pkg_reader)?;
            }
            PkgFlavor::Product => {
                debug!("Package type: Product");
                self.extract_product(pkg_reader)?;
            }
        }

        info!(
            "Extraction completed. Files in: {}",
            self.output_dir.display()
        );
        Ok(())
    }

    fn extract_component<T: Read + Seek + Sized + Debug>(
        &self,
        pkg_reader: &mut PkgReader<T>,
    ) -> Result<(), Box<dyn Error>> {
        match pkg_reader.root_component() {
            Ok(Some(component_pkg_reader)) => {
                self.extract_component_package(&component_pkg_reader)
            }
            Ok(None) => {
                warn!("No root component found, trying xar fallback");
                self.extract_with_xar_fallback()
            }
            Err(e) => {
                warn!("Error reading component: {}, trying xar fallback", e);
                self.extract_with_xar_fallback()
            }
        }
    }

    fn extract_product<T: Read + Seek + Sized + Debug>(
        &self,
        pkg_reader: &mut PkgReader<T>,
    ) -> Result<(), Box<dyn Error>> {
        match pkg_reader.component_packages() {
            Ok(component_packages) => {
                info!("Found {} component packages", component_packages.len());
                for (i, component_pkg_reader) in component_packages.iter().enumerate() {
                    debug!(
                        "Extracting component package {} of {}",
                        i + 1,
                        component_packages.len()
                    );
                    self.extract_component_package(component_pkg_reader)?;
                }
                Ok(())
            }
            Err(e) => {
                warn!("Error reading product package: {}, trying xar fallback", e);
                self.extract_with_xar_fallback()
            }
        }
    }

    fn extract_component_package(
        &self,
        component_pkg_reader: &ComponentPackageReader,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(package_info) = component_pkg_reader.package_info() {
            if let Some(ref payload) = package_info.payload {
                debug!(
                    "Component: {} ({} files, {} KB)",
                    package_info.identifier, payload.number_of_files, payload.install_kbytes
                );
            }
        }

        if let Ok(Some(mut payload_reader)) = component_pkg_reader.payload_reader() {
            let mut total_bytes: u64 = 0;
            let mut file_count: u64 = 0;

            while let Ok(Some(header)) = payload_reader.read_next() {
                let name = header.name();
                let file_size = header.file_size();
                let mode = header.mode();

                if name.is_empty() || name == "." || name == "Payload" {
                    payload_reader.finish()?;
                    continue;
                }

                let clean_name = name.strip_prefix("Payload/").unwrap_or(name);
                let target_path = self.output_dir.join(clean_name);

                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                match FileType::from_mode(mode) {
                    FileType::Directory => {
                        fs::create_dir_all(&target_path)?;
                    }
                    FileType::Regular if file_size > 0 => {
                        let mut outfile = File::create(&target_path)?;
                        let mut buf = vec![0; 8192];
                        let mut remaining = file_size;

                        while remaining > 0 {
                            let to_read = remaining.min(buf.len() as u64) as usize;
                            match payload_reader.read(&mut buf[..to_read]) {
                                Ok(0) => break,
                                Ok(n) => {
                                    outfile.write_all(&buf[..n])?;
                                    remaining -= n as u64;
                                    total_bytes += n as u64;
                                }
                                Err(e) => {
                                    error!("Error reading file {}: {}", name, e);
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

                payload_reader.finish()?;
            }

            debug!("Extracted {} files, {} bytes", file_count, total_bytes);
        } else {
            warn!("No payload reader available");
        }

        Ok(())
    }

    /// Fallback extraction using the system `xar` command
    fn extract_with_xar_fallback(&self) -> Result<(), Box<dyn Error>> {
        let pkg_path = self
            .pkg_file_path
            .as_ref()
            .ok_or("No file path available for xar fallback")?;

        info!("Using xar fallback extraction");

        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        // List components
        let list_output = Command::new("xar")
            .args(["-tf", &pkg_path.to_string_lossy()])
            .output()?;

        if !list_output.status.success() {
            return Err(format!(
                "xar list failed: {}",
                String::from_utf8_lossy(&list_output.stderr)
            )
            .into());
        }

        let contents = String::from_utf8_lossy(&list_output.stdout);
        let component_names: Vec<&str> = contents
            .lines()
            .filter(|line| line.ends_with(".pkg") && !line.contains('/'))
            .collect();

        info!("Found {} components", component_names.len());

        // Extract each component
        for component_name in &component_names {
            let output = Command::new("xar")
                .args(["-xf", &pkg_path.to_string_lossy(), component_name])
                .current_dir(temp_path)
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to extract {}: {}",
                    component_name,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        // Process extracted component packages
        for entry in fs::read_dir(temp_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() && path.extension().is_some_and(|e| e == "pkg") {
                let payload_path = path.join("Payload");
                if payload_path.exists() {
                    if let Err(e) = self.extract_payload_file(&payload_path) {
                        warn!(
                            "Failed to extract payload from {}: {}",
                            path.file_name().unwrap().to_string_lossy(),
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract a payload file (gzipped cpio or pbzx format)
    fn extract_payload_file(&self, payload_path: &Path) -> Result<(), Box<dyn Error>> {
        let mut file = File::open(payload_path)?;
        let mut header = [0u8; 4];
        file.read_exact(&mut header)?;
        drop(file);

        if &header == b"pbzx" {
            self.extract_pbzx_payload(payload_path)
        } else {
            self.extract_gzip_cpio_payload(payload_path)
        }
    }

    fn extract_pbzx_payload(&self, payload_path: &Path) -> Result<(), Box<dyn Error>> {
        let file = File::open(payload_path)?;

        // Try pure Rust implementation first
        match pbzx::PbzxReader::new(file) {
            Ok(mut pbzx_reader) => {
                let mut decompressed = Vec::new();
                match pbzx_reader.decompress_to(&mut decompressed) {
                    Ok(_) => {
                        debug!("pbzx decompressed {} bytes", decompressed.len());
                        return self.extract_cpio(&decompressed);
                    }
                    Err(e) => {
                        warn!("Pure Rust pbzx failed: {}, trying shell fallback", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create pbzx reader: {}, trying shell fallback", e);
            }
        }

        // Shell fallback
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "cd '{}' && pbzx -n '{}' | cpio -idm",
                self.output_dir.display(),
                payload_path.display()
            ))
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Shell pbzx extraction failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn extract_gzip_cpio_payload(&self, payload_path: &Path) -> Result<(), Box<dyn Error>> {
        let file = File::open(payload_path)?;
        let gz_decoder = libflate::gzip::Decoder::new(file)?;
        let mut cpio_reader = OdcReader::new(gz_decoder);

        let mut file_count = 0;
        while let Some(entry) = cpio_reader.read_next()? {
            let path = entry.name();

            if path == "." || path == "TRAILER!!!" || path.is_empty() {
                continue;
            }

            let target_path = self.output_dir.join(path);

            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            match FileType::from_mode(entry.mode()) {
                FileType::Directory => {
                    fs::create_dir_all(&target_path)?;
                }
                FileType::Regular => {
                    let mut file = File::create(&target_path)?;
                    let mut content = Vec::new();
                    cpio_reader.read_to_end(&mut content)?;
                    file.write_all(&content)?;
                    file_count += 1;
                }
                _ => {}
            }
        }

        debug!("Extracted {} files from gzipped cpio", file_count);
        Ok(())
    }

    /// Extract a cpio archive from decompressed data
    fn extract_cpio(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let cursor = Cursor::new(data);
        let mut cpio_reader = OdcReader::new(cursor);

        let mut file_count = 0;
        while let Some(entry) = cpio_reader.read_next()? {
            let path = entry.name();

            if path == "." || path == "TRAILER!!!" || path.is_empty() {
                continue;
            }

            let target_path = self.output_dir.join(path);

            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            match FileType::from_mode(entry.mode()) {
                FileType::Directory => {
                    fs::create_dir_all(&target_path)?;
                }
                FileType::Regular => {
                    let mut file = File::create(&target_path)?;
                    let mut content = Vec::new();
                    cpio_reader.read_to_end(&mut content)?;
                    file.write_all(&content)?;
                    file_count += 1;
                }
                _ => {}
            }
        }

        debug!("Extracted {} files from cpio archive", file_count);
        Ok(())
    }
}
