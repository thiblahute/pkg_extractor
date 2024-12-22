use apple_flat_package::component_package::ComponentPackageReader;
use apple_flat_package::reader::{PkgFlavor, PkgReader};
use log::{debug, error, info, warn};
use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

pub struct PkgExtractor<R: Read + Seek + Sized + Debug> {
    reader: Option<R>,
    output_dir: PathBuf,
}

#[derive(Debug, PartialEq)]
enum FileType {
    Directory,
    Regular,
    Symlink,
    Socket,
    BlockDevice,
    CharacterDevice,
    Fifo,
    Unknown(u32),
}

impl FileType {
    fn from_mode(mode: u32) -> Self {
        match mode & 0o170000 {
            0o040000 => FileType::Directory,
            0o100000 => FileType::Regular,
            0o120000 => FileType::Symlink,
            0o140000 => FileType::Socket,
            0o060000 => FileType::BlockDevice,
            0o020000 => FileType::CharacterDevice,
            0o010000 => FileType::Fifo,
            other => FileType::Unknown(other),
        }
    }
}

impl<R: Read + Seek + Sized + Debug> PkgExtractor<R> {
    pub fn new(reader: R, output_dir: Option<PathBuf>) -> Self {
        let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("extracted_pkg"));

        Self {
            reader: Some(reader),
            output_dir,
        }
    }

    pub fn extract(mut self) -> Result<(), Box<dyn Error>> {
        // Create output directory
        fs::create_dir_all(&self.output_dir)?;

        let reader = self.reader.take().unwrap();

        let mut pkg_reader = PkgReader::new(reader)?;

        // Handle different package flavors
        match pkg_reader.flavor() {
            PkgFlavor::Component => {
                debug!("Package type: Component");
                self.extract_root_component(&mut pkg_reader)?;
            }
            PkgFlavor::Product => {
                debug!("Package type: Product");
                self.extract_product_package(&mut pkg_reader)?;
            }
        }

        info!(
            "Extraction completed successfully. Files are in: {}",
            self.output_dir.display()
        );
        Ok(())
    }

    fn extract_root_component(&self, pkg_reader: &mut PkgReader<R>) -> Result<(), Box<dyn Error>> {
        match pkg_reader.root_component()? {
            Some(component_pkg_reader) => {
                debug!("Extracting Root Component Package");
                self.extract_component_package(&component_pkg_reader)?;
            }
            None => {
                warn!("No root component found");
            }
        }
        Ok(())
    }

    fn extract_product_package(&self, pkg_reader: &mut PkgReader<R>) -> Result<(), Box<dyn Error>> {
        match pkg_reader.component_packages() {
            Ok(component_packages) => {
                info!("Found {} component packages", component_packages.len());

                for component_pkg_reader in component_packages {
                    // Extract directly to output dir without component subdirectory
                    self.extract_component_package(&component_pkg_reader)?;
                }
            }
            Err(e) => {
                error!("Error getting component packages: {}", e);
            }
        }
        Ok(())
    }

    fn extract_component_package(
        &self,
        component_pkg_reader: &ComponentPackageReader,
    ) -> Result<(), Box<dyn Error>> {
        // Log package info
        if let Some(package_info) = component_pkg_reader.package_info() {
            if let Some(ref payload) = package_info.payload {
                debug!("Component Package:");
                debug!("  Identifier: {}", package_info.identifier);
                debug!("  Files: {}", payload.number_of_files);
                debug!("  Install KB: {}", payload.install_kbytes);
            }
        }

        // Extract payload
        if let Ok(Some(mut payload_reader)) = component_pkg_reader.payload_reader() {
            let mut total_bytes = 0;

            // Read each entry from the CPIO archive
            while let Ok(Some(header)) = payload_reader.read_next() {
                let name = header.name();
                let file_size = header.file_size();
                let mode = header.mode();

                // Skip the "Payload" directory itself and empty paths
                if name.is_empty() || name == "." || name == "Payload" {
                    payload_reader.finish()?;
                    continue;
                }

                // Remove "Payload/" prefix if present
                let clean_name = name.strip_prefix("Payload/").unwrap_or(name);
                let target_path = self.output_dir.join(clean_name);

                debug!(
                    "Extracting: {} (size: {} bytes, mode: {:o})",
                    clean_name, file_size, mode
                );

                // Ensure parent directories exist
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Check if it's a directory (mode & 0o170000 == 0o040000)
                let file_type = FileType::from_mode(mode);
                match file_type {
                    FileType::Directory => {
                        fs::create_dir_all(&target_path)?;
                    }
                    FileType::Regular => {
                        if file_size > 0 {
                            // Copy entry contents to file
                            let mut outfile = File::create(&target_path)?;
                            let mut buf = vec![0; 8192];
                            let mut remaining = file_size;

                            while remaining > 0 {
                                let to_read = remaining.min(buf.len() as u64) as usize;
                                match payload_reader.read(&mut buf[..to_read]) {
                                    Ok(0) => break, // EOF
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
                        }
                    }
                    _ => {
                        debug!("Skipping {:?} file type for {}", file_type, name);
                    }
                }

                // Finish reading this entry
                payload_reader.finish()?;
            }

            debug!("Extracted {} bytes total", total_bytes);
        }

        Ok(())
    }
}
