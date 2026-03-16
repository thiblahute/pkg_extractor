use apple_flat_package::component_package::ComponentPackageReader;
use apple_flat_package::reader::{PkgFlavor, PkgReader};
use cpio_archive::{NewcReader, OdcReader, CpioReader};
use log::{debug, error, info, warn};
use std::error::Error;
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{Read, Seek, Write, Cursor};
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

mod pbzx;

pub struct PkgExtractor<R: Read + Seek + Sized + Debug> {
    reader: Option<R>,
    output_dir: PathBuf,
    pkg_file_path: Option<PathBuf>, // Add this for fallback extraction
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
        // Create output directory
        println!("Creating output directory: {}", self.output_dir.display());
        fs::create_dir_all(&self.output_dir)?;

        let reader = self.reader.take().unwrap();
        
        // If we don't have a file path, save the reader data to a temp file first
        // This ensures xar fallback will work if needed
        if self.pkg_file_path.is_none() {
            println!("No file path provided - saving in-memory data to temporary file for potential xar fallback...");
            let temp_file = tempfile::NamedTempFile::new()?;
            let temp_path = temp_file.path().to_path_buf();
            
            // Read all data from reader and write to temp file
            let mut file = std::fs::File::create(&temp_path)?;
            let mut buffer = Vec::new();
            let mut reader_cursor = reader;
            reader_cursor.read_to_end(&mut buffer)?;
            file.write_all(&buffer)?;
            file.sync_all()?;
            drop(file); // Close the file before using it
            
            // Update our pkg_file_path to the temp file
            self.pkg_file_path = Some(temp_path.clone());
            
            // Create a new reader from the temp file
            let temp_file_reader = std::fs::File::open(&temp_path)?;
            let mut pkg_reader = PkgReader::new(temp_file_reader)?;
            
            // Continue with extraction
            self.extract_with_pkg_reader(&mut pkg_reader)
        } else {
            let mut pkg_reader = PkgReader::new(reader)?;
            self.extract_with_pkg_reader(&mut pkg_reader)
        }
    }
    
    fn extract_with_pkg_reader<T: Read + Seek + Sized + Debug>(&self, pkg_reader: &mut PkgReader<T>) -> Result<(), Box<dyn Error>> {

        // Handle different package flavors
        match pkg_reader.flavor() {
            PkgFlavor::Component => {
                println!("Package type: Component");
                debug!("Package type: Component");
                self.extract_root_component_generic(pkg_reader)?;
            }
            PkgFlavor::Product => {
                println!("Package type: Product");
                debug!("Package type: Product");
                self.extract_product_package_generic(pkg_reader)?;
            }
        }

        println!(
            "Extraction completed successfully. Files should be in: {}",
            self.output_dir.display()
        );
        info!(
            "Extraction completed successfully. Files are in: {}",
            self.output_dir.display()
        );
        Ok(())
    }

    fn extract_root_component_generic<T: Read + Seek + Sized + Debug>(&self, pkg_reader: &mut PkgReader<T>) -> Result<(), Box<dyn Error>> {
        match pkg_reader.root_component() {
            Ok(Some(component_pkg_reader)) => {
                debug!("Extracting Root Component Package");
                self.extract_component_package(&component_pkg_reader)?;
                Ok(())
            }
            Ok(None) => {
                println!("No root component found");
                self.extract_with_xar_fallback()
            }
            Err(e) => {
                println!("Error getting component payload: {}", e);
                println!("This is likely an XML parsing issue with package metadata.");
                println!("Attempting to continue with root component extraction...");
                
                match self.extract_with_xar_fallback() {
                    Ok(_) => Ok(()),
                    Err(root_err) => {
                        println!("Root component extraction also failed: {}", root_err);
                        self.extract_with_xar_fallback()
                    }
                }
            }
        }
    }

    fn extract_product_package_generic<T: Read + Seek + Sized + Debug>(&self, pkg_reader: &mut PkgReader<T>) -> Result<(), Box<dyn Error>> {
        println!("Extracting product package...");
        match pkg_reader.component_packages() {
            Ok(component_packages) => {
                println!("Found {} component packages", component_packages.len());
                info!("Found {} component packages", component_packages.len());
                for (i, component_pkg_reader) in component_packages.iter().enumerate() {
                    println!("Extracting component package {} of {}", i + 1, component_packages.len());
                    self.extract_component_package(&component_pkg_reader)?;
                }
                Ok(())
            }
            Err(e) => {
                println!("Error getting component packages: {}", e);
                println!("This is likely an XML parsing issue with package metadata.");
                println!("Attempting to continue with root component extraction...");
                
                match self.extract_with_xar_fallback() {
                    Ok(_) => Ok(()),
                    Err(root_err) => {
                        println!("Root component extraction also failed: {}", root_err);
                        self.extract_with_xar_fallback()
                    }
                }
            }
        }
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
        println!("Extracting product package...");
        match pkg_reader.component_packages() {
            Ok(component_packages) => {
                println!("Found {} component packages", component_packages.len());
                info!("Found {} component packages", component_packages.len());

                for (i, component_pkg_reader) in component_packages.iter().enumerate() {
                    println!("Extracting component package {} of {}", i + 1, component_packages.len());
                    // Extract directly to output dir without component subdirectory
                    self.extract_component_package(&component_pkg_reader)?;
                }
            }
            Err(e) => {
                println!("Error getting component packages: {}", e);
                println!("This is likely an XML parsing issue with package metadata.");
                println!("Attempting to continue with root component extraction...");
                error!("Error getting component packages: {}", e);
                
                // Try to extract root component as fallback
                match pkg_reader.root_component() {
                    Ok(Some(component_pkg_reader)) => {
                        println!("Found root component, extracting as fallback...");
                        self.extract_component_package(&component_pkg_reader)?;
                    }
                    Ok(None) => {
                        println!("No root component found either");
                        if self.pkg_file_path.is_some() {
                            println!("Trying xar fallback...");
                            self.extract_with_xar_fallback()?;
                        } else {
                            println!("No file path available for xar fallback, extraction failed");
                            return Err("Cannot extract package: no root component found and no file path for xar fallback".into());
                        }
                    }
                    Err(e2) => {
                        println!("Root component extraction also failed: {}", e2);
                        if self.pkg_file_path.is_some() {
                            println!("Trying xar fallback extraction...");
                            self.extract_with_xar_fallback()?;
                        } else {
                            println!("No file path available for xar fallback, extraction failed");
                            return Err("Cannot extract package: both apple-flat-package and root component extraction failed, and no file path for xar fallback".into());
                        }
                    }
                }
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
                println!("Component Package:");
                println!("  Identifier: {}", package_info.identifier);
                println!("  Files: {}", payload.number_of_files);
                println!("  Install KB: {}", payload.install_kbytes);
                debug!("Component Package:");
                debug!("  Identifier: {}", package_info.identifier);
                debug!("  Files: {}", payload.number_of_files);
                debug!("  Install KB: {}", payload.install_kbytes);
            }
        }

        // Extract payload
        println!("Getting payload reader...");
        if let Ok(Some(mut payload_reader)) = component_pkg_reader.payload_reader() {
            println!("Got payload reader, starting extraction...");
            let mut total_bytes = 0;

            // Read each entry from the CPIO archive
            let mut file_count = 0;
            while let Ok(Some(header)) = payload_reader.read_next() {
                let name = header.name();
                let file_size = header.file_size();
                let mode = header.mode();
                file_count += 1;

                if file_count <= 10 || file_count % 100 == 0 {
                    println!("Processing file {}: {} (size: {} bytes)", file_count, name, file_size);
                }

                // Skip the "Payload" directory itself and empty paths
                if name.is_empty() || name == "." || name == "Payload" {
                    payload_reader.finish()?;
                    continue;
                }

                // Remove "Payload/" prefix if present
                let clean_name = name.strip_prefix("Payload/").unwrap_or(name);
                let target_path = self.output_dir.join(clean_name);

                if file_count <= 10 {
                    println!(
                        "Extracting: {} -> {} (size: {} bytes, mode: {:o})",
                        clean_name, target_path.display(), file_size, mode
                    );
                }
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

            println!("Extracted {} files, {} bytes total", file_count, total_bytes);
            debug!("Extracted {} bytes total", total_bytes);
        } else {
            println!("Failed to get payload reader!");
        }

        Ok(())
    }

    /// Fallback extraction method using system xar command
    fn extract_with_xar_fallback(&self) -> Result<(), Box<dyn Error>> {
        // If we don't have a file path, we need to create a temporary file
        let pkg_path = if let Some(path) = &self.pkg_file_path {
            path.clone()
        } else {
            // Read data from reader and write to temp file
            println!("No file path available, creating temporary file for xar extraction...");
            let temp_file = tempfile::NamedTempFile::new()?;
            let temp_path = temp_file.path().to_path_buf();
            
            // We now save the data to a temp file before starting extraction,
            // so this should not happen anymore
            return Err("No file path available for xar fallback".into());
        };

        println!("Attempting xar fallback extraction...");
        
        // Create a temporary directory for xar extraction
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        // First, list all components in the package
        let list_output = Command::new("xar")
            .args(&["-tf", &pkg_path.to_string_lossy()])
            .output()?;
            
        if !list_output.status.success() {
            return Err(format!("Failed to list package contents: {}", 
                String::from_utf8_lossy(&list_output.stderr)).into());
        }
        
        let contents = String::from_utf8_lossy(&list_output.stdout);
        let component_names: Vec<&str> = contents.lines()
            .filter(|line| line.ends_with(".pkg") && !line.contains("/"))
            .collect();
            
        println!("Found {} components in package", component_names.len());
        for name in &component_names {
            println!("  - {}", name);
        }
        
        // Extract each component individually to handle partial failures
        for component_name in &component_names {
            println!("Extracting component: {}", component_name);
            let output = Command::new("xar")
                .args(&["-xf", &pkg_path.to_string_lossy(), component_name])
                .current_dir(temp_path)
                .output()?;
                
            if !output.status.success() {
                println!("Failed to extract {}: {}", component_name, 
                        String::from_utf8_lossy(&output.stderr));
                println!("Continuing with next component...");
            } else {
                println!("Successfully extracted {}", component_name);
            }
        }

        println!("xar extraction completed, processing component packages...");

        // Find all .pkg directories (component packages)
        let entries = fs::read_dir(temp_path)?;
        let mut extracted_files = 0;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() && path.extension().map_or(false, |e| e == "pkg") {
                println!("Processing component: {}", path.file_name().unwrap().to_string_lossy());
                
                // Extract payload from this component
                let payload_path = path.join("Payload");
                if payload_path.exists() {
                    match self.extract_payload_file(&payload_path) {
                        Ok(files_extracted) => {
                            extracted_files += files_extracted;
                            println!("Extracted {} files from {}", files_extracted, 
                                    path.file_name().unwrap().to_string_lossy());
                        }
                        Err(e) => {
                            println!("Failed to extract payload from {}: {}", 
                                    path.file_name().unwrap().to_string_lossy(), e);
                            println!("Continuing with other components...");
                        }
                    }
                }
            }
        }

        println!("Total files extracted via xar fallback: {}", extracted_files);
        Ok(())
    }

    /// Extract a single payload file (can be gzipped cpio or pbzx format)
    fn extract_payload_file(&self, payload_path: &std::path::Path) -> Result<usize, Box<dyn Error>> {
        
        println!("Extracting payload: {}", payload_path.display());
        
        // Check the payload format by reading the first few bytes
        let mut file = File::open(payload_path)?;
        let mut header = [0u8; 4];
        file.read_exact(&mut header)?;
        drop(file); // Close the file before reopening
        
        if &header == b"pbzx" {
            println!("Detected pbzx format, trying pure Rust extraction first");
            
            // Try pure Rust implementation first
            let file = File::open(payload_path)?;
            match pbzx::PbzxReader::new(file) {
                Ok(mut pbzx_reader) => {
                    let mut decompressed_cpio = Vec::new();
                    match pbzx_reader.decompress_to(&mut decompressed_cpio) {
                        Ok(_) => {
                            println!("Pure Rust pbzx extraction succeeded, {} bytes", decompressed_cpio.len());
                            
                            // Extract the cpio archive
                            let cursor = Cursor::new(decompressed_cpio);
                            let mut cpio_reader = OdcReader::new(cursor);
                            
                            let mut file_count = 0;
                            while let Some(entry) = cpio_reader.read_next()? {
                                let path = entry.name();
                                
                                // Skip special entries
                                if path == "." || path == "TRAILER!!!" || path.is_empty() {
                                    continue;
                                }
                                
                                let target_path = self.output_dir.join(path);
                                
                                // Create parent directories
                                if let Some(parent) = target_path.parent() {
                                    fs::create_dir_all(parent)?;
                                }
                                
                                // Check file type
                                let mode = entry.mode();
                                if mode & 0o170000 == 0o040000 {
                                    // Directory
                                    fs::create_dir_all(&target_path)?;
                                } else if mode & 0o170000 == 0o100000 {
                                    // Regular file
                                    let mut file = File::create(&target_path)?;
                                    let mut content = Vec::new();
                                    cpio_reader.read_to_end(&mut content)?;
                                    file.write_all(&content)?;
                                    file_count += 1;
                                    
                                    if file_count <= 10 || file_count % 1000 == 0 {
                                        println!("Extracted file {}: {}", file_count, path);
                                    }
                                }
                            }
                            
                            println!("Extracted {} files from cpio archive", file_count);
                            return Ok(file_count);
                        }
                        Err(e) => {
                            println!("Pure Rust pbzx extraction failed: {}", e);
                            println!("Falling back to pbzx command-line tool...");
                        }
                    }
                }
                Err(e) => {
                    println!("Failed to create pbzx reader: {}", e);
                    println!("Falling back to pbzx command-line tool...");
                }
            }
            
            // Fallback to shell command
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("cd '{}' && pbzx -n '{}' | cpio -idm", 
                            self.output_dir.display(), 
                            payload_path.display()))
                .output()?;

            if output.status.success() {
                // Count extracted files
                let file_count = self.count_files_recursive(&self.output_dir)?;
                println!("Shell pbzx extraction succeeded, {} files", file_count);
                Ok(file_count)
            } else {
                println!("Shell pbzx extraction failed: {}", String::from_utf8_lossy(&output.stderr));
                Ok(0)
            }
        } else {
            println!("Detected legacy format, using gzip + cpio extraction");
            
            // Try legacy gzipped cpio format using pure Rust
            let file = File::open(payload_path)?;
            let gz_decoder = libflate::gzip::Decoder::new(file)?;
            let mut cpio_reader = OdcReader::new(gz_decoder);
            
            let mut file_count = 0;
            while let Some(entry) = cpio_reader.read_next()? {
                let path = entry.name();
                
                // Skip special entries
                if path == "." || path == "TRAILER!!!" || path.is_empty() {
                    continue;
                }
                
                let target_path = self.output_dir.join(path);
                
                // Create parent directories
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                // Check file type
                let mode = entry.mode();
                if mode & 0o170000 == 0o040000 {
                    // Directory
                    fs::create_dir_all(&target_path)?;
                } else if mode & 0o170000 == 0o100000 {
                    // Regular file
                    let mut file = File::create(&target_path)?;
                    let mut content = Vec::new();
                    cpio_reader.read_to_end(&mut content)?;
                    file.write_all(&content)?;
                    file_count += 1;
                }
            }
            
            println!("Extracted {} files from gzipped cpio archive", file_count);
            Ok(file_count)
        }
    }

    /// Recursively count files in a directory
    fn count_files_recursive(&self, dir: &std::path::Path) -> Result<usize, Box<dyn Error>> {
        let mut count = 0;
        if dir.exists() {
            for entry in WalkDir::new(dir) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}
