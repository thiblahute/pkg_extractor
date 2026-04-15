// Copyright (C) 2026 Thibault Saunier <tsaunier@igalia.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::{debug, info};
use std::io::{Cursor, Read, Write};
use liblzma::read::XzDecoder;

#[derive(Debug, Clone, Copy)]
enum CompressionAlgo {
    Xz,    // 'x'
    Zlib,  // 'z'
    Lz4,   // '4'
    Lzfse, // 'e'
}

impl CompressionAlgo {
    fn from_byte(b: u8) -> Result<Self, Box<dyn std::error::Error>> {
        match b {
            b'x' => Ok(CompressionAlgo::Xz),
            b'z' => Ok(CompressionAlgo::Zlib),
            b'4' => Ok(CompressionAlgo::Lz4),
            b'e' => Ok(CompressionAlgo::Lzfse),
            _ => Err(format!("Unknown compression algorithm: {}", b as char).into()),
        }
    }
}

pub struct PbzxReader<R: Read> {
    reader: R,
    compression_algo: CompressionAlgo,
    block_size: u64,
}

impl<R: Read> PbzxReader<R> {
    pub fn new(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Read and verify magic bytes
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        if &magic[0..3] != b"pbz" {
            return Err("Not a valid pbzx stream".into());
        }

        // The 4th byte indicates the compression algorithm
        let compression_algo = CompressionAlgo::from_byte(magic[3])?;

        // Read block size (was incorrectly called "flags" in original implementation)
        let mut block_size_bytes = [0u8; 8];
        reader.read_exact(&mut block_size_bytes)?;
        let block_size = u64::from_be_bytes(block_size_bytes);

        debug!(
            "Found pbzx magic with compression: {:?}, block size: {}",
            compression_algo, block_size
        );

        Ok(Self {
            reader,
            compression_algo,
            block_size,
        })
    }

    pub fn decompress_to<W: Write>(
        &mut self,
        output: &mut W,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut total_chunks = 0;
        let mut total_bytes = 0;

        loop {
            // Read uncompressed size
            let mut uncompressed_size_bytes = [0u8; 8];
            match self.reader.read_exact(&mut uncompressed_size_bytes) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Reached end of pbzx stream (possibly truncated)");
                    break;
                }
                Err(e) => {
                    debug!("Error reading uncompressed size: {}", e);
                    break; // Don't fail completely, just stop processing
                }
            }

            let uncompressed_size = u64::from_be_bytes(uncompressed_size_bytes);

            debug!("Read uncompressed_size: {:#x}", uncompressed_size);

            // Check if we should continue (bit 24 must be set in uncompressed_size)
            if (uncompressed_size & (1 << 24)) == 0 {
                debug!(
                    "End of chunks signaled (uncompressed_size: {:#x})",
                    uncompressed_size
                );
                break;
            }

            // Clear the flag bit to get actual uncompressed size
            // The actual size is in the lower bytes, but 0x1000000 means full block size
            let actual_uncompressed_size = if uncompressed_size == 0x1000000 {
                self.block_size // Use the block size from header
            } else {
                uncompressed_size & 0xFFFFFF
            };

            // Read compressed size
            let mut compressed_size_bytes = [0u8; 8];
            match self.reader.read_exact(&mut compressed_size_bytes) {
                Ok(_) => {}
                Err(e) => {
                    debug!("Error reading compressed size: {}", e);
                    break;
                }
            }
            let compressed_size = u64::from_be_bytes(compressed_size_bytes);

            debug!(
                "Processing chunk {} - uncompressed: {}, compressed: {}",
                total_chunks + 1,
                actual_uncompressed_size,
                compressed_size
            );

            // Read chunk data
            let mut chunk_data = vec![0u8; compressed_size as usize];
            match self.reader.read_exact(&mut chunk_data) {
                Ok(_) => {}
                Err(e) => {
                    debug!("Error reading chunk data: {}", e);
                    break;
                }
            }

            // Check if chunk is actually compressed (compressed size < uncompressed size)
            // or has XZ magic header
            let is_compressed = compressed_size < actual_uncompressed_size
                || (chunk_data.len() >= 6 && &chunk_data[0..6] == b"\xfd7zXZ\x00");

            if is_compressed {
                match self.compression_algo {
                    CompressionAlgo::Xz => {
                        debug!("Chunk {} is XZ compressed", total_chunks + 1);

                        // Decompress using XZ decoder
                        let mut decoder = XzDecoder::new(Cursor::new(chunk_data));
                        let mut decompressed = Vec::new();
                        decoder.read_to_end(&mut decompressed)?;

                        output.write_all(&decompressed)?;
                        total_bytes += decompressed.len();
                        debug!("Decompressed {} bytes", decompressed.len());
                    }
                    CompressionAlgo::Zlib => {
                        debug!("Chunk {} is Zlib compressed", total_chunks + 1);

                        // Decompress using zlib decoder (via libflate)
                        let mut decoder = libflate::zlib::Decoder::new(Cursor::new(chunk_data))?;
                        let mut decompressed = Vec::new();
                        decoder.read_to_end(&mut decompressed)?;

                        output.write_all(&decompressed)?;
                        total_bytes += decompressed.len();
                        debug!("Decompressed {} bytes", decompressed.len());
                    }
                    _ => {
                        return Err(format!(
                            "Unsupported compression algorithm: {:?}",
                            self.compression_algo
                        )
                        .into());
                    }
                }
            } else {
                debug!("Chunk {} is uncompressed", total_chunks + 1);

                // Write uncompressed data directly
                output.write_all(&chunk_data)?;
                total_bytes += chunk_data.len();
            }

            total_chunks += 1;
        }

        info!(
            "Processed {} chunks, {} total bytes",
            total_chunks, total_bytes
        );
        Ok(())
    }
}
