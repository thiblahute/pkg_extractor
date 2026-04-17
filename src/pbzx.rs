// Copyright (C) 2026 Thibault Saunier <tsaunier@igalia.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal decoder for the `pbzx` streaming format used inside Apple `.pkg`
//! component payloads. Layout:
//!
//! ```text
//! magic:          4 bytes, literal "pbzx"
//! block_size:     8 bytes, big-endian (advisory hint, typically 0x01000000)
//! repeated chunks, until EOF:
//!     uncompressed_size: 8 bytes, big-endian
//!     compressed_size:   8 bytes, big-endian
//!     chunk_data:        compressed_size bytes
//! ```
//!
//! A chunk is xz-compressed when `compressed_size < uncompressed_size`; when
//! they are equal the chunk is stored verbatim. There is no in-band end-of-
//! stream marker — the last chunk is simply the one whose read hits EOF.

use liblzma::read::XzDecoder;
use log::{debug, info};
use std::io::{Cursor, Read, Write};

pub struct PbzxReader<R: Read> {
    reader: R,
}

impl<R: Read> PbzxReader<R> {
    pub fn new(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"pbzx" {
            return Err("Not a valid pbzx stream".into());
        }

        // Advisory block-size header; not needed for decoding since each
        // chunk carries its own sizes.
        let mut block_size_bytes = [0u8; 8];
        reader.read_exact(&mut block_size_bytes)?;
        debug!(
            "pbzx stream, advisory block size: {:#x}",
            u64::from_be_bytes(block_size_bytes)
        );

        Ok(Self { reader })
    }

    pub fn decompress_to<W: Write>(
        &mut self,
        output: &mut W,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut total_chunks = 0usize;
        let mut total_bytes = 0usize;

        loop {
            let mut uncompressed_size_bytes = [0u8; 8];
            match self.reader.read_exact(&mut uncompressed_size_bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let uncompressed_size = u64::from_be_bytes(uncompressed_size_bytes);

            let mut compressed_size_bytes = [0u8; 8];
            self.reader.read_exact(&mut compressed_size_bytes)?;
            let compressed_size = u64::from_be_bytes(compressed_size_bytes);

            let mut chunk_data = vec![0u8; compressed_size as usize];
            self.reader.read_exact(&mut chunk_data)?;

            debug!(
                "chunk {}: uncompressed={} compressed={}",
                total_chunks + 1,
                uncompressed_size,
                compressed_size
            );

            if compressed_size < uncompressed_size {
                let mut decoder = XzDecoder::new(Cursor::new(chunk_data));
                let mut decompressed = Vec::with_capacity(uncompressed_size as usize);
                decoder.read_to_end(&mut decompressed)?;
                output.write_all(&decompressed)?;
                total_bytes += decompressed.len();
            } else {
                output.write_all(&chunk_data)?;
                total_bytes += chunk_data.len();
            }

            total_chunks += 1;
        }

        info!("decoded {} chunks, {} bytes", total_chunks, total_bytes);
        Ok(())
    }
}
