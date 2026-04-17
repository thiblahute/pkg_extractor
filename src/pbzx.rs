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

#[cfg(test)]
mod tests {
    use super::*;
    use liblzma::write::XzEncoder;

    /// Build a pbzx stream containing one chunk per `(uncompressed, compressed)`
    /// pair. Pass `compressed == uncompressed` for verbatim chunks, or a
    /// shorter buffer (e.g. xz-encoded output) for compressed chunks.
    fn build(chunks: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"pbzx");
        out.extend_from_slice(&0x0100_0000u64.to_be_bytes());
        for (uncomp, comp) in chunks {
            out.extend_from_slice(&(uncomp.len() as u64).to_be_bytes());
            out.extend_from_slice(&(comp.len() as u64).to_be_bytes());
            out.extend_from_slice(comp);
        }
        out
    }

    fn decode(stream: &[u8]) -> Vec<u8> {
        let mut reader = PbzxReader::new(Cursor::new(stream)).expect("valid pbzx header");
        let mut out = Vec::new();
        reader.decompress_to(&mut out).expect("decode succeeds");
        out
    }

    fn xz_encode(data: &[u8]) -> Vec<u8> {
        let mut enc = XzEncoder::new(Vec::new(), 6);
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn rejects_non_pbzx_magic() {
        let mut bytes = b"XXXX".to_vec();
        bytes.extend_from_slice(&0u64.to_be_bytes());
        assert!(PbzxReader::new(Cursor::new(bytes)).is_err());
    }

    #[test]
    fn decodes_empty_stream() {
        let stream = build(&[]);
        assert_eq!(decode(&stream), Vec::<u8>::new());
    }

    #[test]
    fn decodes_single_verbatim_chunk() {
        let payload = b"hello world".as_slice();
        let stream = build(&[(payload, payload)]);
        assert_eq!(decode(&stream), payload);
    }

    #[test]
    fn decodes_multiple_verbatim_chunks() {
        let stream = build(&[
            (b"first ".as_slice(), b"first ".as_slice()),
            (b"second ".as_slice(), b"second ".as_slice()),
            (b"third".as_slice(), b"third".as_slice()),
        ]);
        assert_eq!(decode(&stream), b"first second third");
    }

    #[test]
    fn decodes_xz_compressed_chunk() {
        // Data compressible enough that `compressed < uncompressed`, which
        // triggers the xz-decode branch.
        let payload = vec![b'a'; 4096];
        let compressed = xz_encode(&payload);
        assert!(compressed.len() < payload.len(), "expected xz to shrink input");
        let stream = build(&[(payload.as_slice(), compressed.as_slice())]);
        assert_eq!(decode(&stream), payload);
    }

    #[test]
    fn decodes_tiny_chunk_that_old_bit24_check_would_drop() {
        // Regression guard for the previous reader: any chunk whose
        // uncompressed size was under 16 MiB (bit 24 clear) used to be
        // mistaken for an end-of-stream sentinel and the decoder would
        // return Ok with zero bytes.
        let payload = vec![0x42u8; 100];
        let stream = build(&[(payload.as_slice(), payload.as_slice())]);
        assert_eq!(decode(&stream), payload);
    }

    #[test]
    fn errors_on_truncated_chunk_header() {
        // Valid header, then an uncompressed-size byte but no compressed-
        // size or body. Must fail, not silently stop.
        let mut stream = Vec::new();
        stream.extend_from_slice(b"pbzx");
        stream.extend_from_slice(&0x0100_0000u64.to_be_bytes());
        stream.extend_from_slice(&0x10u64.to_be_bytes()); // uncompressed, no compressed/body
        let mut reader = PbzxReader::new(Cursor::new(stream)).unwrap();
        let mut out = Vec::new();
        assert!(reader.decompress_to(&mut out).is_err());
    }
}
