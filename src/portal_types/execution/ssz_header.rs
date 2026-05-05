//! Custom SSZ codec for `alloy::consensus::Header` — RLP-encoded
//! header bytes wrapped in an SSZ `ByteList[2048]`.
//!
//! Used as `#[ssz(with = "ssz_header")]` on `HeaderWithProof::header`.
//! Source: trin `30aeef8`, `crates/ethportal-api/src/types/execution/ssz_header.rs`.

use crate::portal_types::byte_list::ByteList2048;

pub mod encode {
    use alloy::consensus::Header;
    use ssz::Encode;

    use super::*;

    pub fn is_ssz_fixed_len() -> bool {
        ByteList2048::is_ssz_fixed_len()
    }

    pub fn ssz_append(header: &Header, buf: &mut Vec<u8>) {
        let header = alloy::rlp::encode(header);
        ByteList2048::from(header).ssz_append(buf);
    }

    pub fn ssz_fixed_len() -> usize {
        ByteList2048::ssz_fixed_len()
    }

    pub fn ssz_bytes_len(header: &Header) -> usize {
        // The SSZ encoded length is the same as RLP encoded length.
        alloy_rlp::Encodable::length(header)
    }
}

pub mod decode {
    use alloy::consensus::Header;
    use alloy_rlp::Decodable;
    use ssz::Decode;

    use super::*;

    pub fn is_ssz_fixed_len() -> bool {
        ByteList2048::is_ssz_fixed_len()
    }

    pub fn ssz_fixed_len() -> usize {
        ByteList2048::ssz_fixed_len()
    }

    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Header, ssz::DecodeError> {
        let rlp_encoded_header = ByteList2048::from_ssz_bytes(bytes)?;
        Header::decode(&mut &*rlp_encoded_header).map_err(|_| {
            ssz::DecodeError::BytesInvalid("Unable to decode bytes into header.".to_string())
        })
    }
}
