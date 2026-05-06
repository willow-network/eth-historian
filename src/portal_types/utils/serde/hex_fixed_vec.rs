//! Serialize `FixedVector<u8, N>` as 0x-prefixed hex string.
//!
//! Source: trin `30aeef8`, `crates/ethportal-api/src/utils/serde/hex_fixed_vec.rs`.

use serde::{Deserializer, Serializer};
use serde_utils::hex::PrefixedHexVisitor;
use ssz_types::{typenum::Unsigned, FixedVector};

use crate::portal_types::utils::bytes::hex_encode;

pub fn serialize<S, U>(bytes: &FixedVector<u8, U>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    U: Unsigned,
{
    serializer.serialize_str(&hex_encode(&bytes[..]))
}

pub fn deserialize<'de, D, U>(deserializer: D) -> Result<FixedVector<u8, U>, D::Error>
where
    D: Deserializer<'de>,
    U: Unsigned,
{
    let vec = deserializer.deserialize_string(PrefixedHexVisitor)?;
    FixedVector::new(vec)
        .map_err(|e| serde::de::Error::custom(format!("invalid fixed vector: {e:?}")))
}
