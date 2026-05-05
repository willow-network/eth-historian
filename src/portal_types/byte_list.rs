//! SSZ `ByteList[N]` type aliases.
//!
//! Source: trin `30aeef8`, `crates/ethportal-api/src/types/bytes.rs`.

use ssz_types::{typenum, VariableList};

pub type ByteList1024 = VariableList<u8, typenum::U1024>;
pub type ByteList2048 = VariableList<u8, typenum::U2048>;
