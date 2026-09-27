use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use eth_historian::{sources::DataSource, BlockHeaderProof, HeaderWithProof, Verifier};
use ssz::{Decode, Encode};

struct StaticSource {
    name: &'static str,
    bytes: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl StaticSource {
    fn new(name: &'static str, bytes: Vec<u8>) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                name,
                bytes,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

#[async_trait]
impl DataSource for StaticSource {
    async fn fetch_header_with_proof_by_number(
        &self,
        _block_number: u64,
    ) -> eth_historian::errors::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.bytes.clone())
    }

    async fn fetch_header_with_proof_by_hash(
        &self,
        _block_hash: [u8; 32],
    ) -> eth_historian::errors::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.bytes.clone())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

fn valid_fixture() -> (Vec<u8>, alloy::primitives::B256) {
    let bytes = hex::decode(
        include_str!("fixtures/header_with_proof_1000010.hex")
            .trim()
            .trim_start_matches("0x"),
    )
    .expect("fixture should be valid hex");
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).expect("fixture should decode");
    (bytes, hwp.header.hash_slow())
}

fn tampered_fixture() -> Vec<u8> {
    let (bytes, _) = valid_fixture();
    let mut hwp = HeaderWithProof::from_ssz_bytes(&bytes).expect("fixture should decode");

    if let BlockHeaderProof::HistoricalHashes(ref mut proof) = hwp.proof {
        let mut node = proof[0].0;
        node[0] ^= 0xff;
        proof[0] = node.into();
    } else {
        panic!("fixture should use the HistoricalHashes proof path");
    }

    hwp.as_ssz_bytes()
}

async fn assert_number_fallback(first_response: Vec<u8>) {
    let (valid, _) = valid_fixture();
    let (first, first_calls) = StaticSource::new("first", first_response);
    let (fallback, fallback_calls) = StaticSource::new("fallback", valid);
    let verifier = Verifier::builder()
        .data_source(first)
        .data_source(fallback)
        .build();

    let verified = verifier
        .verify_block_by_number(1_000_010)
        .await
        .expect("the valid fallback source should be tried");

    assert_eq!(verified.header.number, 1_000_010);
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
}

async fn assert_hash_fallback(first_response: Vec<u8>) {
    let (valid, block_hash) = valid_fixture();
    let (first, first_calls) = StaticSource::new("first", first_response);
    let (fallback, fallback_calls) = StaticSource::new("fallback", valid);
    let verifier = Verifier::builder()
        .data_source(first)
        .data_source(fallback)
        .build();

    let verified = verifier
        .verify_block_by_hash(block_hash)
        .await
        .expect("the valid fallback source should be tried");

    assert_eq!(verified.header.hash_slow(), block_hash);
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_number_response_falls_back_to_next_source() {
    assert_number_fallback(vec![0xff]).await;
}

#[tokio::test]
async fn malformed_hash_response_falls_back_to_next_source() {
    assert_hash_fallback(vec![0xff]).await;
}

#[tokio::test]
async fn unverifiable_number_response_falls_back_to_next_source() {
    assert_number_fallback(tampered_fixture()).await;
}

#[tokio::test]
async fn unverifiable_hash_response_falls_back_to_next_source() {
    assert_hash_fallback(tampered_fixture()).await;
}
