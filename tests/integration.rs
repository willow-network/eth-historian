//! End-to-end integration tests against real Portal Network fixtures.
//!
//! Uses `HeaderWithProof` SSZ byte payloads checked into
//! `tests/fixtures/`, sourced from
//! [`portal-spec-tests`](https://github.com/ethereum/portal-spec-tests).
//! These are the exact bytes a real `trin` sidecar would return for
//! these blocks, so a passing test here means the verifier handles
//! production data correctly.
//!
//! Coverage:
//! * Block 1,000,010 — pre-merge (HistoricalHashes)
//! * Block 15,539,558 — post-merge / pre-Capella (HistoricalRoots)
//! * Block 15,555,729 — post-merge / pre-Capella (HistoricalRoots)

use eth_historian::{AuthPath, HeaderWithProof, Verifier};
use ethportal_api::consensus::historical_summaries::HistoricalSummaries;
use ssz::Decode;

const FIXTURE_PRE_MERGE: &str = include_str!("fixtures/header_with_proof_1000010.hex");
const FIXTURE_MERGE_CAPELLA_1: &str = include_str!("fixtures/header_with_proof_15539558.hex");
const FIXTURE_MERGE_CAPELLA_2: &str = include_str!("fixtures/header_with_proof_15555729.hex");
const FIXTURE_CAPELLA_FIRST: &str = include_str!("fixtures/header_with_proof_17034870.hex");
const FIXTURE_CAPELLA_2: &str = include_str!("fixtures/header_with_proof_17042287.hex");
const FIXTURE_PRE_DENEB_LAST: &str = include_str!("fixtures/header_with_proof_19426586.hex");
const FIXTURE_DENEB_FIRST: &str = include_str!("fixtures/header_with_proof_19426587.hex");
const FIXTURE_DENEB_LATER: &str = include_str!("fixtures/header_with_proof_22162263.hex");

const HISTORICAL_SUMMARIES_SLOT_11476992: &[u8] =
    include_bytes!("fixtures/historical_summaries_at_slot_11476992.ssz");

fn decode_fixture(s: &str) -> Vec<u8> {
    hex::decode(s.trim().trim_start_matches("0x")).expect("fixture should be valid hex")
}

fn load_historical_summaries() -> HistoricalSummaries {
    HistoricalSummaries::from_ssz_bytes(HISTORICAL_SUMMARIES_SLOT_11476992)
        .expect("historical_summaries snapshot should SSZ-decode")
}

fn capella_verifier() -> Verifier {
    Verifier::builder()
        .historical_summaries(load_historical_summaries())
        .build()
}

#[tokio::test]
async fn pre_merge_real_block_verifies() {
    let bytes = decode_fixture(FIXTURE_PRE_MERGE);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes)
        .expect("portal-spec-tests fixture should SSZ-decode");

    assert_eq!(
        hwp.header.number, 1_000_010,
        "fixture is for block 1,000,010"
    );

    let verifier = Verifier::new();
    let verified = verifier
        .verify(&hwp)
        .await
        .expect("verification of a real pre-merge HeaderWithProof should succeed");

    assert_eq!(verified.header.number, 1_000_010);
    assert_eq!(
        verified.auth_path,
        AuthPath::HistoricalHashes,
        "pre-merge block must authenticate via HistoricalHashes"
    );
}

#[tokio::test]
async fn merge_to_capella_real_block_15539558_verifies() {
    let bytes = decode_fixture(FIXTURE_MERGE_CAPELLA_1);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes)
        .expect("portal-spec-tests fixture should SSZ-decode");

    assert_eq!(hwp.header.number, 15_539_558);

    let verifier = Verifier::new();
    let verified = verifier
        .verify(&hwp)
        .await
        .expect("verification of a real merge-to-Capella HeaderWithProof should succeed");

    assert_eq!(verified.header.number, 15_539_558);
    assert_eq!(
        verified.auth_path,
        AuthPath::HistoricalRoots,
        "post-merge / pre-Capella block must authenticate via HistoricalRoots"
    );
}

#[tokio::test]
async fn merge_to_capella_real_block_15555729_verifies() {
    let bytes = decode_fixture(FIXTURE_MERGE_CAPELLA_2);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes)
        .expect("portal-spec-tests fixture should SSZ-decode");

    assert_eq!(hwp.header.number, 15_555_729);

    let verifier = Verifier::new();
    let verified = verifier
        .verify(&hwp)
        .await
        .expect("verification of a real merge-to-Capella HeaderWithProof should succeed");

    assert_eq!(verified.header.number, 15_555_729);
    assert_eq!(verified.auth_path, AuthPath::HistoricalRoots);
}

#[tokio::test]
async fn capella_real_block_17034870_verifies() {
    let bytes = decode_fixture(FIXTURE_CAPELLA_FIRST);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).expect("Capella fixture should SSZ-decode");
    assert_eq!(
        hwp.header.number, 17_034_870,
        "first Capella block (Apr 12, 2023)"
    );

    let verifier = capella_verifier();
    let verified = verifier
        .verify(&hwp)
        .await
        .expect("first-Capella block must verify against HistoricalSummaries");

    assert_eq!(verified.header.number, 17_034_870);
    assert_eq!(
        verified.auth_path,
        AuthPath::HistoricalSummariesCapella,
        "Capella-era block must authenticate via HistoricalSummariesCapella"
    );
}

#[tokio::test]
async fn capella_real_block_17042287_verifies() {
    let bytes = decode_fixture(FIXTURE_CAPELLA_2);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(hwp.header.number, 17_042_287);

    let verifier = capella_verifier();
    let verified = verifier.verify(&hwp).await.unwrap();
    assert_eq!(verified.auth_path, AuthPath::HistoricalSummariesCapella);
}

#[tokio::test]
async fn pre_deneb_real_block_19426586_verifies() {
    let bytes = decode_fixture(FIXTURE_PRE_DENEB_LAST);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(
        hwp.header.number, 19_426_586,
        "last pre-Deneb block (Mar 13, 2024)"
    );

    let verifier = capella_verifier();
    let verified = verifier.verify(&hwp).await.unwrap();
    assert_eq!(
        verified.auth_path,
        AuthPath::HistoricalSummariesCapella,
        "still pre-Deneb so still HistoricalSummariesCapella"
    );
}

#[tokio::test]
async fn deneb_real_block_19426587_verifies() {
    let bytes = decode_fixture(FIXTURE_DENEB_FIRST);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(hwp.header.number, 19_426_587, "first Deneb block");

    let verifier = capella_verifier();
    let verified = verifier.verify(&hwp).await.unwrap();
    assert_eq!(
        verified.auth_path,
        AuthPath::HistoricalSummariesDeneb,
        "post-Cancun-activation block must authenticate via HistoricalSummariesDeneb"
    );
}

#[tokio::test]
async fn deneb_real_block_22162263_verifies() {
    let bytes = decode_fixture(FIXTURE_DENEB_LATER);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();
    assert_eq!(hwp.header.number, 22_162_263);

    let verifier = capella_verifier();
    let verified = verifier.verify(&hwp).await.unwrap();
    assert_eq!(verified.auth_path, AuthPath::HistoricalSummariesDeneb);
}

#[tokio::test]
async fn capella_block_fails_without_historical_summaries() {
    // Without supplying a HistoricalSummaries snapshot, post-Capella
    // verification must fail — there's no other way to authenticate.
    let bytes = decode_fixture(FIXTURE_CAPELLA_FIRST);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();
    let verifier = Verifier::new(); // no historical_summaries
    let result = verifier.verify(&hwp).await;
    assert!(
        result.is_err(),
        "Capella verification without HS snapshot must fail"
    );
}

#[tokio::test]
async fn tampered_bytes_rejected() {
    let mut bytes = decode_fixture(FIXTURE_PRE_MERGE);
    let mut hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();
    // Corrupt the first byte of the proof — flips the merkle path.
    if let eth_historian::BlockHeaderProof::HistoricalHashes(ref mut proof) = hwp.proof {
        let mut bs = proof[0].0;
        bs[0] ^= 0xff;
        proof[0] = bs.into();
    } else {
        panic!("fixture should have HistoricalHashes proof");
    }

    let verifier = Verifier::new();
    let result = verifier.verify(&hwp).await;
    assert!(
        result.is_err(),
        "verifier must reject a tampered proof, but got: {:?}",
        result
    );

    // Quiet the unused-mut warning when the test passes.
    let _ = bytes.pop();
}
