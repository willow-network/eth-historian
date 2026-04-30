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

use eth_historian::{
    proof_construction::{construct_pre_merge_proof, decode_epoch_accumulator},
    AuthPath, BlockHeaderProof, HeaderWithProof, Verifier,
};
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
const EPOCH_RECORD_122: &[u8] = include_bytes!("fixtures/epoch-record-00122.ssz");

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
async fn construct_proof_round_trip() {
    // Round-trip proof construction → verification on a real
    // pre-merge block:
    //
    //   1. Decode the EpochAccumulator for epoch 122 (blocks
    //      999,424 .. 1,007,615, ssz_root 0x5ec1ff…b4218).
    //   2. Take the header for block 1,000,010 from a Portal
    //      HeaderWithProof fixture (which already includes a known
    //      valid proof; we ignore that proof and build our own).
    //   3. Call construct_pre_merge_proof(header, &epoch_acc).
    //   4. Wrap the constructed proof in a HeaderWithProof and feed
    //      it to the Verifier.
    //   5. Assert the verifier accepts it.
    //
    // This proves the construct→verify pipeline is consistent: a
    // proof we generate locally validates against the same canonized
    // accumulator the verifier checks against.
    let epoch_acc = decode_epoch_accumulator(EPOCH_RECORD_122)
        .expect("epoch_acc fixture should SSZ-decode");

    let original_bytes = decode_fixture(FIXTURE_PRE_MERGE);
    let original_hwp = HeaderWithProof::from_ssz_bytes(&original_bytes).unwrap();
    let header = original_hwp.header.clone();

    let constructed_proof = construct_pre_merge_proof(&header, &epoch_acc)
        .expect("proof construction should succeed for a canonical pre-merge header");

    let our_hwp = HeaderWithProof {
        header,
        proof: BlockHeaderProof::HistoricalHashes(constructed_proof),
    };

    let verifier = Verifier::new();
    let verified = verifier.verify(&our_hwp).await.expect(
        "locally-constructed proof must verify against the canonized accumulator",
    );
    assert_eq!(verified.header.number, 1_000_010);
    assert_eq!(verified.auth_path, AuthPath::HistoricalHashes);
}

#[cfg(feature = "portal-sidecar")]
mod portal_sidecar_mock_tests {
    use super::*;
    use eth_historian::sources::PortalSidecarSource;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// `verify_block_by_number(1_000_010)` against a wiremock'd Portal
    /// sidecar that returns the real fixture bytes — proves the
    /// JSON-RPC plumbing + content-key encoding + SSZ-decode + verify
    /// chain all line up end-to-end against production data, without
    /// needing a real trin process.
    #[tokio::test]
    async fn portal_sidecar_happy_path_verifies() {
        let mock_server = MockServer::start().await;

        let fixture_hex_no_prefix = FIXTURE_PRE_MERGE
            .trim()
            .trim_start_matches("0x")
            .to_string();

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": format!("0x{}", fixture_hex_no_prefix),
                    "utpTransfer": false,
                }
            })))
            .mount(&mock_server)
            .await;

        let source = PortalSidecarSource::new(mock_server.uri()).unwrap();
        let verifier = Verifier::builder().data_source(source).build();

        let verified = verifier.verify_block_by_number(1_000_010).await.unwrap();
        assert_eq!(verified.header.number, 1_000_010);
        assert_eq!(verified.auth_path, AuthPath::HistoricalHashes);
    }

    /// JSON-RPC error from the sidecar must propagate as
    /// `Error::DataSource`, not panic and not silently succeed.
    #[tokio::test]
    async fn portal_sidecar_rpc_error_surfaces() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32000, "message": "content not found in DHT" }
            })))
            .mount(&mock_server)
            .await;

        let source = PortalSidecarSource::new(mock_server.uri()).unwrap();
        let verifier = Verifier::builder().data_source(source).build();

        let err = verifier.verify_block_by_number(10_000_835).await.unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "RPC error message should be surfaced; got: {}",
            err
        );
    }

    /// Tampered bytes returned by the sidecar must be rejected by the
    /// verifier — Portal is treated as a content router only, never
    /// trusted to attest correctness.
    #[tokio::test]
    async fn portal_sidecar_tampered_response_rejected() {
        let mock_server = MockServer::start().await;

        let mut bytes = decode_fixture(FIXTURE_PRE_MERGE);
        // Flip a byte deep inside the proof region (after the SSZ
        // header, after the alloy::Header bytes — anywhere in the
        // proof tail).
        let len = bytes.len();
        bytes[len - 100] ^= 0xff;
        let tampered_hex = hex::encode(&bytes);

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "content": format!("0x{}", tampered_hex), "utpTransfer": false }
            })))
            .mount(&mock_server)
            .await;

        let source = PortalSidecarSource::new(mock_server.uri()).unwrap();
        let verifier = Verifier::builder().data_source(source).build();

        let result = verifier.verify_block_by_number(1_000_010).await;
        assert!(
            result.is_err(),
            "verifier must reject tampered Portal response, got: {:?}",
            result
        );
    }

    /// Multi-source fallback: first source errors, second source
    /// succeeds, verifier should return the second's result.
    #[tokio::test]
    async fn multi_source_fallback() {
        let bad_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&bad_server)
            .await;

        let good_server = MockServer::start().await;
        let fixture_hex = FIXTURE_PRE_MERGE.trim().trim_start_matches("0x").to_string();
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "content": format!("0x{}", fixture_hex), "utpTransfer": false }
            })))
            .mount(&good_server)
            .await;

        let verifier = Verifier::builder()
            .data_source(PortalSidecarSource::new(bad_server.uri()).unwrap())
            .data_source(PortalSidecarSource::new(good_server.uri()).unwrap())
            .build();

        let verified = verifier.verify_block_by_number(1_000_010).await.unwrap();
        assert_eq!(verified.header.number, 1_000_010);
    }
}

#[tokio::test]
async fn construct_proof_rejects_wrong_epoch() {
    // If the caller hands us an EpochAccumulator that doesn't cover
    // the header's block number, construction must fail loudly — never
    // silently produce an invalid proof.
    let epoch_acc =
        decode_epoch_accumulator(EPOCH_RECORD_122).expect("epoch_acc decode");

    // Block 15,539,558 belongs to epoch 1897, not 122. The header.hash
    // won't match epoch[122][index 1894 in the partial range], so
    // construct_pre_merge_proof should error.
    let bytes = decode_fixture(FIXTURE_MERGE_CAPELLA_1);
    let hwp = HeaderWithProof::from_ssz_bytes(&bytes).unwrap();

    let result = construct_pre_merge_proof(&hwp.header, &epoch_acc);
    assert!(
        result.is_err(),
        "proof construction must reject a header that doesn't match the supplied epoch"
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
