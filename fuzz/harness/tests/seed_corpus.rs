use std::{fs, path::PathBuf};

#[test]
fn committed_html_form_control_corpus_satisfies_the_semantic_oracle() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("corpus")
        .join("html_form_controls");
    let mut seeds: Vec<_> = fs::read_dir(&corpus)
        .expect("committed HTML seed corpus must exist")
        .map(|entry| entry.expect("seed directory entry must be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "html")
        })
        .collect();
    seeds.sort();

    assert!(seeds.len() >= 23, "semantic corpus unexpectedly shrank");
    for seed in seeds {
        let data = fs::read(&seed).expect("committed HTML seed must be readable");
        assert!(
            data.len() <= termivar_fuzz_harness::MAX_HTML_FUZZ_INPUT_BYTES,
            "seed exceeds the harness input bound: {}",
            seed.display()
        );
        termivar_fuzz_harness::check_html_form_controls(&data);
    }
}

#[test]
fn committed_expression_corpus_satisfies_the_semantic_oracle() {
    replay_json_corpus(
        "expression_semantics",
        13,
        termivar_fuzz_harness::MAX_SEMANTIC_FUZZ_INPUT_BYTES,
        termivar_fuzz_harness::check_expression_semantics,
    );
}

#[test]
fn committed_declarative_policy_corpus_satisfies_the_semantic_oracle() {
    replay_json_corpus(
        "declarative_policy_wire",
        22,
        termivar_fuzz_harness::MAX_SEMANTIC_FUZZ_INPUT_BYTES,
        termivar_fuzz_harness::check_declarative_policy_wire,
    );
}

#[test]
fn committed_decision_loop_authority_corpus_satisfies_the_semantic_oracle() {
    replay_json_corpus(
        "decision_loop_authority",
        14,
        termivar_fuzz_harness::MAX_AUTHORITY_FUZZ_INPUT_BYTES,
        termivar_fuzz_harness::check_decision_loop_authority,
    );
}

#[test]
fn bounded_decision_loop_authority_models_cover_numeric_edges() {
    for scenario in 0_u8..14 {
        for boundary in [0_u8, 1, 4, 63, 64, 99, 100, u8::MAX] {
            termivar_fuzz_harness::check_decision_loop_authority(&[
                scenario,
                boundary,
                u8::MAX - boundary,
                boundary,
                boundary,
                b'_',
                b'x',
            ]);
        }
    }
}

#[test]
fn bounded_openapi_regression_inputs_satisfy_the_semantic_oracle() {
    for seed in [
        &b""[..],
        &b"{"[..],
        &br#"{"openapi":"3.1.0","paths":{}}"#[..],
        &br#"{"openapi":"3.0.3","paths":{"/items/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}],"responses":{"200":{"content":{"application/json":{}}}}}}}}"#[..],
        &br#"{"openapi":"3.1.0","openapi":"3.0.3","paths":{}}"#[..],
        &br#"{"openapi":"3.1.0","servers":[{"url":"https://{tenant}.example.test","variables":{"tenant":{"default":"api"}}}],"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},"security":[{"bearer":[]}],"paths":{"/items":{"post":{"requestBody":{"content":{"application/problem+json":{}}},"responses":{"2XX":{},"default":{}}}}}}"#[..],
    ] {
        assert!(
            seed.len() <= termivar_fuzz_harness::MAX_OPENAPI_FUZZ_INPUT_BYTES,
            "OpenAPI regression seed exceeds the harness input bound"
        );
        termivar_fuzz_harness::check_openapi_review(seed);
    }
}

#[test]
fn bounded_oast_regression_inputs_satisfy_the_semantic_oracle() {
    for scenario in 0_u8..12 {
        for boundary in [0_u8, 1, 31, 32, 63, 64, 127, u8::MAX] {
            let seed = structured_oast_seed(scenario, boundary);
            assert_eq!(seed.len(), 80, "structured OAST seed shape drifted");
            assert!(seed[1..33].iter().any(|byte| *byte != 0));
            assert!(seed[33..65].iter().any(|byte| *byte != 0));
            assert_ne!(&seed[1..33], &seed[33..65]);
            assert!(seed.len() <= termivar_fuzz_harness::MAX_OAST_FUZZ_INPUT_BYTES);
            termivar_fuzz_harness::check_oast_correlation(&seed);
        }
    }
}

#[test]
fn bounded_native_oast_provider_models_cover_owned_seed_matrix() {
    let mut count = 0_usize;
    for scenario in 0_u8..12 {
        for boundary in [0_u8, 1, 31, 32, 63, 64, 127, u8::MAX] {
            let seed = structured_native_oast_seed(scenario, boundary);
            assert_eq!(seed.len(), 96, "structured native OAST seed shape drifted");
            assert!(seed.len() <= termivar_fuzz_harness::MAX_NATIVE_OAST_FUZZ_INPUT_BYTES);
            termivar_fuzz_harness::check_native_oast_provider(&seed);
            count += 1;
        }
    }
    assert_eq!(count, 96, "owned native OAST seed inventory drifted");
}

#[test]
fn bounded_native_oast_adapter_models_cover_owned_seed_matrix() {
    let mut count = 0_usize;
    for scenario in 0_u8..12 {
        for boundary in [0_u8, 1, 31, 32, 63, 64, 127, u8::MAX] {
            let seed = structured_native_oast_adapter_seed(scenario, boundary);
            assert_eq!(
                seed.len(),
                128,
                "structured native OAST adapter seed shape drifted"
            );
            assert!(seed.len() <= termivar_fuzz_harness::MAX_NATIVE_OAST_ADAPTER_FUZZ_INPUT_BYTES);
            termivar_fuzz_harness::check_native_oast_adapter(&seed);
            count += 1;
        }
    }
    assert_eq!(
        count, 96,
        "owned native OAST adapter seed inventory drifted"
    );
}

#[test]
fn bounded_ssrf_oast_review_models_cover_owned_seed_matrix() {
    let mut count = 0_usize;
    for scenario in 0_u8..16 {
        for boundary in [0_u8, 1, 31, 32, 63, 64, 127, u8::MAX] {
            let seed = structured_ssrf_oast_review_seed(scenario, boundary);
            assert_eq!(
                seed.len(),
                160,
                "structured SSRF/OAST review seed shape drifted"
            );
            assert!(seed.len() <= termivar_fuzz_harness::MAX_SSRF_OAST_FUZZ_INPUT_BYTES);
            termivar_fuzz_harness::check_ssrf_oast_review(&seed);
            count += 1;
        }
    }
    assert_eq!(count, 128, "owned SSRF/OAST review seed inventory drifted");
}

#[test]
fn owned_native_oast_route_and_bearer_seeds_use_production_contracts() {
    const SESSION_ID: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const CALLBACK_ID: &str = "AgICAgICAgICAgICAgICAg";

    let route_inputs = [
        "/v1/sessions".to_owned(),
        format!("/v1/sessions/{SESSION_ID}/callbacks"),
        format!("/v1/sessions/{SESSION_ID}/events?after=0"),
        format!("/v1/sessions/{SESSION_ID}/events?after=00"),
        format!("/v1/sessions/{SESSION_ID}/events?after=%30"),
        format!("/v1/sessions/{SESSION_ID}/events?after=0&extra=1"),
        format!("/c/{SESSION_ID}/{CALLBACK_ID}"),
        format!("/c/{SESSION_ID}/{CALLBACK_ID}?ignored=RAW-ROUTE-MUST-NOT-LEAK"),
        format!("/c/%41QEBAQEBAQEBAQEBAQEBAQ/{CALLBACK_ID}"),
        "https://provider.example.test/v1/sessions".to_owned(),
    ];
    let bearer_inputs: [(u8, &[u8]); 6] = [
        (0, b"Bearer FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"),
        (1, b"Bearer AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"),
        (0, b"bearer FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"),
        (0, b"Bearer  FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"),
        (1, b"Bearer AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw="),
        (1, b"Bearer\tSESSION-TOKEN-MUST-NOT-BE-ACCEPTED"),
    ];

    let mut count = 0_usize;
    for route in route_inputs {
        let seed = native_oast_seed(7, route.as_bytes());
        assert!(seed.len() <= termivar_fuzz_harness::MAX_NATIVE_OAST_FUZZ_INPUT_BYTES);
        termivar_fuzz_harness::check_native_oast_provider(&seed);
        count += 1;
    }
    for (selector, bearer) in bearer_inputs {
        let mut payload = Vec::with_capacity(bearer.len() + 1);
        payload.push(selector);
        payload.extend_from_slice(bearer);
        let seed = native_oast_seed(9, &payload);
        assert!(seed.len() <= termivar_fuzz_harness::MAX_NATIVE_OAST_FUZZ_INPUT_BYTES);
        termivar_fuzz_harness::check_native_oast_provider(&seed);
        count += 1;
    }

    assert_eq!(count, 16, "owned route/bearer seed inventory drifted");
}

fn structured_oast_seed(scenario: u8, boundary: u8) -> Vec<u8> {
    let mut seed = vec![0_u8; 80];
    seed[0] = scenario;
    for (index, byte) in seed[1..33].iter_mut().enumerate() {
        *byte = boundary
            .wrapping_add(scenario)
            .wrapping_add((index as u8).wrapping_mul(17));
    }
    for (index, byte) in seed[33..65].iter_mut().enumerate() {
        *byte = boundary
            .wrapping_mul(3)
            .wrapping_add(scenario.wrapping_mul(11))
            .wrapping_add((index as u8).wrapping_mul(29))
            ^ 0xa7;
    }

    // Populate the exact timing and limit selector bytes consumed by OastModel.
    for (index, byte) in seed[65..80].iter_mut().enumerate() {
        *byte = boundary
            .rotate_left((index % 8) as u32)
            .wrapping_add(scenario.wrapping_mul(13))
            .wrapping_add(index as u8);
    }
    seed
}

fn structured_native_oast_seed(scenario: u8, boundary: u8) -> Vec<u8> {
    let mut seed = vec![0_u8; 96];
    seed[0] = scenario;
    for (index, byte) in seed[1..].iter_mut().enumerate() {
        *byte = boundary
            .wrapping_add(scenario.wrapping_mul(19))
            .wrapping_add((index as u8).wrapping_mul(37))
            ^ scenario.rotate_left((index % 8) as u32);
    }
    seed
}

fn structured_native_oast_adapter_seed(scenario: u8, boundary: u8) -> Vec<u8> {
    let mut seed = vec![0_u8; 128];
    seed[0] = scenario;
    for (index, byte) in seed[1..].iter_mut().enumerate() {
        *byte = boundary
            .wrapping_mul(5)
            .wrapping_add(scenario.wrapping_mul(23))
            .wrapping_add((index as u8).wrapping_mul(41))
            ^ boundary.rotate_left((index % 8) as u32);
    }
    seed
}

fn structured_ssrf_oast_review_seed(scenario: u8, boundary: u8) -> Vec<u8> {
    let mut seed = vec![0_u8; 160];
    seed[0] = scenario;
    for (index, byte) in seed[1..].iter_mut().enumerate() {
        *byte = boundary
            .wrapping_mul(7)
            .wrapping_add(scenario.wrapping_mul(29))
            .wrapping_add((index as u8).wrapping_mul(43))
            ^ scenario.rotate_left((index % 8) as u32)
            ^ boundary.rotate_right((index % 8) as u32);
    }
    seed
}

fn native_oast_seed(scenario: u8, payload: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(payload.len() + 1);
    seed.push(scenario);
    seed.extend_from_slice(payload);
    seed
}

fn replay_json_corpus(
    directory: &str,
    minimum_seed_count: usize,
    maximum_seed_bytes: usize,
    check: fn(&[u8]),
) {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("corpus")
        .join(directory);
    let mut seeds: Vec<_> = fs::read_dir(&corpus)
        .expect("committed semantic seed corpus must exist")
        .map(|entry| entry.expect("seed directory entry must be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    seeds.sort();

    assert!(
        seeds.len() >= minimum_seed_count,
        "semantic corpus {directory} unexpectedly shrank"
    );
    for seed in seeds {
        let data = fs::read(&seed).expect("committed semantic seed must be readable");
        serde_json::from_slice::<serde_json::Value>(&data).unwrap_or_else(|error| {
            panic!("seed must be structured JSON: {}: {error}", seed.display())
        });
        assert!(
            data.len() <= maximum_seed_bytes,
            "seed exceeds the harness input bound: {}",
            seed.display()
        );
        check(&data);
    }
}
