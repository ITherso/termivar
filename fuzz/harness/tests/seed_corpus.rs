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
