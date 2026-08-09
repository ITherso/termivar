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

    assert!(seeds.len() >= 16, "semantic corpus unexpectedly shrank");
    for seed in seeds {
        let data = fs::read(&seed).expect("committed HTML seed must be readable");
        assert!(
            data.len() <= venom_fuzz_harness::MAX_HTML_FUZZ_INPUT_BYTES,
            "seed exceeds the harness input bound: {}",
            seed.display()
        );
        venom_fuzz_harness::check_html_form_controls(&data);
    }
}

#[test]
fn committed_expression_corpus_satisfies_the_semantic_oracle() {
    replay_json_corpus(
        "expression_semantics",
        8,
        venom_fuzz_harness::check_expression_semantics,
    );
}

#[test]
fn committed_declarative_policy_corpus_satisfies_the_semantic_oracle() {
    replay_json_corpus(
        "declarative_policy_wire",
        16,
        venom_fuzz_harness::check_declarative_policy_wire,
    );
}

fn replay_json_corpus(directory: &str, minimum_seed_count: usize, check: fn(&[u8])) {
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
            data.len() <= venom_fuzz_harness::MAX_SEMANTIC_FUZZ_INPUT_BYTES,
            "seed exceeds the harness input bound: {}",
            seed.display()
        );
        check(&data);
    }
}
