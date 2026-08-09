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
