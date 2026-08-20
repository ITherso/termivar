use criterion::{black_box, criterion_group, criterion_main, Criterion};
use venom_scanner::{LruCache, PayloadEncoding};

fn cache_access(c: &mut Criterion) {
    let cache = LruCache::new(128);
    let key = "benchmark-key".to_string();
    cache.insert(key.clone(), vec![0x41; 4096], 60);

    c.bench_function("lru_cache_hit_4k", |b| {
        b.iter(|| cache.get(black_box(&key)))
    });
}

fn payload_encoding(c: &mut Criterion) {
    let input = b"bounded benchmark marker";

    c.bench_function("payload_percent_encode", |b| {
        b.iter(|| PayloadEncoding::Percent.apply(black_box(input)))
    });
}

criterion_group!(scanner_benchmarks, cache_access, payload_encoding);
criterion_main!(scanner_benchmarks);
