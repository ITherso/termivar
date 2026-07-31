use criterion::{black_box, criterion_group, criterion_main, Criterion};
use venom_scanner::{PayloadEncoder, ResponseCache, WafDetector};

fn cache_access(c: &mut Criterion) {
    let cache = ResponseCache::new(128);
    let url = "https://benchmark.invalid/resource";
    cache.cache_response(url, vec![0x41; 4096], 60);

    c.bench_function("response_cache_hit_4k", |b| {
        b.iter(|| cache.get_response(black_box(url)))
    });
}

fn waf_header_detection(c: &mut Criterion) {
    let detector = WafDetector::new();
    let headers = [
        ("Content-Type", "text/html"),
        ("Server", "cloudflare"),
        ("CF-RAY", "benchmark"),
    ];

    c.bench_function("waf_header_detection", |b| {
        b.iter(|| detector.detect_from_headers(black_box(&headers)))
    });
}

fn payload_encoding(c: &mut Criterion) {
    let payload = "SELECT name FROM accounts WHERE id = 42";

    c.bench_function("payload_double_url_encode", |b| {
        b.iter(|| PayloadEncoder::double_url_encode(black_box(payload)))
    });
}

criterion_group!(
    scanner_benchmarks,
    cache_access,
    waf_header_detection,
    payload_encoding
);
criterion_main!(scanner_benchmarks);
