use criterion::{black_box, criterion_group, criterion_main, Criterion};
use venom_scanner::PayloadEncoding;

fn payload_encoding(c: &mut Criterion) {
    let input = b"bounded benchmark marker";

    c.bench_function("payload_percent_encode", |b| {
        b.iter(|| PayloadEncoding::Percent.apply(black_box(input)))
    });
}

criterion_group!(scanner_benchmarks, payload_encoding);
criterion_main!(scanner_benchmarks);
