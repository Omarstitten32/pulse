use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_platform(c: &mut Criterion) {
    c.bench_function("platform_collect", |b| {
        b.iter(|| {
            let _ = black_box(std::time::SystemTime::now());
        })
    });
}

fn bench_hardening(c: &mut Criterion) {
    c.bench_function("hardening_collect", |b| {
        b.iter(|| {
            let _ = black_box(std::time::SystemTime::now());
        })
    });
}

criterion_group!(benches, bench_platform, bench_hardening);
criterion_main!(benches);
