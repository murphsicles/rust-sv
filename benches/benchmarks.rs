use criterion::{criterion_group, criterion_main, Criterion};
use rust_sv::script::interpreter::eval;
use rust_sv::script::Script;
use rust_sv::script::checker::TransactionlessChecker;
use rust_sv::util::hash256::sha256d;
use rust_sv::wallet::extended_key::extended_key_from_seed;

fn benchmark_eval(c: &mut Criterion) {
    let script = Script::new();
    let mut checker = TransactionlessChecker {};
    c.bench_function("script_eval", |b| b.iter(|| eval(&script.0, &mut checker, 0)));
}

fn benchmark_sha256d(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    c.bench_function("sha256d", |b| b.iter(|| sha256d(&data)));
}

fn benchmark_extended_key(c: &mut Criterion) {
    let seed = vec![0u8; 32];
    c.bench_function("extended_key_from_seed", |b| b.iter(|| extended_key_from_seed(&seed, rust_sv::network::Network::Mainnet)));
}

criterion_group!(benches, benchmark_eval, benchmark_sha256d, benchmark_extended_key);
criterion_main!(benches);
