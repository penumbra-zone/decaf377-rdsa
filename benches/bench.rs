use rand::{thread_rng, Rng};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::convert::TryFrom;

use decaf377_rdsa::*;

enum Item {
    SpendAuth {
        vk_bytes: VerificationKeyBytes<SpendAuth>,
        sig: Signature<SpendAuth>,
    },
    Binding {
        vk_bytes: VerificationKeyBytes<Binding>,
        sig: Signature<Binding>,
    },
}

fn sigs_with_distinct_keys() -> impl Iterator<Item = Item> {
    std::iter::repeat_with(|| {
        let mut rng = thread_rng();
        let msg = b"Bench";
        match rng.gen::<u8>() % 2 {
            0 => {
                let sk = SigningKey::<SpendAuth>::new(thread_rng());
                let vk_bytes = VerificationKey::from(&sk).into();
                let sig = sk.sign(thread_rng(), &msg[..]);
                Item::SpendAuth { vk_bytes, sig }
            }
            1 => {
                let sk = SigningKey::<Binding>::new(thread_rng());
                let vk_bytes = VerificationKey::from(&sk).into();
                let sig = sk.sign(thread_rng(), &msg[..]);
                Item::Binding { vk_bytes, sig }
            }
            _ => panic!(),
        }
    })
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Verification");
    for &n in [8usize, 16, 24, 32, 40, 48, 56, 64].iter() {
        group.throughput(Throughput::Elements(n as u64));

        let sigs = sigs_with_distinct_keys().take(n).collect::<Vec<_>>();

        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    for item in sigs.iter() {
                        let msg = b"Bench";
                        match item {
                            Item::SpendAuth { vk_bytes, sig } => {
                                let _ = VerificationKey::try_from(*vk_bytes)
                                    .and_then(|vk| vk.verify(msg, sig));
                            }
                            Item::Binding { vk_bytes, sig } => {
                                let _ = VerificationKey::try_from(*vk_bytes)
                                    .and_then(|vk| vk.verify(msg, sig));
                            }
                        }
                    }
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Batched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for item in sigs.iter() {
                        let msg = b"Bench";
                        match item {
                            Item::SpendAuth { vk_bytes, sig } => {
                                batch.queue((*vk_bytes, *sig, msg));
                            }
                            Item::Binding { vk_bytes, sig } => {
                                batch.queue((*vk_bytes, *sig, msg));
                            }
                        }
                    }
                    batch.verify(thread_rng())
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_batch_verify);
criterion_main!(benches);
