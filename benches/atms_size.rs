use atms::aggregation::{AggregateSig, Registration};
use atms::multi_sig::{PublicKey, PublicKeyPoP, SigningKey};
use blake2::Blake2b;
use digest::consts::U32;
use rand::prelude::IteratorRandom;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const COMMITEE_SIZES: [usize; 8] = [100, 200, 300, 400, 500, 600, 700, 800];

fn main() {
    let msg = b"ATMS size benchmarks";
    println!("+{a:->width$}+", a="", width=65);
    println!("|{title: <width$}|", title=" Size benchmarks for ATMS: ", width=65);
    println!("+{a:->width$}+", a="", width=65);
    println!("| Committee Size | Non-signers | Cert size | Estimated CPU budget | ");
    //                16              13           11                22

    // You can pad numbers with extra zeroes,
    // and left-adjust by flipping the sign. This will output "10000".
    // println!("{number: <5}a", number=1);

    // You can use named arguments in the format specifier by appending a `$`.
    // println!("{number:0>width$}", number=1, width=5);

    for num_signers in COMMITEE_SIZES {
        print!("| {num_signers: >width$} |", width=14);
        let num_sigs = (2 * num_signers) / 3;

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut sk_pks = Vec::with_capacity(num_sigs);
        let mut pkpops = Vec::with_capacity(num_sigs);
        let mut sigs = Vec::with_capacity(num_sigs);
        for _ in 0..num_signers {
            let sk = SigningKey::gen(&mut rng);
            let pk = PublicKey::from(&sk);
            let pkpop = PublicKeyPoP::from(&sk);
            pkpops.push(pkpop);
            sk_pks.push((sk, pk));
        }
        let registration = Registration::<Blake2b<U32>>::new(&pkpops).expect("Registration should pass with valid keys");

        let signing_parties = (0..num_signers).choose_multiple(&mut rng, num_sigs);
        for index in signing_parties {
            let (sk, pk) = &sk_pks[index];
            let sig = sk.sign(msg);
            assert!(sig.verify(&pk, msg).is_ok());
            let indices = registration.get_index(&pk);
            for j in indices {
                sigs.push((j, sig));
            }
        }
        // println!("Number of signatures: {}", sigs.len());
        let mu = AggregateSig::new(&registration, &sigs, msg).expect("Signatures should be valid");

        let bytes = mu.to_bytes();
        assert!(mu.verify(msg, &registration.to_avk(), num_sigs).is_ok());

        // println!("Number non-sig keys: {:?}", mu.keys.len());
        print!(" {non_signers: >width$} |", non_signers=mu.keys.len(), width=11);
        print!(" {cert_size: >width$} |", cert_size=bytes.len(), width=9);

        // We compute the estimated CPU budget as follows:
        // - Deserialise `non_signers` keys (in G1) (16511372 each)
        // - Perform `non_signers + 1` additions in G1 (1046420 each)
        // - Check `non_signers` merkle paths (this is an upper bound)
        //     - `log (number_signers) * non_signers` hash computations (521475 each)
        // - Two miller loops (402099373 each)
        // - One final exp (388656972)
        //
        // Total budget is 10_000_000_000 units
        let non_signers = mu.keys.len();
        let height_tree = (num_signers as f64).log2().ceil() as usize;
        let estimated_budget = non_signers * 16511372 + (non_signers + 1) * 1046420 + height_tree * non_signers * 521475 + 2 * 402099373 + 388656972;

        let used_budget = (estimated_budget * 100) / 10_000_000_000;
        println!(" {used_budget: >width$}% |", width=19);

        println!("+{a:->width1$}|{a:->width2$}|{a:->width3$}|{a:->width4$}+", a="", width1=16, width2=13, width3=11, width4=22);
    }
}
