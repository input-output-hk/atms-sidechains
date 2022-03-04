use atms_blst::{AggregateSig, AtmsError, PublicKey, PublicKeyPoP, Registration, SigningKey};
use blake2::Blake2b;
use rand::prelude::IteratorRandom;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn full_protocol() -> Result<(), AtmsError> {
    let total_nr_players = 10;
    let players = 0..total_nr_players;

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut msg = [0u8; 16];

    let mut sks: Vec<SigningKey> = Vec::with_capacity(total_nr_players);
    let mut pks_pop: Vec<PublicKeyPoP> = Vec::with_capacity(total_nr_players);
    for _ in 0..total_nr_players {
        let sk = SigningKey::gen(&mut rng);
        pks_pop.push(PublicKeyPoP::from(&sk));
        sks.push(sk);
    }

    // Epoch 1.
    // For the sake of the example, assume that we define the set of signers to be a
    // subset of the total players. We choose such a subset.
    let nr_parties_1 = 5;
    let threshold = 4;
    let qualified_signers = players.clone().choose_multiple(&mut rng, nr_parties_1);

    let mut qp_keys = Vec::with_capacity(nr_parties_1);
    for &qp in qualified_signers.iter() {
        qp_keys.push(pks_pop[qp]);
    }

    // With this data, we can register all eligible parties.
    let atms_registration = Registration::<Blake2b>::new(&qp_keys)?;

    // Once the registration is performed, we can generate the avk
    let avk = atms_registration.to_avk();

    // Now the parties can sign messages. No need of interaction.
    rng.fill_bytes(&mut msg);
    let mut signatures = Vec::with_capacity(nr_parties_1);
    for &i in qualified_signers.iter() {
        signatures.push((PublicKey::from(&sks[i]), sks[i].sign(&msg)));
    }
    let aggr_sig = AggregateSig::new(&atms_registration, &signatures[..], &msg)
        .expect("Signatures should be valid.");

    assert!(aggr_sig.verify(&msg, &avk, threshold).is_ok());

    // A different epoch begins when the signers (or the stake) changes.
    // Beginning of epoch 2
    let nr_parties_2 = 7;
    let threshold = 5;
    let qualified_signers = players.choose_multiple(&mut rng, nr_parties_2);

    let mut qp_keys = Vec::with_capacity(nr_parties_2);
    for &qp in qualified_signers.iter() {
        qp_keys.push(pks_pop[qp]);
    }

    // With this data, we can register the eligible parties.
    let atms_registration = Registration::<Blake2b>::new(&qp_keys)?;

    let avk = atms_registration.to_avk();
    // Now the parties can sign messages. No need of interaction.
    rng.fill_bytes(&mut msg);
    let mut signatures = Vec::with_capacity(nr_parties_2);

    // Now, assume that only 4 parties are available for signing, and therefore, verification will fail.
    for &i in qualified_signers.iter().take(4) {
        signatures.push((PublicKey::from(&sks[i]), sks[i].sign(&msg)));
    }
    let aggr_sig = AggregateSig::new(&atms_registration, &signatures[..], &msg)
        .expect("Signatures should be valid.");

    // aggregated signatures can be verified using the ATMs single key.
    assert!(aggr_sig.verify(&msg, &avk, threshold).is_err());
    Ok(())
}
