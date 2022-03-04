use atms_blst::{AggregateSig, AtmsError, PublicKey, PublicKeyPoP, Registration, SigningKey};
use blake2::Blake2b;
use rand::prelude::IteratorRandom;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn full_protocol() -> Result<(), AtmsError> {
    let total_nr_players = 10;
    let players = 0..total_nr_players;

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let msg_1 = [0u8; 16];

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
    let atms_registration_1 = Registration::<Blake2b>::new(&qp_keys)?;

    // Once the registration is performed, we can generate the avk
    let avk_1 = atms_registration_1.to_avk();

    // Now the parties can sign messages. No need of interaction.
    let mut signatures = Vec::with_capacity(nr_parties_1);
    for &i in qualified_signers.iter() {
        signatures.push((PublicKey::from(&sks[i]), sks[i].sign(&msg_1)));
    }
    let aggr_sig = AggregateSig::new(&atms_registration_1, &signatures[..], &msg_1)?;

    assert!(aggr_sig.verify(&msg_1, &avk_1, threshold).is_ok());

    // A different epoch begins when the signers (or the stake) changes (and the message).
    // Beginning of epoch 2
    let nr_parties_2 = 7;
    let threshold = 5;
    let msg_2 = [1u8; 7];
    let qualified_signers = players.choose_multiple(&mut rng, nr_parties_2);

    let mut qp_keys = Vec::with_capacity(nr_parties_2);
    for &qp in qualified_signers.iter() {
        qp_keys.push(pks_pop[qp]);
    }

    // With this data, we can register the eligible parties.
    let atms_registration_2 = Registration::<Blake2b>::new(&qp_keys)?;

    let avk_2 = atms_registration_2.to_avk();
    // Now the parties can sign messages. No need of interaction.
    let mut signatures = Vec::with_capacity(nr_parties_2);

    // Now, assume that only 4 parties are available for signing, and therefore, verification will fail.
    for &i in qualified_signers.iter().take(4) {
        signatures.push((PublicKey::from(&sks[i]), sks[i].sign(&msg_2)));
    }
    let aggr_sig = AggregateSig::new(&atms_registration_2, &signatures[..], &msg_2)?;

    // aggregated signatures can be verified using the ATMs single key.
    assert!(aggr_sig.verify(&msg_2, &avk_2, threshold).is_err());

    // If we try to aggregate the signatures with respect to the old message, registration will also fail.
    let aggr_sig_old_msg = AggregateSig::new(&atms_registration_2, &signatures[..], &msg_1);
    assert_eq!(aggr_sig_old_msg.unwrap_err(), AtmsError::InvalidSignature);

    // If we aggregate signatures with respect to the old registration, then we will have unknown signers.
    let aggr_unknown_signers = AggregateSig::new(&atms_registration_1, &signatures[..], &msg_2);
    assert_eq!(
        aggr_unknown_signers.unwrap_err(),
        AtmsError::NonRegisteredParticipant
    );
    Ok(())
}
