use std::collections::{BTreeMap, HashMap};

use decaf377_rdsa::frost::keys::dkg::round1;
use rand::thread_rng;

use decaf377_rdsa::*;

use decaf377_rdsa::frost::Identifier;

#[test]
fn simple_dkg_and_signing_flow() -> anyhow::Result<()> {
    const T: u16 = 2;
    const N: u16 = 3;

    // For convenience, store an indexable list of IDs.
    let ids = (0..N)
        .map(|id| Identifier::derive(&id.to_le_bytes()).unwrap())
        .collect::<Vec<_>>();

    // First, run a DKG with three participants

    let mut round1_secrets = HashMap::new();
    let mut round1_packages = HashMap::new();

    for id in &ids {
        let (secret, package) = frost::keys::dkg::part1(*id, N, T, thread_rng())?;
        round1_secrets.insert(*id, secret);
        round1_packages.insert(*id, package);
    }

    dbg!(&round1_secrets);
    dbg!(&round1_packages);
    // Round 1 is a broadcast, so it's enough to copy all the round 1 packages.

    let mut round2_secrets = HashMap::new();
    let mut round2_packages = HashMap::new();

    for id in &ids {
        let round1_secret = round1_secrets.remove(id).unwrap();

        let mut round1_packages_except_us = round1_packages.clone();
        round1_packages_except_us.remove(id);

        //let (secret, packages) = frost::keys::dkg::part2(round1_secret, &round1_packages)?;
        let (secret, packages) =
            frost::keys::dkg::part2(round1_secret, &round1_packages_except_us)?;
        round2_secrets.insert(*id, secret);
        round2_packages.insert(*id, packages);
    }

    dbg!(&round2_secrets);
    dbg!(&round2_packages);

    // Round 2 is point-to-point (and encrypted! but we're faking it), so we need to
    // build a map of messages received by each participant.

    let mut shares = HashMap::new();
    let mut public_key_packages = HashMap::new();

    dbg!("got here");
    for id in &ids {
        let mut recvd_packages = HashMap::new();
        for (other_id, its_packages) in &round2_packages {
            if other_id == id {
                continue;
            }
            recvd_packages.insert(*other_id, its_packages.get(id).unwrap().clone());
        }
        dbg!(&id);
        dbg!(&recvd_packages);

        let mut round1_packages_except_us = round1_packages.clone();
        round1_packages_except_us.remove(id);

        let round2_secret = round2_secrets.remove(id).unwrap();
        let (key_package, public_key_package) =
            //frost::keys::dkg::part3(&round2_secret, &round1_packages, &recvd_packages)?;
            frost::keys::dkg::part3(&round2_secret, &round1_packages_except_us, &recvd_packages)?;

        shares.insert(id, key_package);
        public_key_packages.insert(*id, public_key_package);
    }
    dbg!("got here");

    dbg!(&shares);
    dbg!(&public_key_packages);

    // Now try signing.
    const MSG: &[u8] = b"hello world";

    // Signing round 1
    let mut signing_commitments = BTreeMap::new();
    let mut sign_round1_nonces = HashMap::new();

    for id in &ids {
        let (nonce, commitment) =
            frost::round1::commit(&shares[id].secret_share(), &mut thread_rng());
        signing_commitments.insert(*id, commitment);
        sign_round1_nonces.insert(*id, nonce);
    }

    dbg!(&signing_commitments);
    //dbg!(&sign_round1_nonces);

    let signing_package = frost::SigningPackage::new(signing_commitments, MSG);

    let mut sign_round2_signature_shares = HashMap::new();

    for id in &ids {
        let share = frost::round2::sign(
            &signing_package,
            &sign_round1_nonces.get(id).unwrap(),
            &shares.get(id).unwrap(),
        )?;
        sign_round2_signature_shares.insert(*id, share);
    }

    // Aggregate the signature shares

    let signature_bytes = frost::aggregate(
        &signing_package,
        &sign_round2_signature_shares,
        public_key_packages.values().next().unwrap(),
    )?
    .serialize();

    let signature = Signature::<SpendAuth>::from(signature_bytes);

    let vk_bytes = public_key_packages
        .values()
        .next()
        .unwrap()
        .group_public()
        .serialize();
    let vk = VerificationKey::<SpendAuth>::try_from(vk_bytes)?;

    // Verify the signature
    vk.verify(MSG, &signature)?;

    Ok(())
}
