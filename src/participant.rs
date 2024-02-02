#![allow(non_snake_case)]

use std::collections::BTreeMap;

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

use crate::{
    dleq::DLEQ,
    polynomial::Polynomial,
    sharebox::{DistributionShareBox, ShareBox},
    util::Util,
    vss::VSS,
};

#[derive(Debug, Clone, Default)]
pub struct Participant {
    vss: VSS,
    pub privatekey: BigInt,
    pub publickey: BigInt,
}

impl Participant {
    pub fn new() -> Self {
        Participant {
            vss: VSS::new(),
            privatekey: BigInt::zero(),
            publickey: BigInt::zero(),
        }
    }

    pub fn initialize(&mut self) {
        self.privatekey = self.vss.generate_private_key();
        self.publickey = self.vss.generate_public_key(&self.privatekey);
    }

    fn distribute(
        &mut self,
        secret: &BigInt,
        publickeys: &[BigInt],
        threshold: u32,
        polynomial: &Polynomial,
        w: &BigInt,
    ) -> DistributionShareBox {
        assert!(threshold <= publickeys.len() as u32);

        let mut commitments = Vec::new();
        let mut positions = BTreeMap::new();
        let mut X = BTreeMap::new();
        let mut shares = BTreeMap::new();
        let mut challenge_hasher = Sha256::new();

        let mut sampling_points = BTreeMap::new();
        let mut a = BTreeMap::new();
        let mut dleq_w = BTreeMap::new();
        let mut position: i64 = 1;

        for j in 0..threshold {
            commitments.push(
                self.vss
                    .g
                    .modpow(&polynomial.coefficients[j as usize], &self.vss.q),
            )
        }

        for publickey in publickeys {
            positions.insert(publickey.clone(), position);

            let secret_share =
                polynomial.get_value(&BigInt::from(position)) % (&self.vss.q - BigInt::one());

            sampling_points.insert(publickey.clone(), secret_share.clone());

            let mut x = BigInt::one();
            let mut exponent = BigInt::one();

            for j in 0..=threshold - 1 {
                x = (x * commitments[j as usize].modpow(&exponent, &self.vss.q)) % &self.vss.q;
                exponent = (exponent * BigInt::from(position)) % (&self.vss.q - BigInt::one());
            }

            X.insert(publickey.clone(), x.clone());

            let encrypted_secret_share = publickey.modpow(&secret_share, &self.vss.q);

            shares.insert(publickey.clone(), encrypted_secret_share.clone());

            let mut dleq = DLEQ::new();

            dleq.init2(
                self.vss.g.clone(),
                x.clone(),
                publickey.clone(),
                encrypted_secret_share.clone(),
                self.vss.q.clone(),
                secret_share.clone(),
                w.clone(),
            );

            dleq_w.insert(publickey.clone(), dleq.w.clone());

            a.insert(publickey.clone(), (dleq.get_a1(), dleq.get_a2()));

            challenge_hasher.update(x.to_biguint().unwrap().to_str_radix(10).as_bytes());

            challenge_hasher.update(
                encrypted_secret_share
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );

            challenge_hasher.update(
                dleq.get_a1()
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );

            challenge_hasher.update(
                dleq.get_a2()
                    .to_biguint()
                    .unwrap()
                    .to_str_radix(10)
                    .as_bytes(),
            );

            position += 1;
        }

        let challenge_hash = challenge_hasher.finalize();
        let challenge_big_uint = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(self.vss.q.to_biguint().unwrap() - BigUint::one()));
        let mut responses: BTreeMap<BigInt, BigInt> = BTreeMap::new();

        for publickey in publickeys {
            let x_i = X.get(publickey).unwrap();
            let encrypted_secret_share = shares.get(publickey).unwrap();
            let secret_share = sampling_points.get(publickey).unwrap();
            let w = dleq_w.get(publickey).unwrap();
            let mut dleq = DLEQ::new();

            dleq.init2(
                self.vss.g.clone(),
                x_i.clone(),
                publickey.clone(),
                encrypted_secret_share.clone(),
                self.vss.q.clone(),
                secret_share.clone(),
                w.clone(),
            );

            dleq.c = Some(challenge_big_uint.to_bigint().unwrap());

            let response = dleq.get_r().unwrap();

            responses.insert(publickey.clone(), response);
        }

        let shared_value = self.vss.G.modpow(
            &polynomial
                .get_value(&BigInt::zero())
                .mod_floor(&(self.vss.q.to_bigint().unwrap() - BigInt::one())),
            &self.vss.q,
        );
        let sha256_hash = sha2::Sha256::digest(
            shared_value
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );
        let hash_big_uint =
            BigUint::from_bytes_be(&sha256_hash[..]).mod_floor(&self.vss.q.to_biguint().unwrap());
        let u = secret.to_biguint().unwrap() ^ hash_big_uint;

        let mut shares_box = DistributionShareBox::new();

        shares_box.init(
            &commitments,
            positions,
            shares,
            publickeys,
            &challenge_big_uint.to_bigint().unwrap(),
            responses,
            &u.to_bigint().unwrap(),
        );

        shares_box
    }

    pub fn distribute_secret(
        &mut self,
        secret: &BigInt,
        publickeys: &[BigInt],
        threshold: u32,
    ) -> DistributionShareBox {
        let mut polynomial = Polynomial::new();

        polynomial.init((threshold - 1) as i32, &self.vss.q.to_bigint().unwrap());

        let mut rng = rand::thread_rng();
        let w = rng.gen_biguint_below(&self.vss.q.to_biguint().unwrap());

        self.distribute(
            secret,
            publickeys,
            threshold,
            &polynomial,
            &w.to_bigint().unwrap(),
        )
    }

    fn extract_share(
        &self,
        share_box: &DistributionShareBox,
        private_key: &BigInt,
        w: &BigInt,
    ) -> Option<ShareBox> {
        let public_key = self.vss.generate_public_key(private_key);
        let encrypted_secret_share = share_box.shares.get(&public_key).unwrap();
        let privatekey_inverse =
            Util::mod_inverse(private_key, &(&self.vss.q - BigInt::one())).unwrap();
        let decrypted_share = encrypted_secret_share.modpow(&privatekey_inverse, &self.vss.q);
        let mut dleq = DLEQ::new();

        dleq.init2(
            self.vss.G.clone(),
            public_key.clone(),
            decrypted_share.clone(),
            encrypted_secret_share.clone(),
            self.vss.q.clone(),
            private_key.clone(),
            w.clone(),
        );

        let mut challenge_hasher = Sha256::new();

        challenge_hasher.update(public_key.to_biguint().unwrap().to_str_radix(10).as_bytes());

        challenge_hasher.update(
            encrypted_secret_share
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );

        challenge_hasher.update(
            dleq.get_a1()
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );

        challenge_hasher.update(
            dleq.get_a2()
                .to_biguint()
                .unwrap()
                .to_str_radix(10)
                .as_bytes(),
        );

        let challenge_hash = challenge_hasher.finalize();
        let challenge_big_uint = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(self.vss.q.to_biguint().unwrap() - BigUint::one()));

        dleq.c = Some(challenge_big_uint.to_bigint().unwrap());

        let mut share_box = ShareBox::new();

        share_box.init(
            public_key,
            decrypted_share,
            challenge_big_uint.to_bigint().unwrap(),
            dleq.get_r().unwrap(),
        );

        Some(share_box)
    }

    pub fn extract_secret_share(
        &self,
        share_box: &DistributionShareBox,
        private_key: &BigInt,
    ) -> Option<ShareBox> {
        let w = Generator::new_uint(self.vss.length as usize)
            .mod_floor(&self.vss.q.to_biguint().unwrap());

        self.extract_share(share_box, private_key, &w.to_bigint().unwrap())
    }

    pub fn verify_distribution_shares(&self, distribution_sharebox: &DistributionShareBox) -> bool {
        self.vss.verify_distribution_shares(distribution_sharebox)
    }

    pub fn verify_share(
        &self,
        sharebox: &ShareBox,
        distribution_sharebox: &DistributionShareBox,
        publickey: &BigInt,
    ) -> bool {
        self.vss
            .verify_share(sharebox, distribution_sharebox, publickey)
    }

    pub fn reconstruct(
        &self,
        share_boxes: &[ShareBox],
        distribution_sharebox: &DistributionShareBox,
    ) -> Option<BigInt> {
        self.vss.reconstruct(share_boxes, distribution_sharebox)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use num_bigint::BigInt;
    use num_traits::{One, Zero};

    use crate::{
        polynomial::Polynomial,
        sharebox::{DistributionShareBox, ShareBox},
        vss::VSS,
    };

    use super::Participant;

    struct Setup {
        pub vss: VSS,
        pub privatekey: BigInt,
        pub secret: BigInt,
    }

    impl Setup {
        fn new() -> Self {
            let q = BigInt::from(179426549);
            let g = BigInt::from(1301081);
            let G = BigInt::from(15486487);
            let length: i64 = 64_i64;

            let mut vss = VSS::new();

            vss.q = q;
            vss.g = g;
            vss.G = G;
            vss.length = length as u32;

            return Setup {
                vss,
                privatekey: BigInt::from(105929),
                secret: BigInt::from(1234567890),
            };
        }
    }

    fn dealer_distribute_share_box() -> DistributionShareBox {
        let setup = Setup::new();
        let mut dealer = Participant::new();

        dealer.vss = setup.vss.clone();
        dealer.privatekey = setup.privatekey.clone();
        dealer.publickey = setup.vss.generate_public_key(&setup.privatekey);

        let mut polynomial = Polynomial::new();

        polynomial.init_coefficients(&vec![
            BigInt::from(164102006),
            BigInt::from(43489589),
            BigInt::from(98100795),
        ]);

        let threshold = 3;
        let privatekeys = [BigInt::from(7901), BigInt::from(4801), BigInt::from(1453)];
        let mut publickeys = vec![];
        let w = BigInt::from(6345);

        for key in privatekeys.iter() {
            publickeys.push(setup.vss.generate_public_key(key));
        }

        return dealer.distribute(&setup.secret, &publickeys, threshold, &polynomial, &w);
    }

    fn get_share_box() -> ShareBox {
        let distribution_share_box = dealer_distribute_share_box();
        let private_key = BigInt::from(7901);
        let w = BigInt::from(1337);
        let mut participant = Participant::new();
        let setup = Setup::new();

        participant.vss = setup.vss.clone();
        participant.privatekey = private_key.clone();
        participant.publickey = setup.vss.generate_public_key(&private_key);

        participant
            .extract_share(&distribution_share_box, &private_key, &w)
            .unwrap()
    }

    #[test]
    fn test_distribution() {
        let distribution = dealer_distribute_share_box();
        let commitments = vec![
            BigInt::from(92318234),
            BigInt::from(76602245),
            BigInt::from(63484157),
        ];
        let mut shares: BTreeMap<BigInt, BigInt> = BTreeMap::new();

        shares.insert(distribution.publickeys[0].clone(), BigInt::from(42478042));
        shares.insert(distribution.publickeys[1].clone(), BigInt::from(80117658));
        shares.insert(distribution.publickeys[2].clone(), BigInt::from(86941725));

        let challenge = BigInt::from(41963410);
        let mut responses: BTreeMap<BigInt, BigInt> = BTreeMap::new();

        responses.insert(distribution.publickeys[0].clone(), BigInt::from(151565889));
        responses.insert(distribution.publickeys[1].clone(), BigInt::from(146145105));
        responses.insert(distribution.publickeys[2].clone(), BigInt::from(71350321));

        assert_eq!(distribution.challenge, challenge);

        for i in 0..=2 {
            assert_eq!(distribution.commitments[i], commitments[i]);
            assert_eq!(
                distribution.shares[&distribution.publickeys[i]],
                shares[&distribution.publickeys[i]]
            );
            assert_eq!(
                distribution.responses[&distribution.publickeys[i]],
                responses[&distribution.publickeys[i]]
            );
        }
    }

    #[test]
    fn test_verify_distribution() {
        let setup = Setup::new();
        let distribution = dealer_distribute_share_box();

        assert_eq!(setup.vss.verify_distribution_shares(&distribution), true);
    }

    #[test]
    fn test_extract_share() {
        let share_box = get_share_box();

        assert_eq!(share_box.share, BigInt::from(164021044));
        assert_eq!(share_box.challenge, BigInt::from(134883166));
        assert_eq!(share_box.response, BigInt::from(81801891));
    }

    #[test]
    fn test_verify_share() {
        let private_key = BigInt::from(7901);
        let distribution_share_box = dealer_distribute_share_box();
        let sharebox = get_share_box();

        let setup = Setup::new();

        assert_eq!(
            setup.vss.verify_share(
                &sharebox,
                &distribution_share_box,
                &setup.vss.generate_public_key(&private_key)
            ),
            true
        )
    }

    #[test]
    fn test_secret_reconstruction() {
        let distribution_share_box = dealer_distribute_share_box();
        let share_box1 = get_share_box();
        let mut share_box2 = ShareBox::new();

        share_box2.init(
            BigInt::from(132222922),
            BigInt::from(157312059),
            BigInt::zero(),
            BigInt::zero(),
        );

        let mut share_box3 = ShareBox::new();

        share_box3.init(
            BigInt::from(65136827),
            BigInt::from(63399333),
            BigInt::zero(),
            BigInt::zero(),
        );

        let setup = Setup::new();
        let share_boxes = [share_box1, share_box2, share_box3];
        let reconstructed_secret = setup
            .vss
            .reconstruct(&share_boxes, &distribution_share_box)
            .unwrap();

        assert_eq!(reconstructed_secret, setup.secret);
    }

    // threshold secret reconstruct where 1 out of 4 participants is not available
    #[test]
    fn test_secret_reconstruction_with_sub_group() {
        let share_box1 = get_share_box();
        let mut share_box2 = ShareBox::new();

        share_box2.init(
            BigInt::from(132222922),
            BigInt::from(157312059),
            BigInt::zero(),
            BigInt::zero(),
        );

        let public_key4 = BigInt::from(42);
        let mut share_box4 = ShareBox::new();

        share_box4.init(
            public_key4.clone(),
            BigInt::from(59066181),
            BigInt::zero(),
            BigInt::zero(),
        );

        let mut positions = BTreeMap::new();

        positions.insert(share_box1.clone().publickey, 1_i64);
        positions.insert(share_box2.clone().publickey, 2_i64);
        positions.insert(share_box4.clone().publickey, 4_i64);

        let mut distribution_share_box = DistributionShareBox::new();

        distribution_share_box.init(
            &vec![BigInt::zero(), BigInt::one(), BigInt::from(2)],
            positions,
            BTreeMap::new(),
            &vec![],
            &BigInt::zero(),
            BTreeMap::new(),
            &BigInt::from(1284073502),
        );

        let setup = Setup::new();
        let share_boxes = [share_box1, share_box2, share_box4];
        let reconstructed_secret = setup
            .vss
            .reconstruct(&share_boxes, &distribution_share_box)
            .unwrap();

        assert_eq!(reconstructed_secret, setup.secret);
    }
}
