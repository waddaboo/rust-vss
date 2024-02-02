#![allow(non_snake_case)]

use std::collections::BTreeMap;

use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::{One, Zero};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest, Sha256};

use crate::{
    dleq::DLEQ,
    sharebox::{DistributionShareBox, ShareBox},
    util::Util,
};

/// 2048-bit MODP Group
/// New Modular Exponential (MODP) Diffie-Hellman groups
///
/// This group is assigned id 14.
///
/// This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
///
/// Its hexadecimal value is:
///
///    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
///    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
///    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
///    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
///    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
///    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
///    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
///    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
///    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
///    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
///    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
///
/// The generator is: 2.
///
/// referenced from https://github.com/AlexiaChen/mpvss-rs

#[derive(Debug, Clone, Default)]
pub struct VSS {
    pub q: BigInt,
    pub g: BigInt,
    pub G: BigInt,
    pub length: u32,
}

impl VSS {
    /// `q` is a safe prime of length 2048 bit RFC3526 https://tools.ietf.org/html/rfc3526.
    /// `2` and the corresponding sophie germain prime are generators.
    /// sophie germain prime is p if 2*p + 1 is also prime, let 2*p + 1 = q
    pub fn new() -> Self {
        let q = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16).unwrap();
        let g = (q.clone() - BigUint::one()) / BigUint::from(2_u64);

        VSS {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2_i64),
            length: 2048,
        }
    }

    #[allow(dead_code)]
    pub fn init(length: u32) -> Self {
        let q = Generator::safe_prime(length as usize);
        let g = (q.clone() - BigUint::one()) / BigUint::from(2_u64);

        VSS {
            q: q.to_bigint().unwrap(),
            g: g.to_bigint().unwrap(),
            G: BigInt::from(2_i64),
            length,
        }
    }

    pub fn generate_private_key(&self) -> BigInt {
        let mut rng = rand::thread_rng();
        let mut private_key = rng.gen_biguint_below(&self.q.to_biguint().unwrap());

        while private_key.gcd(&(self.q.to_biguint().unwrap() - BigUint::one())) != BigUint::one() {
            private_key = rng.gen_biguint_below(&self.q.to_biguint().unwrap());
        }

        private_key.to_bigint().unwrap()
    }

    pub fn generate_public_key(&self, private_key: &BigInt) -> BigInt {
        self.G.modpow(private_key, &self.q)
    }

    pub fn verify(&self, sharebox: &ShareBox, encrypted_share: &BigInt) -> bool {
        let mut dleq = DLEQ::new();
        let mut challenge_hasher = Sha256::new();

        dleq.g1 = self.G.clone();
        dleq.h1 = sharebox.publickey.clone();
        dleq.g2 = sharebox.share.clone();
        dleq.h2 = encrypted_share.clone();
        dleq.r = Some(sharebox.response.clone());
        dleq.c = Some(sharebox.challenge.clone());
        dleq.q = self.q.clone();
        dleq.update_hash(&mut challenge_hasher);
        dleq.check(&challenge_hasher)
    }

    pub fn verify_share(
        &self,
        sharebox: &ShareBox,
        distribution_sharebox: &DistributionShareBox,
        publickey: &BigInt,
    ) -> bool {
        let encrypted_share = distribution_sharebox.shares.get(publickey);

        if encrypted_share.is_none() {
            return false;
        }

        self.verify(sharebox, encrypted_share.unwrap())
    }

    pub fn verify_distribution_shares(&self, distribution_sharebox: &DistributionShareBox) -> bool {
        let mut dleq = DLEQ::new();
        let mut challenge_hasher = Sha256::new();

        for publickey in &distribution_sharebox.publickeys {
            let position = distribution_sharebox.positions.get(publickey);
            let response = distribution_sharebox.responses.get(publickey);
            let encrypted_share = distribution_sharebox.shares.get(publickey);

            if position.is_none() || response.is_none() || encrypted_share.is_none() {
                return false;
            }

            let mut x = BigInt::one();
            let mut exponent = BigInt::one();

            for j in 0..distribution_sharebox.commitments.len() {
                x = (x * distribution_sharebox.commitments[j].modpow(&exponent, &self.q)) % &self.q;
                exponent = (exponent * BigInt::from(*position.unwrap() as i64))
                    % &(self.q.clone() - BigInt::one());
            }

            dleq.g1 = self.g.clone();
            dleq.h1 = x;
            dleq.g2 = publickey.clone();
            dleq.h2 = encrypted_share.unwrap().clone();
            dleq.r = Some(response.unwrap().clone());
            dleq.c = Some(distribution_sharebox.challenge.clone());
            dleq.q = self.q.clone();
            dleq.update_hash(&mut challenge_hasher);
        }

        dleq.check(&challenge_hasher)
    }

    fn compute_factor(&self, position: i64, share: &BigInt, values: &[i64]) -> BigInt {
        let mut exponent = BigInt::one();
        let lagrangeCoefficient = Util::lagrange_coefficient(&position, values);

        if &lagrangeCoefficient.0 % &lagrangeCoefficient.1 == BigInt::zero() {
            // lagrange coefficient is an integer
            exponent = &lagrangeCoefficient.0 / Util::abs(&lagrangeCoefficient.1);
        } else {
            // lagrange coefficient is a proper faction, cancel fraction if possible
            let mut numerator = lagrangeCoefficient.0.to_biguint().unwrap();
            let mut denominator = Util::abs(&lagrangeCoefficient.1).to_biguint().unwrap();
            let gcd = numerator.gcd(&denominator);

            numerator /= &gcd;
            denominator /= &gcd;

            let q1 = &self.q - BigInt::one();
            let inverseDenominator =
                Util::mod_inverse(&denominator.to_bigint().unwrap(), &q1.to_bigint().unwrap());

            if let Some(inverseDenom) = inverseDenominator {
                exponent =
                    (numerator.to_bigint().unwrap() * inverseDenom) % q1.to_bigint().unwrap();
            } else {
                eprintln!("Error: Denominator of Lagrange coefficient fraction does not have an inverse. Share cannot be processed")
            }
        }

        let mut factor = share
            .to_bigint()
            .unwrap()
            .modpow(&exponent, &self.q.to_bigint().unwrap());

        if lagrangeCoefficient.0 * lagrangeCoefficient.1 < BigInt::zero() {
            let inverseFactor = Util::mod_inverse(&factor, &self.q.to_bigint().unwrap());

            if let Some(inverseFactor) = inverseFactor {
                factor = inverseFactor;
            } else {
                eprintln!("Error: Lagrange coefficient was negative and does not have an inverse. Share cannot be processed");
            }
        }

        factor
    }

    pub fn reconstruct(
        &self,
        share_boxes: &[ShareBox],
        distribution_sharebox: &DistributionShareBox,
    ) -> Option<BigInt> {
        if share_boxes.len() < distribution_sharebox.commitments.len() {
            return None;
        }

        let mut shares = BTreeMap::new();

        for share_box in share_boxes.iter() {
            let position = distribution_sharebox.positions.get(&share_box.publickey);

            position?;

            shares.insert(*position.unwrap(), share_box.share.clone());
        }

        let mut secret = BigInt::one();
        let values: Vec<i64> = shares.keys().copied().collect();
        let shares_vec: Vec<(i64, BigInt)> = shares
            .into_iter()
            .map(|(position, share)| (position, share))
            .collect();
        let shares_slice = shares_vec.as_slice();
        let factors: Vec<BigInt> = shares_slice
            .par_iter()
            .map(|(position, share)| self.compute_factor(*position, share, values.as_slice()))
            .collect();

        secret = factors
            .into_iter()
            .fold(secret, |acc, factor| (acc * factor) % &self.q);

        let secret_hash = Sha256::digest(secret.to_biguint().unwrap().to_str_radix(10).as_bytes());
        let hash_big_uint =
            BigUint::from_bytes_be(&secret_hash[..]).mod_floor(&self.q.to_biguint().unwrap());
        let decrypted_secret = hash_big_uint ^ distribution_sharebox.u.to_biguint().unwrap();

        Some(decrypted_secret.to_bigint().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, BigUint, ToBigInt};
    use num_integer::Integer;
    use num_primes::Verification;
    use num_traits::One;

    use super::VSS;

    #[test]
    fn test_new() {
        let vss = VSS::new();

        assert!(Verification::is_safe_prime(&vss.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&vss.g.to_biguint().unwrap()));
        assert!(!Verification::is_safe_prime(&vss.g.to_biguint().unwrap()));
    }

    #[test]
    fn test_init() {
        let vss = VSS::init(64);
        assert!(Verification::is_safe_prime(&vss.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&vss.g.to_biguint().unwrap()));
        assert!(!Verification::is_safe_prime(&vss.g.to_biguint().unwrap()));

        let vss = VSS::init(32);
        assert!(Verification::is_prime(&vss.q.to_biguint().unwrap()));
        assert!(Verification::is_prime(&vss.g.to_biguint().unwrap()));
        assert_eq!(
            vss.g,
            ((vss.q - BigInt::one()).to_biguint().unwrap() / BigUint::from(2_u32))
                .to_bigint()
                .unwrap()
        )
    }

    #[test]
    fn test_generate_private_key() {
        let mut vss = VSS::new();
        vss.q = BigInt::from(49999_i32);

        assert!(Verification::is_prime(&vss.q.to_biguint().unwrap()));

        let private_key = vss.generate_private_key();

        assert_eq!(
            private_key.gcd(&(vss.q.clone() - BigInt::one())),
            BigInt::one()
        );
    }

    #[test]
    fn test_generate_public_key() {
        let mut vss = VSS::new();
        let q = BigInt::from(179426549);
        let g = BigInt::from(1301081);
        let G = BigInt::from(15486487);

        vss.q = q;
        vss.g = g;
        vss.G = G;

        let private_key = BigInt::from(105929);
        let public_key = vss.generate_public_key(&private_key);

        assert_eq!(public_key, BigInt::from(148446388));
    }
}
