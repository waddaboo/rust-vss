use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_primes::Generator;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use std::option::Option;

// Chaum-Pedersen Protocol

// To prove that log_g1(h1)= log_g2(h2), for generators g1,h1,g2,h2 ∈ Gq,   Gq is group of order q and q is prime

// We denote this protocol by DLEQ(g1,h1,g2,h2), and it consists of the following steps, where the prover knows α(alpha) such that h1 = g1^α and h2 = g2^α:
// - The prover sends a1 = g1^w and a2 = g2^w to the verifier, with w ∈ R Zq
// - The verifier sends a random challenge c ∈ R Zq to the prover.
// - The prover responds with r = w − αc (mod q).
// - The verifier checks that a1 = (g1^r) * (h1^c) and a2 = (g2^r) * (h2^c).

// referenced from https://github.com/AlexiaChen/mpvss-rs

struct Prover {}

impl Prover {
    fn send(g: &BigInt, w: &BigInt, q: &BigInt) -> BigInt {
        g.modpow(w, q)
    }

    fn response(w: &BigInt, alpha: &BigInt, c: &Option<BigInt>, q: &BigInt) -> Option<BigInt> {
        match c {
            None => None,
            Some(c) => {
                let r: BigInt = w.to_bigint().unwrap() - (alpha * c).to_bigint().unwrap();
                let result = r.mod_floor(&(q.clone().to_bigint().unwrap() - BigInt::one()));
                Some(result)
            }
        }
    }
}
struct Verifier {}

impl Verifier {
    fn send() -> BigInt {
        BigInt::zero()
    }

    fn check(c: &BigInt, q: &BigInt, challenge_hasher: &Sha256) -> bool {
        let challenge_hash = challenge_hasher.clone().finalize();
        let challenge_big_uint = BigUint::from_bytes_be(&challenge_hash[..])
            .mod_floor(&(q.clone().to_biguint().unwrap() - BigUint::one()));

        challenge_big_uint == (*c).to_biguint().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn update(
        g1: &BigInt,
        h1: &BigInt,
        g2: &BigInt,
        h2: &BigInt,
        response: &BigInt,
        c: &BigInt,
        q: &BigInt,
        challenge_hasher: &mut Sha256,
    ) {
        let a1 = (g1.modpow(response, q) * h1.modpow(c, q)) % q;
        let a2 = (g2.modpow(response, q) * h2.modpow(c, q)) % q;

        challenge_hasher.update(h1.to_biguint().unwrap().to_str_radix(10).as_bytes());
        challenge_hasher.update(h2.to_biguint().unwrap().to_str_radix(10).as_bytes());
        challenge_hasher.update(a1.to_biguint().unwrap().to_str_radix(10).as_bytes());
        challenge_hasher.update(a2.to_biguint().unwrap().to_str_radix(10).as_bytes());
    }
}

#[derive(Debug, Clone, Default)]
pub struct DLEQ {
    pub g1: BigInt,
    pub h1: BigInt,
    pub g2: BigInt,
    pub h2: BigInt,

    pub w: BigInt,
    pub q: BigInt,
    pub alpha: BigInt,
    pub c: Option<BigInt>,
    pub a1: BigInt,
    pub a2: BigInt,
    pub r: Option<BigInt>,
}

impl DLEQ {
    pub fn new() -> Self {
        DLEQ {
            g1: BigInt::zero(),
            h1: BigInt::zero(),
            g2: BigInt::zero(),
            h2: BigInt::zero(),

            w: BigInt::zero(),
            q: BigInt::zero(),
            alpha: BigInt::zero(),
            c: None,
            a1: BigInt::zero(),
            a2: BigInt::zero(),
            r: None,
        }
    }

    #[allow(dead_code)]
    pub fn init(
        &mut self,
        g1: BigInt,
        h1: BigInt,
        g2: BigInt,
        h2: BigInt,
        length: u32,
        q: BigInt,
        alpha: BigInt,
    ) {
        let w: BigUint = Generator::new_prime(length as usize).mod_floor(&q.to_biguint().unwrap());

        self.init2(g1, h1, g2, h2, q, alpha, w.to_bigint().unwrap());
    }

    pub fn init2(
        &mut self,
        g1: BigInt,
        h1: BigInt,
        g2: BigInt,
        h2: BigInt,
        q: BigInt,
        alpha: BigInt,
        w: BigInt,
    ) {
        self.g1 = g1;
        self.h1 = h1;
        self.g2 = g2;
        self.h2 = h2;
        self.q = q;
        self.alpha = alpha;
        self.w = w;
    }

    pub fn get_a1(&self) -> BigInt {
        Prover::send(&self.g1, &self.w, &self.q)
    }

    pub fn get_a2(&self) -> BigInt {
        Prover::send(&self.g2, &self.w, &self.q)
    }

    pub fn get_r(&self) -> Option<BigInt> {
        Prover::response(&self.w, &self.alpha, &self.c, &self.q)
    }

    #[allow(dead_code)]
    pub fn get_c(&self) -> BigInt {
        Verifier::send()
    }

    pub fn update_hash(&self, challenge_hasher: &mut Sha256) {
        Verifier::update(
            &self.g1,
            &self.h1,
            &self.g2,
            &self.h2,
            &self.r.clone().unwrap(),
            &self.c.clone().unwrap(),
            &self.q,
            challenge_hasher,
        )
    }

    pub fn check(&self, challenge_hasher: &Sha256) -> bool {
        Verifier::check(&self.c.clone().unwrap(), &self.q, challenge_hasher)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    use super::DLEQ;

    #[test]
    fn test_dleq() {
        let g1 = BigInt::from(8443);
        let h1 = BigInt::from(531216);
        let g2 = BigInt::from(1299721);
        let h2 = BigInt::from(14767239);
        let w = BigInt::from(81647);
        let q = BigInt::from(15487469);
        let alpha = BigInt::from(163027);

        let mut dleq = DLEQ::new();

        dleq.init2(g1, h1, g2, h2, q.clone(), alpha, w);

        let a1 = BigInt::from(14735247);
        let a2 = BigInt::from(5290058);

        assert_eq!(dleq.get_a1(), a1);
        assert_eq!(dleq.get_a2(), a2);

        let c = BigInt::from(127997);
        dleq.c = Some(c);

        let r = BigInt::from(10221592);

        assert_eq!(dleq.get_r().unwrap(), r);
        assert_eq!(
            (dleq.g1.modpow(&dleq.get_r().unwrap(), &dleq.q)
                * dleq.h1.modpow(&dleq.c.clone().unwrap(), &dleq.q))
                % q.clone(),
            a1
        );
        assert_eq!(
            (dleq.g2.modpow(&dleq.get_r().unwrap(), &dleq.q)
                * dleq.h2.modpow(&dleq.c.clone().unwrap(), &dleq.q))
                % q.clone(),
            a2
        );
    }
}
