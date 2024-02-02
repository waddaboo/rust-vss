use std::ops::Mul;

use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::pow::Pow;

// Based on Shamir's Secret Sharing (SSS) scheme.
// p(X)= s + p1X + ⋯ + pfXf

#[derive(Debug, Clone, Default)]
pub struct Polynomial {
    pub coefficients: Vec<BigInt>,
}

impl Polynomial {
    pub fn new() -> Self {
        Polynomial {
            coefficients: Vec::new(),
        }
    }

    pub fn init_coefficients(&mut self, coefficients: &[BigInt]) {
        self.coefficients = coefficients.to_vec();
    }

    pub fn init(&mut self, degree: i32, q: &BigInt) {
        let mut coefficients = vec![];
        let mut rng = rand::thread_rng();

        for _ in 0..=degree {
            let coefficient = rng
                .gen_biguint_below(&q.to_biguint().unwrap())
                .to_bigint()
                .unwrap();

            coefficients.push(coefficient);
        }

        self.init_coefficients(&coefficients);
    }

    // get p(X) = value
    pub fn get_value(&self, x: &BigInt) -> BigInt {
        let mut result = self.coefficients[0].clone();

        for i in 1..self.coefficients.len() {
            result += self.coefficients[i].clone().mul(x.pow(i));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, ToBigInt};

    use super::Polynomial;

    #[test]
    fn test_init_polynomial() {
        let mut polynomial = Polynomial::new();
        let degree = 3;

        polynomial.init(degree, &BigInt::from(5_i32));

        assert_eq!(polynomial.coefficients.len(), (degree + 1) as usize);
    }

    #[test]
    fn test_get_value() {
        let mut polynomial = Polynomial::new();

        polynomial.init_coefficients(&vec![
            3.to_bigint().unwrap(),
            2.to_bigint().unwrap(),
            2.to_bigint().unwrap(),
            4.to_bigint().unwrap(),
        ]);

        // p(0) = a_0 = 3
        assert_eq!(
            polynomial.get_value(&0.to_bigint().unwrap()),
            BigInt::from(3_i32)
        );

        // p(1) = 11
        assert_eq!(
            polynomial.get_value(&1.to_bigint().unwrap()),
            BigInt::from(11_i32)
        );

        // p(2) = 47
        assert_eq!(
            polynomial.get_value(&2.to_bigint().unwrap()),
            BigInt::from(47_i32)
        );

        // p(3) = 135
        assert_eq!(
            polynomial.get_value(&3.to_bigint().unwrap()),
            BigInt::from(135_i32)
        );
    }

    #[test]
    fn test_get_value2() {
        let q = BigInt::from(15486967);
        let coefficients = vec![
            BigInt::from(105211),
            BigInt::from(1548877),
            BigInt::from(892134),
            BigInt::from(3490857),
            BigInt::from(324),
            BigInt::from(14234735),
        ];
        let x = BigInt::from(278);
        let mut polynomial = Polynomial::new();

        polynomial.init_coefficients(&coefficients);

        assert_eq!(polynomial.get_value(&x) % q, BigInt::from(4115179));
    }
}
