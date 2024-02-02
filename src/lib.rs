use num_bigint::{BigInt, BigUint, ToBigInt};

mod dleq;
mod participant;
mod polynomial;
mod sharebox;
mod util;
mod vss;

pub use participant::Participant;
pub use sharebox::{DistributionShareBox, ShareBox};

pub fn string_to_secret(message: &str) -> BigInt {
    BigUint::from_bytes_be(message.as_bytes())
        .to_bigint()
        .unwrap()
}

pub fn string_from_secret(secret: &BigInt) -> String {
    String::from_utf8(secret.to_biguint().unwrap().to_bytes_be()).unwrap()
}
