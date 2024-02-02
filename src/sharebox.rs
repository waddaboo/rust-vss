use std::collections::BTreeMap;

use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Debug, Clone, Default)]
pub struct ShareBox {
    pub publickey: BigInt,
    pub share: BigInt,
    pub challenge: BigInt,
    pub response: BigInt,
}

impl ShareBox {
    pub fn new() -> Self {
        ShareBox {
            publickey: BigInt::zero(),
            share: BigInt::zero(),
            challenge: BigInt::zero(),
            response: BigInt::zero(),
        }
    }

    pub fn init(&mut self, publickey: BigInt, share: BigInt, challenge: BigInt, response: BigInt) {
        self.publickey = publickey;
        self.share = share;
        self.challenge = challenge;
        self.response = response;
    }
}

#[derive(Debug, Clone, Default)]
pub struct DistributionShareBox {
    pub commitments: Vec<BigInt>,
    pub positions: BTreeMap<BigInt, i64>,
    pub shares: BTreeMap<BigInt, BigInt>,
    pub publickeys: Vec<BigInt>,
    pub challenge: BigInt,
    pub responses: BTreeMap<BigInt, BigInt>,
    pub u: BigInt,
}

impl DistributionShareBox {
    pub fn new() -> Self {
        DistributionShareBox {
            commitments: Vec::new(),
            positions: BTreeMap::new(),
            shares: BTreeMap::new(),
            publickeys: Vec::new(),
            challenge: BigInt::zero(),
            responses: BTreeMap::new(),
            u: BigInt::zero(),
        }
    }

    pub fn init(
        &mut self,
        commitments: &[BigInt],
        positions: BTreeMap<BigInt, i64>,
        shares: BTreeMap<BigInt, BigInt>,
        publickeys: &[BigInt],
        challenge: &BigInt,
        responses: BTreeMap<BigInt, BigInt>,
        u: &BigInt,
    ) {
        self.commitments = commitments.to_vec();
        self.positions = positions;
        self.shares = shares;
        self.publickeys = publickeys.to_vec();
        self.challenge = challenge.clone();
        self.responses = responses;
        self.u = u.clone();
    }
}
