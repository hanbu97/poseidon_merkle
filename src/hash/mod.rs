use ark_ff::PrimeField;
use ark_ff::Zero;
use zkhash::{
    fields::{bn256::FpBN256, goldilocks::FpGoldiLocks, vesta::FpVesta},
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS,
        poseidon2_instance_goldilocks::{
            POSEIDON2_GOLDILOCKS_12_PARAMS, POSEIDON2_GOLDILOCKS_16_PARAMS,
            POSEIDON2_GOLDILOCKS_20_PARAMS, POSEIDON2_GOLDILOCKS_8_PARAMS,
        },
        poseidon2_instance_vesta::POSEIDON2_VESTA_PARAMS,
    },
};

use self::poseidon::PoseidonMethod;

pub trait HashFunction<F: PrimeField> {
    fn hash(&self, left: &F, right: &F) -> anyhow::Result<Vec<F>>;
    fn zero(&self) -> F;
    fn pad(&self, ileft: &F, right: &F) -> Vec<F>;
}

pub enum PoseidonHasher {
    Bn256(Poseidon2<FpBN256>),
    Goldilocks(Poseidon2<FpGoldiLocks>),
    Vesta(Poseidon2<FpVesta>),
}

impl PoseidonHasher {
    pub fn new(method: PoseidonMethod) -> anyhow::Result<Self> {
        match method {
            PoseidonMethod::Bn256 => {
                let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
                Ok(PoseidonHasher::Bn256(poseidon2))
            }
            PoseidonMethod::Goldilocks(rounds) => {
                let poseidon2 = match rounds {
                    8 => Poseidon2::new(&POSEIDON2_GOLDILOCKS_8_PARAMS),
                    12 => Poseidon2::new(&POSEIDON2_GOLDILOCKS_12_PARAMS),
                    16 => Poseidon2::new(&POSEIDON2_GOLDILOCKS_16_PARAMS),
                    20 => Poseidon2::new(&POSEIDON2_GOLDILOCKS_20_PARAMS),
                    _ => {
                        return Err(anyhow::anyhow!(
                            "Invalid rounds number for Goldilocks Poseidon hash function"
                        ))
                    }
                };
                Ok(PoseidonHasher::Goldilocks(poseidon2))
            }
            PoseidonMethod::Vesta => {
                let poseidon2 = Poseidon2::new(&POSEIDON2_VESTA_PARAMS);
                Ok(PoseidonHasher::Vesta(poseidon2))
            }
        }
    }
}

#[derive(Clone, Copy)]
pub enum Hashable {
    BN256(zkhash::fields::bn256::FpBN256),
    Goldilocks(zkhash::fields::goldilocks::FpGoldiLocks),
    Vesta(zkhash::fields::vesta::FpVesta),
}

impl From<zkhash::fields::bn256::FpBN256> for Hashable {
    fn from(value: zkhash::fields::bn256::FpBN256) -> Self {
        Hashable::BN256(value)
    }
}

impl From<zkhash::fields::goldilocks::FpGoldiLocks> for Hashable {
    fn from(value: zkhash::fields::goldilocks::FpGoldiLocks) -> Self {
        Hashable::Goldilocks(value)
    }
}

impl From<zkhash::fields::vesta::FpVesta> for Hashable {
    fn from(value: zkhash::fields::vesta::FpVesta) -> Self {
        Hashable::Vesta(value)
    }
}

impl Hashable {
    pub fn zero(&self) -> Self {
        match self {
            Hashable::BN256(_) => Hashable::BN256(FpBN256::zero()),
            Hashable::Goldilocks(_) => Hashable::Goldilocks(FpGoldiLocks::zero()),
            Hashable::Vesta(_) => Hashable::Vesta(FpVesta::zero()),
        }
    }

    pub fn hash(
        left: &Self,
        right: &Self,
        hasher: &PoseidonHasher,
        padding: &[Self],
    ) -> anyhow::Result<Vec<Self>> {
        match (left, right, hasher) {
            (Hashable::BN256(l), Hashable::BN256(r), PoseidonHasher::Bn256(h))
                if padding.iter().all(|p| matches!(p, Hashable::BN256(_))) =>
            {
                let mut input = vec![];
                for p in padding {
                    if let Hashable::BN256(value) = p {
                        input.push(*value);
                    }
                }
                input.push(*l);
                input.push(*r);

                Ok(h.permutation(&input)
                    .into_iter()
                    .map(Hashable::BN256)
                    .collect())
            }
            (Hashable::Goldilocks(l), Hashable::Goldilocks(r), PoseidonHasher::Goldilocks(h))
                if padding.iter().all(|p| matches!(p, Hashable::Goldilocks(_))) =>
            {
                let mut input = vec![];
                for p in padding {
                    if let Hashable::Goldilocks(value) = p {
                        input.push(*value);
                    }
                }
                input.push(*l);
                input.push(*r);

                Ok(h.permutation(&input)
                    .into_iter()
                    .map(Hashable::Goldilocks)
                    .collect())
            }
            (Hashable::Vesta(l), Hashable::Vesta(r), PoseidonHasher::Vesta(h))
                if padding.iter().all(|p| matches!(p, Hashable::Vesta(_))) =>
            {
                let mut input = vec![];
                for p in padding {
                    if let Hashable::Vesta(value) = p {
                        input.push(*value);
                    }
                }
                input.push(*l);
                input.push(*r);

                Ok(h.permutation(&input)
                    .into_iter()
                    .map(Hashable::Vesta)
                    .collect())
            }
            _ => Err(anyhow::anyhow!("Not implemented yet")),
        }
    }
}

pub mod poseidon;
