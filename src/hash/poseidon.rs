use ark_ff::PrimeField;
use serde::de::DeserializeOwned;
use zkhash::{
    fields::{
        bn256::FpBN256,
        goldilocks::FpGoldiLocks,
        utils::{decode_from_cbor_string, encode_to_cbor_string, from_hex, random_scalar, to_hex},
        vesta::FpVesta,
    },
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

// Poseidon hash
pub struct PoseidonHash<F: PrimeField> {
    pub method: PoseidonMethod,
    // padding input with
    pub summary: Vec<F>,
    // padding function
    pub summary_fn: Option<fn(&[F], usize, left: &F, right: &F) -> Vec<F>>,
    // hasher
    pub hasher: Poseidon2<F>,
}

impl<F: PrimeField> super::HashFunction<F> for PoseidonHash<F> {
    // impl<F: PrimeField> PoseidonHash<F> {
    fn zero(&self) -> F {
        let zero = F::zero();
        zero
    }

    fn pad(&self, left: &F, right: &F) -> Vec<F> {
        if let Some(summary_fn) = self.summary_fn {
            return summary_fn(&[], self.method.statesize(), left, right);
        } else {
            let mut padding = self.summary.clone();
            padding.push(left.to_owned());
            padding.push(right.to_owned());
            return padding;
        }
    }

    fn hash(&self, left: &F, right: &F) -> anyhow::Result<Vec<F>> {
        let input = self.pad(left, right);
        Ok(self.hasher.permutation(&input))
    }
}

impl<F: PrimeField> PoseidonHash<F> {
    pub fn new_for_bintree(
        method: PoseidonMethod,
        summary: Option<Vec<F>>,
        rand: bool,
        summary_fn: Option<fn(&[F], usize, left: &F, right: &F) -> Vec<F>>,
        hasher: Poseidon2<F>,
    ) -> anyhow::Result<Self> {
        if summary_fn.is_some() {
            return Ok(PoseidonHash {
                method,
                summary: vec![],
                summary_fn,
                hasher,
            });
        }

        let input_len = method.statesize();
        let pad_len = input_len - 2; // 2 for bin tree
        let mut padding = vec![];
        if let Some(summary) = summary {
            for i in 0..pad_len {
                padding.push(summary[i].clone());
            }
        } else {
            if rand {
                padding = method.input_rand_gen()?[..pad_len].to_vec();
            } else {
                padding = method.input_zero()[..pad_len].to_vec();
            }
        }

        Ok(PoseidonHash {
            method,
            summary: padding,
            summary_fn,
            hasher,
        })
    }
}

// Poseidon hash function
pub enum PoseidonMethod {
    Bn256,
    Goldilocks(usize),
    Vesta,
}

impl PoseidonMethod {
    pub fn new_bn256() -> anyhow::Result<Poseidon2<FpBN256>> {
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
        Ok(poseidon2)
    }

    pub fn new_goldilocks(rounds: usize) -> anyhow::Result<Poseidon2<FpGoldiLocks>> {
        // check if rounds is valid(8, 12, 16, 20)
        if rounds != 8 && rounds != 12 && rounds != 16 && rounds != 20 {
            return Err(anyhow::anyhow!(
                "Invalid rounds number for Goldilocks Poseidon hash function"
            ));
        }

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

        Ok(poseidon2)
    }

    pub fn new_vesta() -> anyhow::Result<Poseidon2<FpVesta>> {
        let poseidon2 = Poseidon2::new(&POSEIDON2_VESTA_PARAMS);
        Ok(poseidon2)
    }

    // get statesize
    pub fn statesize(&self) -> usize {
        match self {
            PoseidonMethod::Bn256 => 3,
            PoseidonMethod::Goldilocks(len) => len.to_owned(),
            PoseidonMethod::Vesta => 3,
        }
    }

    // gen reandom input
    pub fn input_rand_gen<F: PrimeField>(&self) -> anyhow::Result<Vec<F>> {
        let t = self.statesize();
        let input = (0..t).map(|_| random_scalar()).collect();

        Ok(input)
    }

    // read input from string array
    pub fn input_read_from_hex_string_array<F: PrimeField>(
        &self,
        input: &[&str],
    ) -> anyhow::Result<Vec<F>> {
        let t = self.statesize();
        // check length
        if input.len() != t {
            return Err(anyhow::anyhow!(
                "Invalid input length for Poseidon hash function"
            ));
        }

        // read to F vector
        let data: Vec<F> = input
            .into_iter()
            .map(|s| {
                let data = from_hex(s);
                data
            })
            .collect();

        Ok(data)
    }

    // read input from cbor
    pub fn input_read_from_cbor<F: PrimeField + DeserializeOwned>(
        &self,
        input: &str,
    ) -> anyhow::Result<Vec<F>> {
        let t = self.statesize();
        // decode cbor
        let data: Vec<F> = decode_from_cbor_string(input);
        // check length
        if data.len() != t {
            return Err(anyhow::anyhow!(
                "Invalid input length for Poseidon hash function"
            ));
        }

        Ok(data)
    }

    // parse input to string array
    pub fn input_parse_to_hex_string_array<F: PrimeField>(
        &self,
        input: &[F],
    ) -> anyhow::Result<Vec<String>> {
        // parse to string array
        let data: Vec<String> = to_hex(input);
        Ok(data)
    }

    // parse input to cbor
    pub fn input_parse_to_cbor_string<F: PrimeField>(&self, input: &[F]) -> String {
        // parse to cbor
        let data: String = encode_to_cbor_string(input);
        data
    }

    // zero
    pub fn zero<F: PrimeField>(&self) -> F {
        let zero = F::zero();
        zero
    }

    // zero input
    pub fn input_zero<F: PrimeField>(&self) -> Vec<F> {
        let t = self.statesize();
        let input = (0..t).map(|_| self.zero()).collect();

        input
    }
}
