use ark_ff::PrimeField;
use serde::de::DeserializeOwned;
use zkhash::{
    fields::utils::{
        decode_from_cbor_string, encode_to_cbor_string, from_hex, random_scalar, to_hex,
    },
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
};

// Poseidon hash
pub struct PoseidonHash<F: PrimeField> {
    pub method: PoseidonMethod,
    // padding input with
    pub summary: Option<Vec<F>>,
    // padding function
    pub padding: Option<fn(&[F], usize, left: &[F], right: &[F]) -> Vec<F>>,
}

// Poseidon hash function
pub enum PoseidonMethod {
    Bn256,
    Goldilocks(usize),
    Vesta,
}

impl PoseidonMethod {
    pub fn new_bn256() -> anyhow::Result<Self> {
        Ok(PoseidonMethod::Bn256)
    }

    pub fn new_goldilocks(rounds: usize) -> anyhow::Result<Self> {
        // check if rounds is valid(8, 12, 16, 20)
        if rounds != 8 && rounds != 12 && rounds != 16 && rounds != 20 {
            return Err(anyhow::anyhow!(
                "Invalid rounds number for Goldilocks Poseidon hash function"
            ));
        }

        Ok(PoseidonMethod::Goldilocks(rounds))
    }

    pub fn new_vesta() -> anyhow::Result<Self> {
        Ok(PoseidonMethod::Vesta)
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

// impl HashFunction for Poseidon {
//     fn hash<F: PrimeField>(&self, left: &[F], right: &[F]) -> anyhow::Result<F> {
//         // match self {
//         //     Poseidon::Bn256 => {
//         //         let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS);

//         //         let hash = hasher.hash();
//         //         Ok(hash)
//         //     }
//         //     Poseidon::Goldilocks(rounds) => {
//         //         let mut hasher = PoseidonGoldilocks::new_with_preimage(input, *rounds);
//         //         let hash = hasher.hash();
//         //         Ok(hash)
//         //     }
//         //     Poseidon::Vesta => {
//         //         let mut hasher = PoseidonVesta::new_with_preimage(input);
//         //         let hash = hasher.hash();
//         //         Ok(hash)
//         //     }
//         // }
//     }
// }
