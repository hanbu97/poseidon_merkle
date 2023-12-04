use ark_ff::PrimeField;
// use rand::{thread_rng, Rng};
// use sha3::digest::XofReader;
// use std::cmp::min;
// use core::num::ParseIntError;
use crate::ark_ff::BigInteger;
use hex::FromHex;

// use cbor4ii::serde::{from_reader, to_writer};
use cbor4ii::serde::{from_slice, to_vec};
use data_encoding::BASE64;
use serde::de::DeserializeOwned;

pub fn from_hex<F: PrimeField>(s: &str) -> F {
    let a = Vec::from_hex(&s[2..]).expect("Invalid Hex String");
    F::from_be_bytes_mod_order(&a as &[u8])
}

pub fn random_scalar<F: PrimeField>() -> F {
    let mut rng = ark_std::rand::thread_rng();
    F::rand(&mut rng)
}

pub fn random_scalar_without_0<F: PrimeField>() -> F {
    loop {
        let element = random_scalar::<F>();
        if !element.is_zero() {
            return element;
        }
    }
}

pub fn to_hex<F: PrimeField>(field_elements: &[F]) -> Vec<String> {
    field_elements
        .iter()
        .map(|element| {
            let big_int = element.into_bigint(); // Convert the element to its BigInteger representation
            let bytes = big_int.to_bytes_be(); // Convert the BigInteger to a byte array in big-endian
            format!("0x{}", hex::encode(bytes)) // Prepend '0x' to the hexadecimal string
        })
        .collect() // Collect the converted strings into a Vec
}

pub fn encode_to_cbor_string<F: PrimeField>(field_elements: &[F]) -> String {
    // TODO: cbor size opt
    // let elements: Vec<<F as PrimeField>::BigInt> = field_elements
    //     .iter()
    //     .map(|element| {
    //         let big_int = element.into_bigint(); // Convert the element to its BigInteger representation
    //         big_int
    //     })
    //     .collect();
    let elements: Vec<Vec<u8>> = field_elements
        .iter()
        .map(|element| {
            let big_int: <F as PrimeField>::BigInt = element.into_bigint(); // Convert the element to its BigInteger representation
            let bytes = big_int.to_bytes_be(); // Convert the BigInteger to a byte array in big-endian

            bytes
        })
        .collect();

    let buf = to_vec(Vec::new(), &elements).expect("CBOR encoding failed");
    BASE64.encode(&buf)
}

pub fn encode_to_cbor_string_slim<F: PrimeField>(field_elements: &[F]) -> String {
    let elements: Vec<Vec<u8>> = field_elements
        .iter()
        .map(|element| {
            let big_int = element.into_bigint(); // Convert the element to its BigInteger representation
            let limbs = big_int.as_ref();

            // Find the highest non-zero limb
            let last_non_zero = limbs.iter().rposition(|&limb| limb != 0).unwrap_or(0);

            // Serialize only the necessary limbs
            let necessary_limbs = &limbs[..=last_non_zero];
            necessary_limbs
                .iter()
                .flat_map(|&limb| limb.to_be_bytes())
                .collect()
        })
        .collect();

    let buf = to_vec(Vec::new(), &elements).expect("CBOR encoding failed");
    BASE64.encode(&buf)
}

// g5ggCxi2GB0YJBjaGMoYVRjuGLwYsRiSGJoYghhlDxgyGIEYNBgzGE0YqRiOGKQY+BhHGPcYYAUYTxhKGDAYM5ggGDAYOxhvGHwYhhjQGEMYvxjLGMwYgBghGE8YJhijAhh3GKEYXRg/GHQYyhhlGEkYkhjeGP4Yfxj4GNAYNRhwmCAYHhjSGFEYlBhUGCsSGO4Y+BhhGHMYYRjDGLoYfBhSGOYYYBixGEUYmRhEGCcYzBiGGCkYYhhCGM8YdhhuGMg="

pub fn decode_from_cbor_string<F: PrimeField + DeserializeOwned>(encoded_str: &str) -> Vec<F> {
    // Decode the Base64 string into a CBOR byte sequence
    let cbor_bytes = BASE64
        .decode(encoded_str.as_bytes())
        .expect("Failed to decode Base64");

    // Deserialize the CBOR byte sequence into Vec<Vec<u8>>
    let byte_arrays: Vec<Vec<u8>> = from_slice(&cbor_bytes).expect("Failed to decode CBOR");

    // Convert each byte array back to a PrimeField element
    byte_arrays
        .into_iter()
        .map(|bytes| F::from_be_bytes_mod_order(&bytes))
        .collect()
}

//-----------------------------------------------------------------------------
// pub fn from_u64<F: PrimeField>(val: u64) -> F {
//     F::from_repr(F::Repr::from(val)).unwrap()
// }

// pub fn random_scalar_rng<F: PrimeField, R: Rng>(allow_zero: bool, rng: &mut R) -> F {
//     loop {
//         let s = F::rand(rng);
//         if allow_zero || s != F::zero() {
//             return s;
//         }
//     }
// }

// pub fn random_scalar<F: PrimeField>(allow_zero: bool) -> F {
//     loop {
//         let s = F::rand(&mut thread_rng());
//         if allow_zero || s != F::zero() {
//             return s;
//         }
//     }
// }

// pub fn into_limbs<F: PrimeField>(val: &F) -> Vec<u64> {
//     val.into_repr().as_ref().to_owned()
// }

// pub fn from_limbs<F: PrimeField>(repr: &[u64]) -> F {
//     let mut tmp = F::Repr::default();
//     tmp.as_mut().copy_from_slice(repr);
//     F::from_repr(tmp).unwrap()
// }

// fn from_limbs_with_error<F: PrimeField>(repr: &[u64]) -> F {
//     let mut tmp = F::Repr::default();
//     tmp.as_mut().copy_from_slice(repr);
//     F::from_repr(tmp)
// }

// pub fn field_element_from_shake<F: PrimeField>(reader: &mut dyn XofReader) -> F {
//     let bytes = f64::ceil(F::MODULUS_BIT_SIZE as f64 / 8f64) as usize;
//     let mut words = f64::ceil(bytes as f64 / 8f64) as usize;
//     if F::MODULUS_BIT_SIZE == 64 { // Quick and dirty fix for Goldilocks
//         words = 2;
//     }

//     let mod_ = F::NUM_BITS % 8;
//     let mask = if mod_ == 0 { 0xFF } else { (1u8 << mod_) - 1 };
//     let mut buf = vec![0u8; bytes];
//     let mut word_buf = vec![0u64; words];

//     let len = buf.len();
//     loop {
//         reader.read(&mut buf);
//         buf[len - 1] &= mask;
//         for i in 0..words {
//             let mut byte_array = [0u8; 8];
//             for j in i * 8..min((i + 1) * 8, len) {
//                 byte_array[j - i * 8] = buf[j];
//             }
//             word_buf[i] = u64::from_le_bytes(byte_array);
//         }
//         let res = from_limbs_with_error::<F>(&word_buf);
//         if let Ok(el) = res {
//             return el;
//         }
//     }
// }

// pub fn field_element_from_shake_without_0<F: PrimeField>(reader: &mut dyn XofReader) -> F {
//     loop {
//         let element = field_element_from_shake::<F>(reader);
//         if !element.is_zero() {
//             return element;
//         }
//     }
// }
