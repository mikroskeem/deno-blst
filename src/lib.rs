#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::{
    ops::DerefMut,
    sync::{Mutex, MutexGuard, OnceLock},
};

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};
use bls_signatures::{PrivateKey, PublicKey, Serialize, Signature};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[cfg(not(target_arch = "wasm32"))]
use deno_bindgen::deno_bindgen;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

pub type StdError = Box<dyn std::error::Error + Send + Sync>;

static RANDOM: OnceLock<Mutex<ChaCha8Rng>> = OnceLock::new();

fn get_rng<'a>() -> MutexGuard<'a, ChaCha8Rng> {
    let rng = RANDOM.get_or_init(|| Mutex::new(ChaCha8Rng::from_entropy()));

    rng.lock().expect("lock poisoned")
}

fn load_public_key(public_key: &[u8]) -> Result<PublicKey, StdError> {
    let g1_affine = match public_key.len() {
        48 => {
            let result = G1Affine::from_compressed(public_key.try_into()?);
            if result.is_none().into() {
                Err(StdError::from("public key must be a valid g1 point"))
            } else {
                Ok(result.unwrap())
            }
        }
        96 => {
            let result = G1Affine::from_uncompressed(public_key.try_into()?);
            if result.is_none().into() {
                Err(StdError::from("public key must be a valid g1 point"))
            } else {
                Ok(result.unwrap())
            }
        }
        l => Err(StdError::from(format!(
            "public key must be exactly 48 or 96 bytes, got {}",
            l
        ))),
    }?;

    let projective = G1Projective::from(g1_affine);
    Ok(PublicKey::from(projective))
}

fn load_private_key(private_key: &[u8]) -> Result<PrivateKey, StdError> {
    let scalar = match private_key.len() {
        32 => {
            let result = Scalar::from_bytes(private_key.try_into()?);
            if result.is_none().into() {
                Err(StdError::from("private key must be a valid scalar"))
            } else {
                Ok(result.unwrap())
            }
        }
        64 => Ok(bls12_381::Scalar::from_bytes_wide(private_key.try_into()?)),
        l => Err(StdError::from(format!(
            "private key must be exactly 32 or 64 bytes, got {}",
            l
        ))),
    }?;

    Ok(PrivateKey::from(scalar))
}

fn load_signature(signature: &[u8]) -> Result<Signature, StdError> {
    let g2_affine = match signature.len() {
        96 => {
            let result = G2Affine::from_compressed(signature.try_into()?);
            if result.is_none().into() {
                Err(StdError::from("signature must be a valid g2 point"))
            } else {
                Ok(result.unwrap())
            }
        }
        192 => {
            let result = G2Affine::from_uncompressed(signature.try_into()?);
            if result.is_none().into() {
                Err(StdError::from("signature must be a valid g2 point"))
            } else {
                Ok(result.unwrap())
            }
        }
        l => Err(StdError::from(format!(
            "signature must be exactly 96 or 192 bytes, got {}",
            l
        ))),
    }?;

    Ok(Signature::from(g2_affine))
}

#[cfg_attr(not(target_arch = "wasm32"), deno_bindgen(non_blocking))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn get_random(n: usize) -> Vec<u8> {
    let mut rng = get_rng();

    let mut buf = Vec::with_capacity(n);
    rng.deref_mut().fill_bytes(&mut buf);

    buf
}

#[cfg_attr(not(target_arch = "wasm32"), deno_bindgen(non_blocking))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn generate_private_key_seed(seed: &[u8]) -> Vec<u8> {
    PrivateKey::new(seed).as_bytes()
}

#[cfg_attr(not(target_arch = "wasm32"), deno_bindgen(non_blocking))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn generate_private_key_random() -> Vec<u8> {
    let mut rng = get_rng();

    PrivateKey::generate(rng.deref_mut()).as_bytes()
}

#[cfg_attr(not(target_arch = "wasm32"), deno_bindgen(non_blocking))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn get_public_key(private_key: &[u8]) -> Vec<u8> {
    load_private_key(private_key)
        .expect("unable to load private key")
        .public_key()
        .as_bytes()
}

#[cfg_attr(not(target_arch = "wasm32"), deno_bindgen(non_blocking))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    load_private_key(private_key)
        .expect("unable to load private key")
        .sign(message)
        .as_bytes()
}

#[cfg_attr(not(target_arch = "wasm32"), deno_bindgen(non_blocking))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> u8 {
    let public_key = load_public_key(public_key).expect("unable to load public key");
    let signature = load_signature(signature).expect("unable to load signature");
    let result = public_key.verify(signature, message);

    if result {
        1
    } else {
        0
    }
}
