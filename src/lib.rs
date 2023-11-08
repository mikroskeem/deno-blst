#![allow(clippy::not_unsafe_ptr_arg_deref)]

use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};
use bls_signatures::{PrivateKey, PublicKey, Serialize, Signature};
use deno_bindgen::deno_bindgen;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub type StdError = Box<dyn std::error::Error + Send + Sync>;

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

#[deno_bindgen(non_blocking)]
pub fn generate_key() -> Vec<u8> {
    let mut rng = ChaCha8Rng::from_entropy();

    PrivateKey::generate(&mut rng).as_bytes()
}

#[deno_bindgen(non_blocking)]
pub fn get_public_key(private_key: &[u8]) -> Vec<u8> {
    load_private_key(private_key)
        .expect("unable to load private key")
        .public_key()
        .as_bytes()
}

#[deno_bindgen(non_blocking)]
pub fn sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    load_private_key(private_key)
        .expect("unable to load private key")
        .sign(message)
        .as_bytes()
}

#[deno_bindgen(non_blocking)]
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
