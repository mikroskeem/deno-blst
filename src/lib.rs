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
            let b: &[u8; 48] = &public_key[0..48].try_into()?;

            let result = G1Affine::from_compressed(b);
            if result.is_none().into() {
                Err(StdError::from("public key must be a valid g1 point"))
            } else {
                Ok(result.unwrap())
            }
        }
        96 => {
            let b: &[u8; 96] = &public_key[0..96].try_into()?;

            let result = G1Affine::from_uncompressed(b);
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
            let b: &[u8; 32] = private_key[0..32].try_into()?;

            let result = Scalar::from_bytes(b);
            if result.is_none().into() {
                Err(StdError::from("private key must be a valid scalar"))
            } else {
                Ok(result.unwrap())
            }
        }
        64 => {
            let b: &[u8; 64] = private_key[0..64].try_into()?;

            Ok(bls12_381::Scalar::from_bytes_wide(b))
        }
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
            let b: &[u8; 96] = &signature[0..96].try_into()?;

            let result = G2Affine::from_compressed(b);
            if result.is_none().into() {
                Err(StdError::from("signature must be a valid g2 point"))
            } else {
                Ok(result.unwrap())
            }
        }
        192 => {
            let b: &[u8; 192] = &signature[0..192].try_into()?;

            let result = G2Affine::from_uncompressed(b);
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

#[deno_bindgen]
pub fn generate_key() -> Vec<u8> {
    let mut rng = ChaCha8Rng::from_entropy();

    PrivateKey::generate(&mut rng).as_bytes()
}

#[deno_bindgen]
pub fn get_public_key(private_key: &[u8]) -> Vec<u8> {
    load_private_key(private_key)
        .expect("unable to load private key")
        .public_key()
        .as_bytes()
}

#[deno_bindgen]
pub fn sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    load_private_key(private_key)
        .expect("unable to load private key")
        .sign(message)
        .as_bytes()
}

#[deno_bindgen]
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
