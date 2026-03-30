use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use getrandom::fill;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

type HmacSha512 = Hmac<Sha512>;

/// Domain-separated Fiat-Shamir challenge.
/// c = SHA-512("WGZK-v1/schnorr-ristretto255" ‖ R_compressed ‖ session_nonce) mod ℓ
#[inline]
fn challenge(r_point: &RistrettoPoint, session_nonce: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"WGZK-v1/schnorr-ristretto255");
    h.update(r_point.compress().as_bytes());
    h.update(session_nonce);
    Scalar::from_hash(h)
}

/// Schnorr++ measure 2: hedged nonce.
/// r = HMAC-SHA512(sk_bytes, "WGZK-v1/hedged-nonce" ‖ OSRAND_64) mod ℓ
///
/// Combining secret-key material with fresh OS randomness provides resilience
/// against both RNG failures (deterministic component) and fault attacks
/// (random component).
fn hedged_nonce(sk_bytes: &[u8; 32]) -> Scalar {
    const SALT: &[u8] = b"WGZK-v1/hedged-nonce";
    let mut osrand = [0u8; 64];
    fill(&mut osrand).expect("rng");

    let mut mac = HmacSha512::new_from_slice(sk_bytes).expect("valid hmac key");
    mac.update(SALT);
    mac.update(&osrand);
    let tag = mac.finalize().into_bytes();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&tag);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Generate a fresh 32-byte session nonce for transcript binding.
pub fn gen_session_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    fill(&mut n).expect("rng");
    n
}

/// Schnorr++ prove.
/// π = (R, s) where R = r·G, c = H(domain ‖ R ‖ session_nonce), s = r + c·sk mod ℓ
///
/// Uses Ristretto255 (prime-order, no cofactor) and hedged nonce derivation.
pub fn prove(sk_x: &Scalar, session_nonce: &[u8]) -> ([u8; 32], [u8; 32]) {
    let sk_bytes: [u8; 32] = sk_x.to_bytes();
    let r = hedged_nonce(&sk_bytes);
    let r_point = &G * &r;
    let c = challenge(&r_point, session_nonce);
    let s = r + c * sk_x;
    (r_point.compress().to_bytes(), s.to_bytes())
}

/// Schnorr++ verify.
/// Checks s·G == R + c·X, with canonical encoding validation (measure 7).
pub fn verify(pk_bytes: &[u8; 32], r_bytes: &[u8; 32], s_bytes: &[u8; 32], session_nonce: &[u8]) -> bool {
    // Ristretto canonical decoding — rejects non-canonical encodings (measure 7)
    let Some(x_point) = CompressedRistretto(*pk_bytes).decompress() else { return false; };
    let Some(r_point) = CompressedRistretto(*r_bytes).decompress() else { return false; };

    // Canonical scalar — reject malleable inputs (measure 7)
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*s_bytes)) else { return false; };

    let c = challenge(&r_point, session_nonce);

    // Constant-time equality check via Ristretto (measure 8)
    (&G * &s) == (r_point + c * x_point)
}

pub fn parse_sk_hex(hex32: &str) -> anyhow::Result<Scalar> {
    let b = hex::decode(hex32.trim())?;
    if b.len() != 32 { anyhow::bail!("secret must be 32 bytes hex"); }
    Ok(Scalar::from_bytes_mod_order(b.as_slice().try_into().unwrap()))
}

pub fn parse_pk_hex(hex32: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(hex32.trim())?;
    if b.len() != 32 { anyhow::bail!("public must be 32 bytes hex (Ristretto255 compressed)"); }
    Ok(b.as_slice().try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_verify_roundtrip() {
        // Generate random key pair using Ristretto255
        let mut seed = [0u8; 32];
        fill(&mut seed).expect("rng");
        let sk = Scalar::from_bytes_mod_order(seed);
        let pk: [u8; 32] = (&G * &sk).compress().to_bytes();

        let session_nonce = gen_session_nonce();
        let (r, s) = prove(&sk, &session_nonce);
        assert!(verify(&pk, &r, &s, &session_nonce), "verify should succeed");
    }

    #[test]
    fn wrong_nonce_fails() {
        let mut seed = [0u8; 32];
        fill(&mut seed).expect("rng");
        let sk = Scalar::from_bytes_mod_order(seed);
        let pk: [u8; 32] = (&G * &sk).compress().to_bytes();

        let nonce1 = gen_session_nonce();
        let nonce2 = gen_session_nonce();
        let (r, s) = prove(&sk, &nonce1);
        assert!(!verify(&pk, &r, &s, &nonce2), "wrong nonce must fail");
    }

    #[test]
    fn wrong_key_fails() {
        let mut seed1 = [0u8; 32];
        let mut seed2 = [0u8; 32];
        fill(&mut seed1).expect("rng");
        fill(&mut seed2).expect("rng");
        let sk1 = Scalar::from_bytes_mod_order(seed1);
        let sk2 = Scalar::from_bytes_mod_order(seed2);
        let pk2: [u8; 32] = (&G * &sk2).compress().to_bytes();

        let nonce = gen_session_nonce();
        let (r, s) = prove(&sk1, &nonce);
        assert!(!verify(&pk2, &r, &s, &nonce), "wrong key must fail");
    }
}
