use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use getrandom::fill;
use sha2::{Digest, Sha512};

#[inline]
fn challenge(R: &EdwardsPoint, extra: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"WGZK-v1/schnorr-ed25519");
    h.update(R.compress().as_bytes());
    h.update(extra);
    Scalar::from_hash(h)
}

pub fn prove(sk_x: &Scalar, extra: &[u8]) -> ([u8; 32], [u8; 32]) {
    // r = H(rand64) mod l
    let mut buf = [0u8; 64];
    fill(&mut buf).expect("rng");
    let r = Scalar::from_bytes_mod_order_wide(&buf);
    let R = &G * &r;
    let c = challenge(&R, extra);
    let s = r + c * sk_x;
    (R.compress().to_bytes(), s.to_bytes())
}

pub fn verify(pk_x_bytes: &[u8; 32], r_bytes: &[u8; 32], s_bytes: &[u8; 32], extra: &[u8]) -> bool {
    let Some(X) = CompressedEdwardsY(*pk_x_bytes).decompress() else { return false; };
    let Some(R) = CompressedEdwardsY(*r_bytes).decompress() else { return false; };
    let s = Scalar::from_canonical_bytes(*s_bytes)
        .unwrap_or_else(|| Scalar::from_bytes_mod_order(*s_bytes));
    let c = challenge(&R, extra);
    (&G * &s) == (R + c * X)
}

pub fn parse_sk_hex(hex32: &str) -> anyhow::Result<Scalar> {
    let b = hex::decode(hex32.trim())?;
    if b.len() != 32 { anyhow::bail!("secret must be 32 bytes hex"); }
    Ok(Scalar::from_bytes_mod_order(b.as_slice().try_into().unwrap()))
}
pub fn parse_pk_hex(hex32: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(hex32.trim())?;
    if b.len() != 32 { anyhow::bail!("public must be 32 bytes hex"); }
    Ok(b.as_slice().try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::fill;

    #[test]
    fn prove_verify_roundtrip() {
        let sk_hex = "852d598bbbf3a329d4366e0a592f520a33a36f398dd7a9793f4917f58daf3f09";
        let pk_hex = "bb62278f97fb18e0e61918a7c0f9d77f0d9f0c90c326af6c16be6b71d3b73cb1";
        let sk = parse_sk_hex(sk_hex).unwrap();
        let pk = parse_pk_hex(pk_hex).unwrap();

        // verify PK matches SK
        let computed_pk = (&G * &sk).compress().to_bytes();
        assert_eq!(computed_pk, pk, "PK does not match SK!");

        // prove/verify
        let (r, s) = prove(&sk, b"");
        assert!(verify(&pk, &r, &s, b""), "verify failed!");
    }
}
