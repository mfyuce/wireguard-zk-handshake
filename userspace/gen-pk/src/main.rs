use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as G,
    edwards::EdwardsPoint,
    scalar::Scalar,
};
use getrandom::fill; // 0.3 API
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 32 bayt rastgele tohum
    let mut seed = [0u8; 32];
    fill(&mut seed)?; // getrandom 0.3.3

    // Tohumu skalar'a çevir (Schnorr için yeterli)
    let sk: Scalar = Scalar::from_bytes_mod_order(seed);

    // Public key: X = sk * G
    let pk_point: EdwardsPoint = &G * &sk;
    let pk: [u8; 32] = pk_point.compress().to_bytes();

    // Skaların kanonik 32-bayt gösterimi
    let sk_bytes: [u8; 32] = sk.to_bytes();

    // Çıktılar (daemon’daki WGZK_* env değişkenleriyle birebir uyumlu)
    println!("{}", hex::encode(pk)); // sadece PK
    println!("WGZK_SK_HEX={}", hex::encode(sk_bytes));
    println!("WGZK_PK_HEX={}", hex::encode(pk));

    Ok(())
}
