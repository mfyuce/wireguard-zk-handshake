use ed25519_dalek::{SigningKey, VerifyingKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 32 bayt rastgele seed üret
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?; // getrandom 0.2 API

    // Ed25519 signing key + public key (compressed Edwards-Y)
    let sk = SigningKey::from_bytes(&seed);
    let pk: VerifyingKey = sk.verifying_key();

    // 32 bayt public key → 64 hex karakter
    println!("{}", hex::encode(pk.to_bytes()));
    Ok(())
}
