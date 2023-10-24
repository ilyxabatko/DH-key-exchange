use blake2::{self, digest::Update, digest::VariableOutput};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

const XCHACHA20_POLY1305_KEY_SIZE: usize = 32;
pub const XCHACHA20_POLY1305_NONCE_SIZE: usize = 24;

fn main() {
    // Create a nonce (non-repeating num), sometimes it's called salt.
    let nonce = [0u8; XCHACHA20_POLY1305_NONCE_SIZE];

    // Generating private and public keys for both parties.
    let alice_private_key = EphemeralSecret::random_from_rng(OsRng);
    let alice_public_key = PublicKey::from(&alice_private_key);

    let bob_private_key = EphemeralSecret::random_from_rng(OsRng);
    let bob_public_key = PublicKey::from(&bob_private_key);

    // Then we have to derive the shared secret from both parties:
    // Bob needs Alice's public key;
    // Alice needs Bob's public key;
    let bob_secret = derive_secret_for_bob(bob_private_key, &alice_public_key, &nonce);
    let alice_secret = derive_secret_for_alice(alice_private_key, &bob_public_key, &nonce);

    // Checks if both generated shared secrets are equal
    assert_eq!(&bob_secret, &alice_secret);
    println!("Shared secrets are equal!");
}

fn derive_secret_for_bob(
    bob_private_key: EphemeralSecret,
    alice_public_key: &PublicKey,
    nonce: &[u8; XCHACHA20_POLY1305_NONCE_SIZE],
) -> Vec<u8> {
    let dh_secret = bob_private_key.diffie_hellman(&alice_public_key);

    // Using Blake2 function with the Diffie-Hellman secret to generate a cryptographically secure key
    let mut kdf =
        blake2::VarBlake2b::new_keyed(dh_secret.as_bytes(), XCHACHA20_POLY1305_KEY_SIZE);
    kdf.update(nonce);

    let shared_key = kdf.finalize_boxed();

    // Turns Boxed array of bytes into a vector of bytes
    shared_key.into()
}

fn derive_secret_for_alice(
    alice_private_key: EphemeralSecret,
    bob_public_key: &PublicKey,
    nonce: &[u8; XCHACHA20_POLY1305_NONCE_SIZE],
) -> Vec<u8> {
    let dh_secret = alice_private_key.diffie_hellman(&bob_public_key);

    // using key derivation function
    let mut kdf =
        blake2::VarBlake2b::new_keyed(dh_secret.as_bytes(), XCHACHA20_POLY1305_KEY_SIZE);
    kdf.update(nonce);

    let shared_key = kdf.finalize_boxed();

    shared_key.into()
}
