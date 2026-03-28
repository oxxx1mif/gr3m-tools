/*
 * Copyright (C) 2026 GGroup, Gleb Obitotsky, Gteam.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

use pqcrypto_kyber::kyber768;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};
use rand_core::{OsRng, RngCore};
use blake3;
use argon2::{Argon2, password_hash::SaltString};

pub struct HybridKeystream {
    pub aes_key: [u8; 32],
}

impl HybridKeystream {
    pub fn new_ultra_secure(x25519_shared: [u8; 32], kyber_shared: [u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&x25519_shared);
        hasher.update(&kyber_shared);
        hasher.update(b"GhostMesh-Inital-Entropy");
        let intermediate_hash = hasher.finalize();

        let salt = b"GhostMesh_Static_Salt_32_Bytes__"; 
        let mut final_key = [0u8; 32];
        
        let argon2 = Argon2::default();
        argon2.hash_password_into(intermediate_hash.as_bytes(), salt, &mut final_key)
            .expect("Argon2 execution failed");

        Self { aes_key: final_key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::{SharedSecret, PublicKey};

    #[test]
    fn test_full_ultra_hybrid_handshake() {
        println!("\n================================================");
        println!("   MESH SECURE HYBRID    ");
        println!("================================================\n");

        let client_x_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_x_pub = XPublicKey::from(&client_x_secret);
        
        let server_x_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_x_pub = XPublicKey::from(&server_x_secret);

        let x_shared_client = client_x_secret.diffie_hellman(&server_x_pub);
        let x_shared_server = server_x_secret.diffie_hellman(&client_x_pub);

        println!("[L1] X25519 Shared (first 16b): {:02x?}", &x_shared_client.as_bytes()[..16]);

        let (pk_k, sk_k) = kyber768::keypair();
        let (ss_k_client, ct_k) = kyber768::encapsulate(&pk_k);
        let ss_k_server = kyber768::decapsulate(&ct_k, &sk_k);
        
        println!("[L2] Kyber-768 Shared (first 16b): {:02x?}", &ss_k_client.as_bytes()[..16]);

        let client_final = HybridKeystream::new_ultra_secure(
            *x_shared_client.as_bytes(), 
            ss_k_client.as_bytes().try_into().unwrap()
        );
        
        let server_final = HybridKeystream::new_ultra_secure(
            *x_shared_server.as_bytes(), 
            ss_k_server.as_bytes().try_into().unwrap()
        );

        println!("\n[RESULT] FINAL 256-BIT HYBRID KEY:");
        println!("HEX: {:02x?}", client_final.aes_key);
        
        assert_eq!(client_final.aes_key, server_final.aes_key);
        
        println!("\n✅");
        println!("✅");
        println!("================================================\n");
    }
}
