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

use pqcrypto_traits::kem::{
    PublicKey as _, 
    SecretKey as _, 
    Ciphertext as _, 
    SharedSecret as _
};

pub fn generate_pqc_keypair() -> (kyber768::PublicKey, kyber768::SecretKey) {
    kyber768::keypair()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::kem::{PublicKey, SharedSecret};

    #[test]
    fn test_kyber_handshake_verbose() {
        println!("\n--- [PQC DEBUG] ---");

        let (pk, sk) = generate_pqc_keypair();
        println!("Server PK (16b): {:02x?}", &pk.as_bytes()[..16]);

        let (ss_client, ct) = kyber768::encapsulate(&pk);
        
        println!("Client SS: {:02x?}", ss_client.as_bytes());
        println!("Ciphertext (16b): {:02x?}", &ct.as_bytes()[..16]);

        let ss_server = kyber768::decapsulate(&ct, &sk);
        
        println!("Server SS: {:02x?}", ss_server.as_bytes());

        assert_eq!(ss_client.as_bytes(), ss_server.as_bytes(), "KEY ERROR");
        println!("\n✅ Key");
        println!("--- [END DEBUG] ---\n");
    }
}
