use crate::output::HashRaw;

impl HashRaw {
    pub(crate) fn encode_rust(&self) -> String {
        use base64::prelude::*;
        let hash_encoded = BASE64_STANDARD_NO_PAD.encode(self.raw_hash_bytes());
        let salt_encoded = BASE64_STANDARD_NO_PAD.encode(self.raw_salt_bytes());
        format!(
            "${}$v={}$m={},t={},p={}${}${}",
            self.variant().as_str(),
            self.version().as_str(),
            self.memory_size(),
            self.iterations(),
            self.lanes(),
            salt_encoded,
            hash_encoded,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    use crate::backend::encode_c;
    use crate::hasher::Hasher;

    #[test]
    fn test_encode_against_c() {
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let mut password = vec![0u8; 12];
        let mut secret_key = vec![0u8; 32];
        for _ in 0..100 {
            rng.fill_bytes(&mut password);
            rng.fill_bytes(&mut secret_key);
            for hash_len in &[8, 32, 128] {
                let mut hasher = Hasher::default();
                let hash_raw = hasher
                    .configure_hash_len(*hash_len)
                    .configure_iterations(1)
                    .configure_memory_size(32)
                    .configure_password_clearing(false)
                    .configure_secret_key_clearing(false)
                    .configure_threads(1)
                    .configure_lanes(1)
                    .with_secret_key(&secret_key[..])
                    .with_password(&password[..])
                    .hash_raw()
                    .unwrap();
                let hash1 = hash_raw.encode_rust();
                let hash2 = encode_c(&hash_raw).unwrap();
                assert_eq!(hash1, hash2);
            }
        }
    }
}
