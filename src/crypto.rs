use std::sync::{Arc, Mutex};
pub mod aes {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Error, Key, Nonce,
    };

    pub use aes_gcm::{Aes128Gcm, Aes256Gcm};

    #[derive(Clone, Debug)]
    pub struct AES<T: AeadCore + Aead + KeyInit> {
        cipher: T,
    }

    impl<T: AeadCore + Aead + KeyInit> AES<T> {
        pub fn new<K: AsRef<[u8]>>(key: K) -> Result<Self, Error> {
            Ok(Self {
                cipher: T::new(Key::<T>::from_slice(key.as_ref())),
            })
        }

        pub fn encrypt(&self, plaintext: &[u8], nonce: Option<&[u8]>) -> Result<Vec<u8>, Error> {
            let nonce = match nonce {
                Some(n) => Nonce::from_slice(n).to_owned(),
                None => T::generate_nonce(&mut OsRng),
            };
            let ciphertext = self.cipher.encrypt(&nonce, plaintext)?;
            let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
            result.extend_from_slice(&nonce);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
            const NONCE_SIZE: usize = 12;
            if ciphertext.len() < NONCE_SIZE {
                return Err(Error);
            }

            let (nonce, encrypted_data) = ciphertext.split_at(NONCE_SIZE);
            self.cipher
                .decrypt(Nonce::from_slice(nonce), encrypted_data)
        }
    }
}

pub struct SecretKey {
    key: Vec<u8>,
}
impl SecretKey {
    pub fn gen() -> Arc<Mutex<Self>> {
        let mut key = vec![0u8; 32];
        let rng = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&rng, &mut key).expect("RNG failure");

        Arc::new(Mutex::new(Self { key }))
    }
    pub fn from_vec<T: AsRef<Vec<u8>>>(vec: T) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            key: vec.as_ref().to_owned(),
        }))
    }
    pub fn get(&self) -> &[u8] {
        &self.key
    }
}
pub mod rsa {
    use rsa::{
        pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
        RsaPrivateKey, RsaPublicKey,
    };

    #[derive(Debug)]
    pub struct RSA {
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey,
    }

    impl RSA {
        pub fn new(bits: usize) -> Result<Self, rsa::Error> {
            let mut rng = rand::thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, bits)?;
            let public_key = RsaPublicKey::from(&private_key);
            Ok(Self {
                private_key,
                public_key,
            })
        }

        pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, rsa::Error> {
            let mut rng = rand::thread_rng();
            self.public_key
                .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, data)
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, rsa::Error> {
            self.private_key.decrypt(rsa::Pkcs1v15Encrypt, ciphertext)
        }

        pub fn export_public_key(&self) -> Result<Vec<u8>, rsa::Error> {
            Ok(self.public_key.to_pkcs1_der().unwrap().to_vec())
        }

        pub fn export_private_key(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, rsa::Error> {
            Ok(self.private_key.to_pkcs1_der().unwrap().to_bytes())
        }
        pub fn import_private_key(key: &[u8]) -> Result<Self, rsa::Error> {
            let private_key = RsaPrivateKey::from_pkcs1_der(key)?;
            let public_key = RsaPublicKey::from(&private_key);
            Ok(Self {
                private_key,
                public_key,
            })
        }
    }
}
pub mod diffie_hellman {
    pub use rand::rngs::OsRng;
    pub use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
}

/*pub mod ecdsa {
    use p256::{
        ecdsa::{Signature, SigningKey, VerifyingKey},
        SecretKey,
    };
    use rand_core::OsRng;

    pub struct ECDSA {
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
    }

    impl ECDSA {
        pub fn new() -> Self {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            Self {
                signing_key,
                verifying_key,
            }
        }

        pub fn sign(&self, message: &[u8]) -> Signature {
            self.signing_key.sign(message)
        }

        pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
            self.verifying_key.verify(message, signature).is_ok()
        }

        pub fn export_public_key(&self) -> Vec<u8> {
            self.verifying_key
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        }

        pub fn export_private_key(&self) -> Vec<u8> {
            self.signing_key.to_bytes().to_vec()
        }

        pub fn import_private_key(key: &[u8]) -> Result<Self, p256::Error> {
            let secret_key = SecretKey::from_be_bytes(key)?;
            let signing_key = SigningKey::from(secret_key);
            let verifying_key = VerifyingKey::from(&signing_key);
            Ok(Self {
                signing_key,
                verifying_key,
            })
        }

        pub fn import_public_key(key: &[u8]) -> Result<VerifyingKey, p256::Error> {
            VerifyingKey::from_sec1_bytes(key)
        }
    }
}
*/
