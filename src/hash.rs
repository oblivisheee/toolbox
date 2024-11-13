pub use hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();

        Self(result.into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ToHex for Sha256 {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.encode_hex()
    }
    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.encode_hex_upper()
    }
}

impl FromHex for Sha256 {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = Vec::from_hex(hex)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| hex::FromHexError::InvalidStringLength)?,
        ))
    }
}

pub struct Blake3(blake3::Hash);

impl Blake3 {
    pub fn new(data: &[u8]) -> Self {
        Self(blake3::hash(data))
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }
    pub fn to_hex(&self) -> String {
        self.0.to_hex().to_string()
    }
    pub fn from_hex(hex: &str) -> Self {
        Self(blake3::Hash::from_hex(hex).unwrap())
    }
}
impl ToHex for Blake3 {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.as_bytes().encode_hex()
    }
    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.as_bytes().encode_hex_upper()
    }
}
