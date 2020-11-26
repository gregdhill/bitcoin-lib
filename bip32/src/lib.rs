mod error;
#[cfg(feature = "std")]
pub mod path;

use error::Error;
use hmac::{Hmac, Mac};
use ripemd160::Ripemd160;
use secp256k1::{PublicKey, PublicKeyFormat, SecretKey};
use sha2::{Digest, Sha256, Sha512};

type ChainCode = Vec<u8>;

#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedPubKey {
    pub network: Vec<u8>,
    pub depth: u8,
    pub fingerprint: Vec<u8>,
    pub child: Vec<u8>,
    pub chain_code: ChainCode,
    pub public_key: PublicKey,
}

const MAINNET_PUBLIC_VERSION: &[u8] = &[0x04, 0x88, 0xB2, 0x1E];
const MAINNET_PRIVATE_VERSION: &[u8] = &[0x04, 0x88, 0xAD, 0xE4];
const TESTNET_PUBLIC_VERSION: &[u8] = &[0x04, 0x35, 0x87, 0xCF];
const TESTNET_PRIVATE_VERSION: &[u8] = &[0x04, 0x35, 0x83, 0x94];

const HIGHEST_BIT: u32 = 0x80000000;

const KEY_SIZE: usize = 32;

#[cfg(feature = "std")]
impl ToString for ExtendedPubKey {
    fn to_string(&self) -> String {
        bs58::encode(self.to_vec()).with_check().into_string()
    }
}

impl ExtendedPubKey {
    pub fn from_b58(data: String) -> Result<Self, Error> {
        // 78 + 4 (checksum)
        let mut result = [0u8; 82];
        bs58::decode(data)
            .with_check(None)
            .into(&mut result)
            .map_err(|_| Error::InvalidExtendedPubKey)?;

        Ok(ExtendedPubKey {
            network: match &result[0..4] {
                MAINNET_PUBLIC_VERSION => {
                    // mainnet - public
                    Ok(MAINNET_PUBLIC_VERSION.to_vec())
                }
                MAINNET_PRIVATE_VERSION => {
                    // mainnet - private
                    Err(Error::InvalidVersion)
                }
                TESTNET_PUBLIC_VERSION => {
                    // testnet - public
                    Ok(TESTNET_PUBLIC_VERSION.to_vec())
                }
                TESTNET_PRIVATE_VERSION => {
                    // testnet - private
                    Err(Error::InvalidVersion)
                }
                _ => Err(Error::InvalidVersion),
            }?,
            depth: result[4],
            fingerprint: result[5..9].to_vec(),
            child: result[9..13].to_vec(),
            chain_code: result[13..45].to_vec(),
            public_key: PublicKey::parse_slice(&result[45..78], Some(PublicKeyFormat::Compressed))?,
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut payment_code = Vec::with_capacity(78);
        payment_code.extend(self.network.to_vec());
        payment_code.extend(vec![self.depth]);
        payment_code.extend(self.fingerprint.to_vec());
        payment_code.extend(self.child.to_vec());
        payment_code.extend(self.chain_code.to_vec());
        payment_code.extend(self.public_key.serialize_compressed().to_vec());
        payment_code
    }

    pub fn derive_public_key(&self, index: u32) -> Result<Self, Error> {
        if index >= HIGHEST_BIT {
            return Err(Error::CannotDeriveHardenedPublicKey);
        }

        let mut signature = {
            let mut hmac = Hmac::<Sha512>::new_varkey(&self.chain_code.to_vec())
                .map_err(|_| Error::InvalidKeyLength)?;
            hmac.input(&self.public_key.serialize_compressed());
            hmac.input(&index.to_be_bytes());
            hmac.result().code()
        };

        let (secret_key, chain_code) = signature.split_at_mut(KEY_SIZE);
        let private_key = SecretKey::parse_slice(&secret_key)?;
        let mut public_key = self.public_key.clone();
        public_key.tweak_add_assign(&private_key)?;

        let mut sha256 = Sha256::new();
        sha256.input(self.public_key.clone().serialize_compressed());
        let mut ripemd = Ripemd160::new();
        ripemd.input(sha256.result());
        let fingerprint = ripemd.result()[..4].to_vec();

        Ok(ExtendedPubKey {
            network: self.network.clone(),
            depth: self.depth + 1,
            fingerprint,
            // TODO: child number
            child: vec![0, 0, 0, 0],
            chain_code: chain_code.to_vec(),
            public_key,
        })
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_public_key() {
        let extended_public_key_str = "xpub661MyMwAqRbcGKjsoAeR5J1XVVNGi1ctrVkC2kh3oQjvUiuYUr66QHUBaVHk1Z54T9sebEWhA1LH4rtLQZhyRxwiGFcTF5r3HXnPek63R8A";

        assert_eq!(
            extended_public_key_str,
            ExtendedPubKey::from_b58(extended_public_key_str.to_string())
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn test_derive_child_keys() {
        let extended_public_key_0 = "xpub661MyMwAqRbcEunPoQfrgAg92EzsgNMX2KnFZYJxjVrF6Bi3QVc9GK888uCzRn78VwQeKyEPEbGXFoB1hbS1CikjCnNAaLvHpESkJB9eJQ3";
        let extended_public_key_1 = "xpub69LNMsao5jCHxq4GF5yJ84VoqYG9FcXJXcybDw9qbvAz8ZK158uZNLmqCMGAduh73LQ8JpHMAcBJQJML6vBzhU78TB9xxQqQFy97z17o6Ug";

        let extended_public_key_0_result =
            ExtendedPubKey::from_b58(extended_public_key_0.to_string()).unwrap();
        let extended_public_key_1_result =
            ExtendedPubKey::from_b58(extended_public_key_1.to_string()).unwrap();

        let extended_public_key_0_child_0 =
            extended_public_key_0_result.derive_public_key(0).unwrap();

        assert_eq!(extended_public_key_1_result, extended_public_key_0_child_0);
    }
}
