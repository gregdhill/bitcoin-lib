mod error;

use bip32::ExtendedPubKey;
use error::Error;
use hmac::{Hmac, Mac};
use secp256k1::{
    curve::{Affine, Jacobian, Scalar, ECMULT_CONTEXT},
    PublicKey, PublicKeyFormat, SecretKey,
};
use sha2::Sha512;

fn calculate_secret_point(public_key: Affine, secret_key: Scalar) -> Affine {
    let mut res = Jacobian::default();
    let mut point = public_key.clone();

    ECMULT_CONTEXT.ecmult_const(&mut res, &point, &secret_key);
    point.set_gej(&res);

    point.x.normalize();
    point.y.normalize();

    let mut secret = public_key.clone();
    secret.set_gej(&res);
    secret.x.normalize();
    secret.y.normalize();
    secret
}

fn calculate_blinding_mask(
    secret_key: SecretKey,
    public_key: PublicKey,
    outpoint: Vec<u8>,
) -> Vec<u8> {
    // TODO: implement upstream
    let x = calculate_secret_point(public_key.into(), secret_key.into()).x;

    // s = HMAC-SHA512(x, o)
    let mut hmac = Hmac::<Sha512>::new_varkey(&outpoint).unwrap();
    hmac.input(&x.b32().as_ref());
    hmac.result().code().to_vec()
}

fn xor(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    left.iter()
        .zip(right.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect()
}

#[derive(Debug)]
pub struct PaymentCode {
    pub version: u8,
    pub features: u8,
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[cfg(feature = "std")]
impl ToString for PaymentCode {
    fn to_string(&self) -> String {
        let mut payment_code = Vec::with_capacity(81);
        payment_code.append(&mut vec![0x47]);
        payment_code.append(&mut self.to_vec());
        bs58::encode(payment_code).with_check().into_string()
    }
}

impl PaymentCode {
    pub fn from_b58(data: String) -> Result<Self, Error> {
        // version + payment_code + checksum
        let mut result = [0u8; 85];
        bs58::decode(data)
            .with_check(None)
            .into(&mut result)
            .map_err(|_| Error::InvalidPaymentCode)?;

        Ok(PaymentCode {
            version: if result[1] == 1 {
                1
            } else {
                return Err(Error::VersionNotSupported);
            },
            features: result[2],
            public_key: result[3..36].to_vec(),
            chain_code: result[36..68].to_vec(),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut payment_code = Vec::with_capacity(80);
        payment_code.append(&mut vec![self.version, self.features]);
        payment_code.append(&mut self.public_key.to_vec());
        payment_code.append(&mut self.chain_code.to_vec());
        payment_code.append(&mut vec![0u8; 13]); // reserved
        payment_code
    }

    pub fn to_extended_public_key(&self) -> Result<ExtendedPubKey, Error> {
        // TODO: require args
        Ok(ExtendedPubKey {
            network: vec![0, 0, 0, 0],
            depth: 0,
            fingerprint: vec![0, 0, 0, 0],
            child: vec![0, 0, 0, 0],
            chain_code: self.chain_code.to_vec(),
            public_key: PublicKey::parse_slice(
                &self.public_key,
                Some(PublicKeyFormat::Compressed),
            )?,
        })
    }

    pub fn blind_from_keys(
        &self,
        secret_key: SecretKey,
        public_key: PublicKey,
        outpoint: Vec<u8>,
    ) -> Result<Self, Error> {
        let blinding_mask = calculate_blinding_mask(secret_key, public_key, outpoint);
        self.blind(blinding_mask)
    }

    pub fn blind(&self, blinding_mask: Vec<u8>) -> Result<Self, Error> {
        // x' = x XOR (first 32 bytes of s)
        let mut public_key = xor(
            // TODO: check if updated x is member of the secp256k1 group
            self.public_key[1..33].to_vec(),
            blinding_mask[..32].to_vec(),
        );
        // c' = c XOR (last 32 bytes of s)
        let chain_code = xor(self.chain_code.to_vec(), blinding_mask[32..].to_vec());

        let sign = self.public_key[0];
        let mut public_key_with_sign = vec![sign];
        public_key_with_sign.append(&mut public_key);

        Ok(PaymentCode {
            version: self.version,
            features: self.features,
            public_key: public_key_with_sign,
            chain_code,
        })
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;
    use rand::thread_rng;
    use secp256k1::SharedSecret;
    use sha2::Sha256;

    // https://hackernoon.com/blockchain-privacy-enhancing-technology-series-stealth-address-i-c8a3eb4e4e43

    fn generate_shared_secret(
        recipient_public_key: &PublicKey,
        sender_secret_key: SecretKey,
    ) -> Result<SecretKey, Error> {
        let shared_secret: SharedSecret<Sha256> =
            SharedSecret::new(recipient_public_key, &sender_secret_key)?;

        Ok(SecretKey::parse_slice(shared_secret.as_ref())?)
    }

    fn generate_destination_public_key(
        recipient_public_key: PublicKey,
        shared_secret_key: SecretKey,
    ) -> Result<PublicKey, Error> {
        let shared_public_key = PublicKey::from_secret_key(&shared_secret_key);

        Ok(PublicKey::combine(&[
            shared_public_key,
            recipient_public_key,
        ])?)
    }

    #[test]
    fn test_improved_stealth_address() {
        // (b, B), B = b·G
        let mut receiver_secret_key = SecretKey::random(&mut thread_rng());
        let receiver_public_key = PublicKey::from_secret_key(&receiver_secret_key);

        // (r, R), R = r·G
        let sender_secret_key = SecretKey::random(&mut thread_rng());

        // c = H(r·b·G) = H(r·B) = H(b·R)
        let shared_secret_key =
            generate_shared_secret(&receiver_public_key, sender_secret_key).unwrap();

        // c·G + B
        let destination_public_key =
            generate_destination_public_key(receiver_public_key, shared_secret_key.clone())
                .unwrap();

        receiver_secret_key
            .tweak_add_assign(&shared_secret_key)
            .unwrap();

        assert_eq!(
            PublicKey::from_secret_key(&receiver_secret_key),
            destination_public_key
        );
    }

    #[test]
    fn test_dual_key_stealth_address() {
        // (s, S), S = s·G
        let receiver_scan_secret_key = SecretKey::random(&mut thread_rng());
        let receiver_scan_public_key = PublicKey::from_secret_key(&receiver_scan_secret_key);

        // (b, B), B = b·G
        let mut receiver_spend_secret_key = SecretKey::random(&mut thread_rng());
        let receiver_spend_public_key = PublicKey::from_secret_key(&receiver_spend_secret_key);

        // (r, R), R = r·G
        let sender_secret_key = SecretKey::random(&mut thread_rng());

        // c = H(r·s·G) = H(r·S) = H(s·R)
        let shared_secret_key =
            generate_shared_secret(&receiver_scan_public_key, sender_secret_key).unwrap();

        // c·G + B
        let destination_public_key = generate_destination_public_key(
            receiver_spend_public_key.clone(),
            shared_secret_key.clone(),
        )
        .unwrap();

        assert_eq!(
            PublicKey::combine(&[
                PublicKey::from_secret_key(&shared_secret_key),
                receiver_spend_public_key
            ])
            .unwrap(),
            destination_public_key
        );

        // c + b
        receiver_spend_secret_key
            .tweak_add_assign(&shared_secret_key)
            .unwrap();

        // (c + b)·G
        assert_eq!(
            PublicKey::from_secret_key(&receiver_spend_secret_key),
            destination_public_key
        );
    }

    #[test]
    fn test_generate_payment_code_alice() {
        let payment_code = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";

        assert_eq!(
            PaymentCode::from_b58(payment_code.to_string())
                .unwrap()
                .to_string(),
            payment_code.to_string()
        );

        // payment code payload
        assert_eq!(
            hex::encode(PaymentCode::from_b58(payment_code.to_string()).unwrap().to_vec()),
            "010002b85034fb08a8bfefd22848238257b252721454bbbfba2c3667f168837ea2cdad671af9f65904632e2dcc0c6ad314e11d53fc82fa4c4ea27a4a14eccecc478fee00000000000000000000000000".to_string()
        );
    }

    #[test]
    fn test_generate_payment_code_bob() {
        let payment_code = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";

        assert_eq!(
            PaymentCode::from_b58(payment_code.to_string())
                .unwrap()
                .to_string(),
            payment_code.to_string()
        );

        // notification address public key
        assert_eq!(
            hex::encode(PaymentCode::from_b58(payment_code.to_string()).unwrap().to_extended_public_key().unwrap().derive_public_key(0).unwrap().public_key.serialize()),
            "044ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8b008f2d9fbd6902479c9645d565dc0ef8a149ab41d4f600666aba9df29afd52c"
        );
    }

    #[test]
    fn test_protocol_version_1() {
        // https://gist.github.com/SamouraiDev/6aad669604c5930864bd

        // 1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW
        let sender_secret_key = SecretKey::parse_slice(
            &hex::decode("1b7a10f45118e2519a8dd46ef81591c1ae501d082b6610fdda3de7a3c932880d")
                .unwrap(),
        )
        .unwrap();

        let sender_public_key = PublicKey::parse_slice(
            &hex::decode("0472d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad86597eb61bb93940edbcf12a88967943a434c04c47f3784bb2d9f1321c7e1dcb0")
                .unwrap(),
            Some(PublicKeyFormat::Full),
        )
        .unwrap();

        // 1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV
        let receiver_secret_key = SecretKey::parse_slice(
            &hex::decode("04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b")
                .unwrap(),
        )
        .unwrap();

        let receiver_public_key = PublicKey::parse_slice(
            &hex::decode("044ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8b008f2d9fbd6902479c9645d565dc0ef8a149ab41d4f600666aba9df29afd52c")
                .unwrap(),
            Some(PublicKeyFormat::Full),
        )
        .unwrap();

        let outpoint =
            hex::decode("86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000")
                .unwrap();

        assert_eq!(
            hex::encode(calculate_blinding_mask(sender_secret_key.clone(), receiver_public_key.clone(), outpoint.clone())),
            "be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5".to_string(),
            "Alice should compute the correct blinding mask"
        );

        // Alice's payment code
        let payment_code = PaymentCode::from_b58("PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA".to_string())
                .unwrap();

        // `OP_RETURN` payload
        let payment_code = payment_code
            .blind_from_keys(
                sender_secret_key.clone(),
                receiver_public_key.clone(),
                outpoint.clone(),
            )
            .unwrap();

        assert_eq!(
            payment_code.to_vec(),
            hex::decode("010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000").unwrap()
        );

        assert_eq!(
            hex::encode(calculate_blinding_mask(receiver_secret_key.clone(), sender_public_key.clone(), outpoint.clone())),
            "be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5".to_string(),
            "Bob should compute the same blinding mask"
        );

        // Bob recovers Alice's payment code
        let payment_code = payment_code
            .blind_from_keys(
                sender_secret_key.clone(),
                receiver_public_key.clone(),
                outpoint.clone(),
            )
            .unwrap();

        assert_eq!(
            payment_code.to_vec(),
            hex::decode("010002b85034fb08a8bfefd22848238257b252721454bbbfba2c3667f168837ea2cdad671af9f65904632e2dcc0c6ad314e11d53fc82fa4c4ea27a4a14eccecc478fee00000000000000000000000000").unwrap()
        );
    }
}
