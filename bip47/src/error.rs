use secp256k1::Error as Secp256k1Error;

#[derive(Debug)]
pub enum Error {
    InvalidPaymentCode,
    VersionNotSupported,

    Secp256k1Error(Secp256k1Error),
}

impl From<Secp256k1Error> for Error {
    fn from(source: Secp256k1Error) -> Self {
        Error::Secp256k1Error(source)
    }
}
