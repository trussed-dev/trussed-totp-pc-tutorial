//! The example TOTP authenticator of this tutorial.
//!
//! While not a requirement from Trussed™, we use a pattern of declaring
//! command/request inputs (`Register` and `Authenticate`) as Rust structs.
//!
//! This pushes (or can help to push) the question of lower-level protocol
//! encodings outside of the "app", which can then focus even more on
//! implementing the exact logic required.

use core::convert::TryInto;

use delog::hex_str;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use trussed::{consts, syscall, try_syscall, types::Message};
use trussed::{ByteBuf, types::{Mechanism, /*SignatureSerialization, StorageAttributes,*/ StorageLocation}};

use crate::Result;


/// The core "app", implementing TOTP authentication, using Trussed™
pub struct Authenticator<T>
where
    T: trussed::Client,
{
    trussed: T,
}

#[derive(Clone, Debug, PartialEq)]
/// One of the two commands this authenticator can process: credential registration
pub struct Register {
    /// Label for the credential, e.g. `alice@trussed.dev`
    pub label: String,
    /// Choices could be made here on who is responsible for decoding the raw secret bytes
    pub base32_secret: String,
    /// Period in seconds after which the counter for the TOTP token is incremented
    pub period_seconds: u64,
}

#[derive(Clone, Debug, PartialEq)]
/// One of the two commands this authenticator can process: authentication with a registered
/// credential
pub struct Authenticate {
    /// Label for the credential, e.g. `alice@trussed.dev`
    pub label: String,
    /// Timestamp (seconds since UNIX epoch)
    // pub timestamp: std::time::Instant,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq)]
/// The public API of this TOTP authenticator
#[allow(missing_docs)]
pub enum Command {
    Register(Register),
    Authenticate(Authenticate),
}

#[derive(Clone, Debug, PartialEq)]
/// Contains a one-time password
pub struct Otp(pub u64);

/// OTP codes are typically presented as left-zero-padded strings
impl core::fmt::Display for Otp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
/// The metadata associated with a TOTP secret, enabling later use
/// in the `Authenticate` command.
///
/// The `serde::Serialize` and `serde::Deserialize` implementations allow
/// credentials to easily be stored in binary format.
pub struct Credential {
    label: trussed::ByteBuf<consts::U256>,
    period_seconds: u64,
    key_handle: trussed::types::ObjectHandle,
}

impl<T: trussed::Client> Authenticator<T> {
    /// Constructor, consumes a Trussed client
    pub fn new(trussed: T) -> Self {
        Self { trussed }
    }

    /// Injects the TOTP secret in Trussed's key storage, stores a `Credential`
    /// with the metadata for the secret.
    pub fn register(&mut self, parameters: &Register) -> Result<()> {

        let  Register { label, base32_secret, period_seconds } = parameters;
        debug!("register {:?}", parameters);

        // 1. Decode TOTP secret
        let raw_key_bytes = data_encoding::BASE32.decode(&base32_secret.as_bytes())?;
        let raw_key: [u8; 20] = (&raw_key_bytes[..]).try_into()?;
        debug!("raw key: {}", hex_str!(&raw_key, 4));

        // 2. Store secret in Trussed
        let key_handle = syscall!(
            self.trussed
                .unsafe_inject_totp_key(&raw_key, StorageLocation::Internal)
        ).key;
        info!("new key handle: {:?}", key_handle);

        // 3. Generate credential
        let credential = Credential {
            label: ByteBuf::try_from_slice(label.as_bytes()).map_err(EmptyError::from)?,
            period_seconds: *period_seconds,
            key_handle,
        };
        let mut buf = [0u8; 512];
        let serialized_credential = postcard::to_slice(&credential, &mut buf)
            .map_err(|_| anyhow::anyhow!("postcard serialization error"))?;

        // 4. Store credential
        let filename = self.filename_for_label(&label);
        debug!("saving to filename {}", filename.as_ref());

        syscall!(self.trussed.write_file(
            StorageLocation::Internal,
            filename,
            ByteBuf::try_from_slice(&*serialized_credential).unwrap(),
            None
        ));

        // done \o/
        Ok(())
    }

    /// Looks up a previously registered credential (else fails),
    /// create a TOTP using the supplied timestamp.
    pub fn authenticate(&mut self, parameters: &Authenticate) -> Result<Otp> {
        let Authenticate { label, timestamp } = parameters;
        debug!("authenticate {:?}", parameters);

        // 1. Load credential
        let filename = self.filename_for_label(&label);
        let serialized_credential = try_syscall!(self.trussed.read_file(
            StorageLocation::Internal,
            filename,
        ))
            .map_err(|_| anyhow::anyhow!("Could not find a credential labelled {}", label))?
            .data;

        let credential: Credential = postcard::from_bytes(serialized_credential.as_ref())
            .map_err(|_| anyhow::anyhow!("postcard deserialization error"))?;
        debug!("found credential: {:?}", &credential);

        // 2. Calculate OTP
        let counter = *timestamp / credential.period_seconds;

        // // TODO: take this out of Trussed again, and implement "by hand" for posterity
        // let counter_bytes: [u8; 8] = counter.to_be_bytes();
        // let hmac = syscall!(self.trussed.sign(
        //     Mechanism::Totp,
        //     credential.handle,
        //     &counter_bytes,
        //     SignatureSerialization::Raw,
        // )).signature;
        // debug!("calculated HMAC: {}", hex_str!(&hmac, 4));

        let otp = syscall!(self.trussed.sign_totp(
            &credential.key_handle,
            counter,
        )).signature;

        try_syscall!(self.trussed.confirm_user_present(5_000))
            .map_err(|_| anyhow::anyhow!("Could not obtain confirmation of user presence!"))?;

        let otp = u64::from_le_bytes(otp[..8].try_into().unwrap());
        debug!("calculated OTP: {}", otp);

        // done \o_
        Ok(Otp(otp))
    }

    /// Helper method, using Trussed, to determine a filename for the Credential
    fn filename_for_label(&mut self, label: &str) -> trussed::types::PathBuf {
        let filename = syscall!(self.trussed.hash(Mechanism::Sha256, Message::try_from_slice(label.as_bytes()).unwrap())).hash;
        let mut hex_filename = [0u8; 16];
        use std::io::Write as _;
        // first 8 bytes of SHA256 hash of label, as hexadecimal digits
        hex_filename.as_mut().write_fmt(format_args!("{}", delog::hexstr!(&filename[..8]))).unwrap();

        trussed::types::PathBuf::from(hex_filename.as_ref())
    }
}

#[derive(Debug, thiserror::Error)]
/// In embedded, we don't have `std::error::Error`, and in many situations,
/// the type `()` is used as error type. To make this compatible with our use
/// of `std` Errors here, we need a wrapper type (the error trait is not implemented for `()`).
pub enum EmptyError {
    #[error("no error")]
    /// The empty singleton
    Empty,
}

impl core::convert::From<()> for EmptyError {
    fn from(_: ()) -> Self {
        Self::Empty
    }
}
