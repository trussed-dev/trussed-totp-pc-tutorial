use core::convert::TryInto;

use delog::hex_str;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use trussed::{consts, syscall, types::Message};
use trussed::{ByteBuf, types::{Mechanism, /*SignatureSerialization, StorageAttributes,*/ StorageLocation}};

use crate::Result;

pub struct Authenticator<T>
where
    T: trussed::Client,
{
    trussed: T,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Register {
    pub label: String,
    pub secret: String,
    pub period: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Authenticate {
    pub label: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    Register(Register),
    Authenticate(Authenticate),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Otp(u64);

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Credential {
    label: trussed::ByteBuf<consts::U256>,
    period: u64,
    handle: trussed::types::ObjectHandle,
}

impl<T: trussed::Client> Authenticator<T> {
    pub fn new(trussed: T) -> Self {
        Self { trussed }
    }

    pub fn register(&mut self, parameters: &Register) -> Result<()> {
        let  Register { label, secret, period } = parameters;
        debug!("register {:?}", parameters);

        // 1. Decode TOTP secret
        let raw_key_bytes = data_encoding::BASE32.decode(&secret.as_bytes()).unwrap();
        let raw_key: [u8; 20] = (&raw_key_bytes[..]).try_into().unwrap();
        debug!("raw key: {}", hex_str!(&raw_key, 4));

        // 2. Store secret in Trussed
        let handle = syscall!(self.trussed.unsafe_inject_totp_key(&raw_key, StorageLocation::Internal)).key;
        info!("new key handle: {:?}", handle);

        // 3. Generate credential
        let credential = Credential {
            label: ByteBuf::from(label.as_bytes()),
            period: *period,
            handle,
        };
        let mut buf = [0u8; 512];
        let serialized_credential = postcard::to_slice(&credential, &mut buf).unwrap();

        // 4. Store credential
        let filename = self.filename_for_label(&label);
        debug!("saving to filename {}", filename.as_ref());

        syscall!(self.trussed.write_file(
            StorageLocation::Internal,
            filename,
            ByteBuf::from(&*serialized_credential),
            None
        ));

        // done \o/
        Ok(())
    }

    pub fn authenticate(&mut self, parameters: &Authenticate) -> Result<Otp> {
        let Authenticate { label, timestamp } = parameters;
        debug!("authenticate {:?}", parameters);

        // 1. Load credential
        let filename = self.filename_for_label(&label);
        let serialized_credential = syscall!(self.trussed.read_file(
            StorageLocation::Internal,
            filename,
        )).data;

        let credential: Credential = postcard::from_bytes(serialized_credential.as_slice()).unwrap();
        debug!("found credential: {:?}", &credential);

        // 2. Calculate OTP
        let counter = *timestamp / credential.period;

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
            &credential.handle,
            counter,
        )).signature;

        let otp = u64::from_le_bytes(otp[..8].try_into().unwrap());
        debug!("calculated OTP: {}", otp);

        // done \o/
        Ok(Otp(otp))
    }

    fn filename_for_label(&mut self, label: &str) -> trussed::types::PathBuf {
        let filename = syscall!(self.trussed.hash(Mechanism::Sha256, Message::from(label.as_bytes()))).hash;

        fn format_hex(data: &[u8], mut buffer: &mut [u8]) {
            const HEX_CHARS: &[u8] = b"0123456789abcdef";
            for byte in data.iter() {
                buffer[0] = HEX_CHARS[(byte >> 4) as usize];
                buffer[1] = HEX_CHARS[(byte & 0xf) as usize];
                buffer = &mut buffer[2..];
            }
        }

        let mut hex_filename = [0u8; 16];
        format_hex(&filename[..8], &mut hex_filename);

        trussed::types::PathBuf::from(hex_filename.as_ref())
    }
}
