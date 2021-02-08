//! Wireguard
/**

no permissions / unknown user : 

     Authenticate                    params: PIN/pass         - Unlocks the device to use it. 

     get AEAD                        params: pubkey, C, H     - The most important function, since the AEAD is necessary to perform the NOISE handshake.
                                                              - Transmitts the peer's public key, the chained key C and chained Hash 'H' to the device. Returns AEAD.
                                                              - Requires: User action (e.g. Button interaction) on first use. Perhaps additionaly every X minutes (configurable)


elevated permisions / authenticated user: 

     set private key                 params: privkey, id      - Sets a private key. If an ID is provided -> overwrite. Returns the internal private key UID
     generate keypair                params: <none>           - Generates a keypair, saves the private key and returns a public key, as well as the internal private key UID
     delete private key              params  id               - Deletes a private key from the device with a given ID 

     set user config                 params: configUID, value - Change the config. Probably needed to change the behaviour stated in `get AEAD`.


___________

Perhaps not interesting for NPX: 

    set time                                     - No RTC available on the STM32, that was capable of incrementing a day/month/year. 
                                                  Restricted to time exclusively. Solution: transmit the current epoch and extract the date.

    get time                                     - get the device time. Mostly to check, whether a new timestamp is needed.



**/

use core::convert::TryInto;

use delog::hex_str;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use trussed::{consts, syscall, try_syscall, types::Message};
use trussed::{ByteBuf, types::{Mechanism, /*SignatureSerialization, StorageAttributes,*/ StorageLocation}};

use crate::Result;


// Some constants

const SIZE_CK: usize = 32;
const SIZE_HS: usize = 32;
const SIZE_PUBKEY: usize = 32;
const SIZE_PRIVKEY: usize = 32;


#[allow(missing_docs)]
// core wireguard app
pub struct Wireguard <T : trussed::Client>
{
    trussed: T,
}

/*
    Commands / Requests
 */

 /*
  get AEAD                        params: pubkey, C, H     - The most important function, since the AEAD is necessary to perform the NOISE handshake.
                                                              - Transmitts the peer's public key, the chained key C and chained Hash 'H' to the device. Returns AEAD.
                                                              - Requires: User action (e.g. Button interaction) on first use. Perhaps additionaly every X minutes (configurable)
 */
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct GetAead 
 {
     pub pubkey: [u8;SIZE_PUBKEY],
     pub c : [u8; SIZE_CK],
     pub h : [u8; SIZE_HS]
 }

 //  Authenticate                    params: PIN/pass         - Unlocks the device to use it. 
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct Unlock
 {
     pub pin: String, // pin code to unlock the device
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct RegisterPrivatekey
 {
     pub privkey : [u8; SIZE_PRIVKEY],
 }
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct UpdatePrivatekey
 {
     pub privkey : [u8; SIZE_PRIVKEY],
     pub uid : u32 // unique ID 
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct DeletePrivatekey
 {
     pub uid : u32 // unique ID 
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct GenerateKeyPair
 {
    // empty!
 }
 

 /*
    Reponses
 */
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct AEAD(pub [u8;32]);

  
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct PrivateKeyUid(pub u32);


 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct GenerateKeyPairResponse
 {
    pub pubkey : [u8; SIZE_PUBKEY],
    pub uid : PrivateKeyUid // Uid of the respective private key
 }



// implementations

// hex
impl core::fmt::Display for AEAD {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}


impl core::fmt::Display for PrivateKeyUid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::fmt::Display for GenerateKeyPairResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?} w/ UID: {}", self.pubkey, self.uid)
    }
}




#[derive(Clone, Debug, PartialEq)]
/// The public API of this wireguard m
#[allow(missing_docs)]
pub enum WgCommand {
    Unlock(Unlock),
    RegisterPrivatekey(RegisterPrivatekey),
    UpdatePrivatekey(UpdatePrivatekey),
    DeletePrivatekey(DeletePrivatekey),

    GenerateKeyPair(GenerateKeyPair),
    GetAead(GetAead)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
/// The `serde::Serialize` and `serde::Deserialize` implementations allow
/// credentials to easily be stored in binary format.
pub struct PrivateKey {
    uid: u64,
    key_handle: trussed::types::ObjectHandle,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
/// The `serde::Serialize` and `serde::Deserialize` implementations allow
/// credentials to easily be stored in binary format.
pub struct Credential {
    label: trussed::ByteBuf<consts::U256>,
    period_seconds: u64,
    key_handle: trussed::types::ObjectHandle,
}

#[allow(missing_docs)]
impl<T> Wireguard<T>
where
    T: trussed::Client
{
   /// Constructor, consumes a Trussed client
   pub fn new(trussed: T) -> Self {
    Self { trussed }
    }

    pub fn unlock(&mut self, parameters: &Unlock) -> Result<()> {

        print!("Unlock called: {:?}", parameters);

        // done
        Ok(())
    }

    pub fn get_aead(&mut self, parameters: &Unlock) -> Result<()> {

        debug!("get_aead called: {:?}", parameters);

        // done
        Ok(())
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
