//! Wireguard
use anyhow::Error;
use littlefs2::path::Path;
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

use log::{debug, info};
use serde::{Deserialize, Serialize};
use trussed::{api::reply::Delete, consts, syscall, try_syscall, types::Message};
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
     pub h : [u8; SIZE_HS],
     pub key_id : u32
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
 pub struct RegisterKeyPair
 {
     pub privkey : [u8; SIZE_PRIVKEY],
     pub pubkey : [u8; SIZE_PUBKEY],
     pub label : String
 }
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct UpdateKeyPair
 {
    pub privkey : [u8; SIZE_PRIVKEY],
    pub pubkey : [u8; SIZE_PUBKEY],
    pub label : String
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct DeleteKeyPair
 {
     pub uid : u64 // unique ID 
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct GenerateKeyPair
 {
    pub uid : u64, // unique ID 
    pub label : String
 }
 
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct ListKeys
 {
    //empty
 }
 
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct SetUnlockSecret
 {
     pub secret: String, // pin code to unlock the device
 }



 /*
    Reponses
 */
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct AEAD(pub [u8;32]);


 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct KeyResponse
 {
    id : u64,
    label : String,
    pubkey : [u8; SIZE_PUBKEY],
 }


 /**/

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 struct UnlockStatus{
     is_locked : bool,
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 struct UnlockSecret{
     password : trussed::ByteBuf<consts::U256>,
 }

 // To be serialized and safed in the trussed store
 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 pub struct KeyInfo 
 {
    id : u64,
    label : String,
    pubkey : trussed::ByteBuf<consts::U256>,
    privkey : trussed::types::ObjectHandle,
 }


// implementations

// hex
impl core::fmt::Display for AEAD {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

impl core::fmt::Display for KeyResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?} w/ UID: {} pubkey : {:x?}", self.key_info.id, self.key_info.label, self.key_info.pubkey)
    }
}

impl core::fmt::Display for GetAead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\nC: \t\t{:x?}\nH: \t\t{:x?}\nPubkey: \t{:x?}\nkeyid: \t\t{:x?}\n", self.c, self.h, self.pubkey, self.key_id)
    }
}


#[derive(Clone, Debug, PartialEq)]
/// The public API of this wireguard m
#[allow(missing_docs)]
pub enum WgCommand {
    Unlock(Unlock),
    RegisterKeyPair(RegisterKeyPair),
    DeleteKeyPair(DeleteKeyPair),
    UpdateKeyPair(UpdateKeyPair),
    ListKeys(ListKeys),

    SetUnlockSecret(SetUnlockSecret),

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

    fn isUnlocked() -> bool
    {
        let ans = syscall!(self.trussed.read_file(
            Location::Internal,
            Path::from_cstr(Cstr::new("/wg/unlocked_status"))
        ));
        let locked_status :UnlockStatus;
        match ans 
        {
            Some(byteBuf) => { locked_status = postcard::from_bytes(byteBuf.as_ref())}
            Err(err) => {anyhow::Error("Could not read status")}
        }
        return locked_status.status;
    }

    fn setLockedStatus( status : bool )
    {
       let mut buf = [0u8; 512];
       let serialied = postcard::to_slice(UnlockStatus(status), &mut buf)
       .map_err(|_| anyhow::anyhow!("postcard serialization error"))?;

       let ans = syscall!(self.trussed.write_file(
            trussed::types::StorageLocation::internal,
            Path::from_cstr(Cstr::new("/wg/unlocked_status")),
            ByteBuf::try_from_slice(&*serialied).unwrap(),
        ));

        match ans 
        {
            Some(byteBuf) => {}
            Err(err) => {anyhow::Error("Could not write status")}
        }
    }

    pub fn setUnlockSecret(&mut self, parameters: &SetUnlockSecret) -> Result<()>  
    {
        let mut buf = [0u8; 512];
        let serialied = postcard::to_slice(SetUnlockSecret, &mut buf)
        .map_err(|_| anyhow::anyhow!("postcard serialization error"))?;
 
        let ans = syscall!(self.trussed.write_file(
             trussed::types::StorageLocation::internal,
             Path::from_cstr(Cstr::new("/wg/unlock_secret")),
             ByteBuf::try_from_slice(&*serialied).unwrap(),
         ));
    }

    fn isSecretEqual(secret : String) -> bool
    {
        return true;
    }

    pub fn unlock(&mut self, parameters: &Unlock) -> Result<()> {

        print!("Unlock called: {:?}", parameters);

        if !self.isSecretEqual(parameters.pin){ Error("Secrets do not match");}

        self.setLockedStatus(false);
        // done
        Ok(())
    }

    pub fn register_key_pair(&mut self, parameters: &RegisterKeyPair) -> Result<KeyResponse> {

        let privkey;
        let pubkey;
        let label;
         /*
            Trussed: safe a private key w/ label in the persistent storage. -> id 
            return KeyResponse
        */

        Ok(KeyResponse{  pubkey : [0;32], id : 0, label : String::from("A key label!") })
    }

    pub fn update_key_pair( &mut self, parameters: &UpdateKeyPair) -> Result<KeyResponse> {

       /*
            Trussed: update a private key w/ label in the persistent storage. -> id 
            return KeyResponse
       */
        Ok(KeyResponse{ pubkey : [0;32], id : 0, label : String::from("A key label!")})
    }

    pub fn delete_key_pair( &mut self, parameters: &DeleteKeyPair) -> Result<()> {


        /*
             TODO : Return Collection istead of single object
             Trussed: find the private key via id and safely remove the information from the persistent storage
         */
 
         Ok(())
     }

    pub fn list_keys( &mut self, parameters: &ListKeys) -> Result<KeyResponse> {

        /*
            TODO : Return Collection istead of single object
            Trussed: iterate keystore and return <id, label,> for each key
        */
        Ok(KeyResponse{pubkey : [0;32], id : 0, label : String::from("A key label!")})
    }

    pub fn generate_key_pair( &mut self, parameters: &GenerateKeyPair) -> Result<KeyResponse> {

        /*
            Trussed: Generate a new key pair and store w/ label and id -> return id
            return ID
        */

        Ok(KeyResponse{ pubkey : [0;32], id : 0, label : String::from("A key label!")})
    }

    pub fn get_aead(&mut self, parameters: &GetAead) -> Result<AEAD> {

        print!("GetAEAD called. Params: {}", *parameters);
        /*
            params -> pubkey, C, H 
             - Trussed:  obtain the private key handle
             - Trussed:  dhparam = DH(privkey, parameters->pubkey)
             - Trussed:  Ck = KDF2 ( parameters->c, dhparam )
             - Trussed:  aead = chacha20poly1305(ZERO_NONCE, timestamp, parameters->h )
             Return AEAD 
        */
        Ok(AEAD([0;32]))
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
