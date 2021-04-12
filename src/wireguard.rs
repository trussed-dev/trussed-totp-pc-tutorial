//! Wireguard
/*

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

use serde::{Deserialize, Serialize};
use trussed::{ consts, syscall, types::{KeySerialization, Location,Vec}};
use trussed::{ByteBuf, types::{Mechanism}};

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

 #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
 #[allow(missing_docs)]
 struct UnlockStatus{
    is_unlocked : bool,
 }

 #[derive(Clone, Debug, PartialEq)]
 #[allow(missing_docs)]
 struct UnlockSecret{
     password : trussed::ByteBuf<consts::U256>,
 }

 // To be serialized and safed in the trussed store
 #[derive( Debug, PartialEq,Clone, Deserialize, Serialize)]
 #[allow(missing_docs)]
 pub struct KeyInfo 
 {
    label : trussed::ByteBuf<consts::U256>,
    privkey : trussed::types::ObjectHandle,
 }

// hex
impl core::fmt::Display for AEAD {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

impl core::fmt::Display for KeyResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?} w/ UID: {} pubkey : {:x?}", self.id, self.label, self.pubkey)
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


#[allow(missing_docs)]
impl<T> Wireguard<T>
where
    T: trussed::Client + trussed::client::mechanisms::X255,
{
   /// Constructor, consumes a Trussed client
   pub fn new(trussed: T) -> Self {
    Self { trussed }
    }


    /*
    fn init_store(&mut self) // to be called when paths dont exist
    {

    }
*/
    fn is_unlocked(&mut self) -> bool
    {
        let strpath = "/wg/unlocked_status";
        let p =  trussed::types::PathBuf::from(strpath.as_bytes());

        let ans = syscall!(self.trussed.read_file(
            Location::Internal,
            p
        ));
        let locked_status:UnlockStatus;
        locked_status = postcard::from_bytes(&ans.data).expect("unable to deserialize");

        return locked_status.is_unlocked;
    }

    fn set_unlock_status(&mut self, status : bool )
    {
       let mut buf = [0u8; 512];
       let serialied = postcard::to_slice(&UnlockStatus{is_unlocked : status}, &mut buf)
       .expect("cannot serialize");

       let strpath = "/wg/unlocked_status";
       let p =  trussed::types::PathBuf::from(strpath.as_bytes());

       syscall!(self.trussed.write_file(
            Location::Internal,
            p,
            ByteBuf::try_from_slice(&*serialied).unwrap(),
            None
        ));
    }

    fn get_list_keys(&mut self) -> Result<Vec::<Option::<KeyInfo>, heapless::consts::U8>>
    {
        let strpath = "/wg/key_store";
        let p =  trussed::types::PathBuf::from(strpath.as_bytes());
        let r = syscall!(self.trussed.read_file(Location::Internal,p));
       

        let key_infos : Vec::<Option::<KeyInfo>, heapless::consts::U8> ;
        match postcard::from_bytes(&r.data)
        {
            Ok(val) => { key_infos = val;}
            Err(_) =>{ key_infos= Vec::<Option::<KeyInfo>, heapless::consts::U8>::new() }
        }
        return Ok(key_infos);

    }

    fn add_to_key_store(&mut self, val : &KeyInfo) -> Result<()>
    {

    
        let mut key_infos = self.get_list_keys().unwrap();
        // check if exists
        for (_, ele ) in key_infos.iter().enumerate()
        {
            if ele.is_some() && ele.clone().unwrap().label == val.label
            {
                // This key exists
                print!("This key already exists.\n");
                return Err(anyhow::anyhow!("This key exists"));
            }
        }


        // Set new key 
        match key_infos.push(Option::<KeyInfo>::from(KeyInfo{label: val.label.clone(), privkey : val.privkey}))
        {
            Ok(_) => {}
            Err(_) => {}
        }
       // print!("{:?}", keyInfos);

       //Write keys
       let strpath = "/wg/key_store";
        let mut buf = [0u8; 10000];
        let serialied = postcard::to_slice(&key_infos.clone(), &mut buf)
        .expect("cannot serialize");
        let p =  trussed::types::PathBuf::from(strpath.as_bytes());
        syscall!(self.trussed.write_file(
             Location::Internal,
             p,
             ByteBuf::try_from_slice(&*serialied).unwrap(),
             None
         ));

         Ok(())
    }

    pub fn get_unlock_secret(&mut self)
    {
            //Stub
    }

    fn is_secret_equal(&self, secret : &String) -> bool
    {
        secret.to_string();
        return true;
    }

////////////////////////////
    pub fn set_unlock_secret(&mut self, _: &SetUnlockSecret) -> Result<()>  
    {
            Ok(())
    }


    pub fn unlock(&mut self, parameters: &Unlock) -> Result<()> {

        if !self.is_secret_equal(&parameters.pin)
        { 
            return Err(anyhow::anyhow!("Secret does not match"));
        }
        
        self.set_unlock_status(true);

        print!("Unlock status: {:?}", self.is_unlocked());
        
        // done
        Ok(())
    }

    pub fn register_key_pair(&mut self, parameters: &RegisterKeyPair) -> Result<KeyResponse> {


        if !self.is_unlocked()
        {
            print!("Device is locked");
            return Err(anyhow::anyhow!("Device is locked. Unlock first."));
        }


        print!("Privkey {:?}",parameters.privkey);
        print!("Pubkey {:?}",parameters.pubkey);
        print!("label {:?}",parameters.label);

        //let privkey;
        //let pubkey;
        //let label;
         /*
            Trussed: safe a private key w/ label in the persistent storage. -> id 
            return KeyResponse
        */

        Ok(KeyResponse{  pubkey : [0;32], id : 0, label : String::from("A key label!") })
    }

    pub fn update_key_pair( &mut self, _: &UpdateKeyPair) -> Result<KeyResponse> {

       /*
            Trussed: update a private key w/ label in the persistent storage. -> id 
            return KeyResponse
       */
        Ok(KeyResponse{ pubkey : [0;32], id : 0, label : String::from("A key label!")})
    }

    pub fn delete_key_pair( &mut self, _: &DeleteKeyPair) -> Result<()> {


        /*
             TODO : Return Collection istead of single object
             Trussed: find the private key via id and safely remove the information from the persistent storage
         */
 
         Ok(())
     }

    pub fn list_keys( &mut self) -> Result<KeyResponse> {

        let key_list = self.get_list_keys().unwrap();
        for (index, ele ) in key_list.iter().enumerate()
        {
            let pubkey = syscall!(self.trussed.derive_x255_public_key(ele.clone().unwrap().privkey,
                Location::Internal,
            )).key;

            let pub_serialized = syscall!(self.trussed.serialize_key( Mechanism::X255, pubkey, KeySerialization::Raw)).serialized_key.into_vec();
            print!("Key {:?}\nPublic Key: {:x?}\nLabel : {:?}\n\n",index+1,pub_serialized, ele.clone().unwrap().label)
        }
        Ok(KeyResponse{pubkey : [0;32], id : 0, label : String::from("A key label!")})
    }

    pub fn generate_key_pair( &mut self, parameters: &GenerateKeyPair) -> Result<KeyResponse> {
        
        // Generate Keys
        let privkey = syscall!(self.trussed.generate_x255_secret_key(
            Location::Internal,
        )).key;

        let pubkey = syscall!(self.trussed.derive_x255_public_key(privkey,
            Location::Internal,
        )).key;

       
        //Store
        let key_info = KeyInfo{ label : ByteBuf::try_from_slice( parameters.label.as_bytes()).map_err(EmptyError::from)?, privkey : privkey };
        match self.add_to_key_store(&key_info)
        {
            Ok(_)=>{}
            Err(err) =>{return Err(err);}
        }
        //Prepare response 
        let pub_serialized = syscall!(self.trussed.serialize_key( Mechanism::X255, pubkey, KeySerialization::Raw)).serialized_key.into_vec();
        let mut resp = KeyResponse{ pubkey : [0;32], id : 0, label : String::from(parameters.label.clone()) };

        for (place, element) in resp.pubkey.iter_mut().zip(pub_serialized.iter()) {
        *place = *element;
        }

       print!("Keys generated. \nPubkey: {:x?}, \nLabel: {:?}", resp.pubkey, resp.label);
        // Generate key pair -> DH curve25519
        /*
            Trussed: Generate a new key pair and store w/ label and id -> return id
            return ID
        */

        Ok(resp)
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
