use core::convert::TryFrom;

use anyhow::Result;
use log::info;

// #[cfg(feature = "include-main-in-lib-for-docs")]
// use crate::{authenticator, cli, platform};
// #[cfg(not(feature = "include-main-in-lib-for-docs"))]
use tutorial::{wireguard, cli, platform};


/// Simplified "runner" to demonstrate the TOTP authenticator app.
///
/// In general: There is a runner (often a firmware), which is responsible
/// for piping together and scheduling the main components of a Trussed runner:
///
/// - interfaces (typically USB, possibly NFC)
/// - dispatch (between the interfaces and the apps)
/// - multiple Trussed applications
/// - multiple Trussed clients, connected to the Trussed service
///
/// In this tutorial, the interface is a CLI, which directly dispatches into the single app.
///
/// This allows us to more clearly demonstrate:
/// - the authenticator app, which is only concerned with the logic needed to
///   process a `Command`, using its Trussed client for crypto, storage, and UI.
/// - the piping necessary to pack everything up into a runner
///
pub fn main() -> Result<()> {

    pretty_env_logger::init();
    info!("Welcome to the tutorial.");

    let (args, state_file) = cli::init_cli();

    //setup wireguard
    let trussed_platform_wg = platform::init_platform(state_file.clone());
    let mut trussed_service_wg = trussed::service::Service::new(trussed_platform_wg);
    let client_id_wg = "wireguard";
    let trussed_client_wg = trussed_service_wg.try_as_new_client(client_id_wg).unwrap();
    let mut wireguard = wireguard::Wireguard::new(trussed_client_wg);

    
    // The "runner"'s actual "scheduling" part starts here
    info!("Let's go!");



    // the "args" come in over the CLI "interface", and are "deserialized" for processing
    // using `Command`'s implementation of `TryFrom`, the standard Trait for fallible type conversion
    let wg_command = wireguard::WgCommand::try_from(&args)?;


    // the command is "dispatched" into the application
    match wg_command {
       wireguard::WgCommand::Unlock(unlock) => 
        {
            wireguard.unlock(&unlock).ok();
        }
       
        wireguard::WgCommand::RegisterKeyPair(register_key_pair) =>
         {
            wireguard.register_key_pair(&register_key_pair).ok();
         }
        wireguard::WgCommand::UpdateKeyPair(update_key_pair) => 
        {
            wireguard.update_key_pair(&update_key_pair).ok();
        }
        wireguard::WgCommand::DeleteKeyPair(delete_key_pair) => 
        {
            wireguard.delete_key_pair(&delete_key_pair).ok();
        }
        wireguard::WgCommand::GenerateKeyPair(generate_key_pair) => 
        {
            wireguard.generate_key_pair(&generate_key_pair).ok();
        }

        wireguard::WgCommand::ListKeys(_) => 
        {
            wireguard.list_keys().ok();
        }

        wireguard::WgCommand::SetUnlockSecret(secret) => 
        {
            wireguard.set_unlock_secret(&secret).ok();
        }

    
        wireguard::WgCommand::GetAead(get_aead) => {

            wireguard.get_aead(&get_aead).ok();
        }
    }

    Ok(())
}
