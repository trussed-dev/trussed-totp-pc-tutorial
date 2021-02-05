use core::convert::TryFrom;

use anyhow::Result;
use log::info;

use tutorial::{authenticator, cli, platform};


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
fn main() -> Result<()> {

    pretty_env_logger::init();
    info!("Welcome to the tutorial.");

    let (args, state_file) = cli::init_cli();

    // setup platform (in our case, PC)
    let trussed_platform = platform::init_platform(state_file);

    // setup Trussed
    let mut trussed_service = trussed::service::Service::new(trussed_platform);
    let client_id = "totp";
    // In real life, `trussed_service.try_new_client` has an additional parameter that is a `Syscall`
    // implementation; giving the client a way to signal the ambient runtime to call the service.
    // Here, we use the service's implementation of `Syscall`, where it simply calls itself :)
    let trussed_client = trussed_service.try_as_new_client(client_id).unwrap();

    // setup authenticator
    let mut authenticator = authenticator::Authenticator::new(trussed_client);


    // The "runner"'s actual "scheduling" part starts here
    info!("Let's go!");

    // the "args" come in over the CLI "interface", and are "deserialized" for processing
    // using `Command`'s implementation of `TryFrom`, the standard Trait for fallible type conversion
    let command = authenticator::Command::try_from(&args)?;

    // the command is "dispatched" into the application
    match command {
        authenticator::Command::Register(register) => {
            authenticator.register(&register)?;
        }
        authenticator::Command::Authenticate(authenticate) => {
            let otp = authenticator.authenticate(&authenticate)?;

            // the application response is "dispatched" back over the CLI
            println!("{}", &otp);
        }
    }

    Ok(())
}
