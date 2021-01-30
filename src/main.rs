use core::convert::TryFrom;

use anyhow::Result;
use trussed::Interchange;
use log::info;

use trussed_totp_pc_tutorial::{
    cli,
    totp,
    board,
};

fn main() -> Result<()> {

    init_logger();
    info!("Welcome to the tutorial.");

    let args = init_app();

    let state_file: &str = args.value_of("STATE-FILE").unwrap();
    let board = board::init_board(state_file);
    let mut trussed_service = trussed::service::Service::new(board);
    let (totp_requester, totp_responder) = trussed::pipe::TrussedInterchange::claim(0).unwrap();
    let totp_client_id = littlefs2::path::PathBuf::from(b"totp");
    assert!(trussed_service.add_endpoint(totp_responder, totp_client_id).is_ok());
    // In real life, the second parameter is a `Syscall` implementation, that signals to the
    // ambient runtime to call the service. Here, we use the service's implementation, which simply
    // causes it to call itself :)
    let trussed_client = trussed::client::ClientImplementation::new(totp_requester, &mut trussed_service);
    let mut authenticator = totp::Authenticator::new(trussed_client);

    info!("Let's go!");
    let command = totp::Command::try_from(&args)?;

    match command {
        totp::Command::Register(register) => {
            authenticator.register(&register)?;
        }
        totp::Command::Authenticate(authenticate) => {
            let otp = authenticator.authenticate(&authenticate)?;

            println!("OTP = {:?}", &otp);
        }
    }

    Ok(())
}

pub fn init_app() -> clap::ArgMatches<'static> {
    let app = cli::app();
    let matches = app.get_matches();
    matches
}

pub fn init_logger() {
    simple_logger::SimpleLogger::new().init().unwrap();
}

