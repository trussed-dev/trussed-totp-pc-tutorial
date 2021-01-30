use core::convert::TryFrom;

use anyhow::{Error, Result};
use clap::{
    App,
    Arg,
    crate_authors, crate_version,
    SubCommand,
};

use crate::totp::{Authenticate, Command, Register};

const ABOUT: &str = "
An example app, using Trussed™, running on PC, implementing TOTP.

Project homepage: <https://github.com/trussed-dev/trussed-totp-pc-tutorial>.
";

pub fn app() -> clap::App<'static, 'static> {

    let app = App::new("trussed-otp-pc-tutorial")
        .author(crate_authors!())
        .version(crate_version!())
        .about(ABOUT)
        // .help_message("Prints help information. Use --help for more details.")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)

        .arg(Arg::with_name("STATE-FILE")
             .short("s")
             .long("state-file")
             .default_value("state.littlefs2")
             .help("file containing persistent state")
             .required(false)
             .global(true)
        )

        // cf. https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        // eg. otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

        .subcommand(SubCommand::with_name("register")
            .about("register a TOTP secret")
            .arg(Arg::with_name("label")
                 .help("label to use for the TOTP secret, e.g. alice@trussed.dev")
                 .value_name("LABEL")
                 .required(true)
             )
            .arg(Arg::with_name("secret")
                 .help("the actual TOTP seed, e.g. JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
                 .value_name("SECRET")
                 .required(true)
             )
        )

        .subcommand(SubCommand::with_name("authenticate")
            .about("generate a TOTP from a previously registered secret")
            .arg(Arg::with_name("TIMESTAMP")
                 .short("t")
                 .long("timestamp")
                 .help("timestamp to use to generate the OTP, as seconds since the UNIX epoch")
                 .value_name("TIMESTAMP")
                 .required(false)
             )
            .arg(Arg::with_name("label")
                 .help("Label of the TOTP secret to use, e.g. alice@trussed.dev")
                 .value_name("LABEL")
                 .required(true)
             )
        )
    ;

    app

}

impl TryFrom<&'_ clap::ArgMatches<'static>> for Command {
    type Error = Error;
    fn try_from(args: &clap::ArgMatches<'static>) -> Result<Self> {
        if let Some(command) = args.subcommand_matches("register") {
            return Ok(Command::Register(Register {
                label: command.value_of("label").unwrap().into(),
                secret: command.value_of("secret").unwrap().into(),
                period: 30,
            }));
        }

        if let Some(command) = args.subcommand_matches("authenticate") {
            let timestamp = match command.value_of("timestamp") {
                Some(s) => s.parse()?,
                None => {
                    let since_epoch = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap();
                    since_epoch.as_secs()
                }
            };
            return Ok(Command::Authenticate(Authenticate {
                label: command.value_of("label").unwrap().into(),
                timestamp,
            }));
        }
        Err(anyhow::anyhow!("Unexpected case"))
    }
}

