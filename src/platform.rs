//! Implementation of `trussed::Platform` trait for our platform, PC

use trussed::platform::{consent, reboot, ui};

pub mod store;

trussed::platform!(Platform,
    R: chacha20::ChaCha8Rng,
    S: store::Store,
    UI: UserInterface,
);

pub fn init_platform(state_path: impl AsRef<std::path::Path>) -> Platform {
    use trussed::service::SeedableRng;
    let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
    let store = store::init_store(state_path);
    let ui = UserInterface::new();

    let platform = Platform::new(rng, store, ui);

    platform
}

pub struct UserInterface {
    start_time: std::time::Instant,
}

impl UserInterface {
    pub fn new() -> Self {
        Self { start_time: std::time::Instant::now() }
    }
}

impl trussed::platform::UserInterface for UserInterface
{
    /// Silent authentication
    fn check_user_presence(&mut self) -> consent::Level {
        consent::Level::Normal
    }

    fn set_status(&mut self, status: ui::Status) {
        println!("Set status: {:?}", status);
    }

    fn refresh(&mut self) {}

    fn uptime(&mut self) -> core::time::Duration {
        self.start_time.elapsed()
    }

    fn reboot(&mut self, to: reboot::To) -> ! {
        println!("Restart!  ({:?})", to);
        std::process::exit(25);
    }

}

