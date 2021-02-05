//! # Trussed™-based TOTP authenticator, for PC.
//!
//! This is a demo implementation of a TOTP authenticator, built on [Trussed™][trussed].
//!
//! In general, Trussed requires a platform-specific implementation of its `Platform` trait,
//! encapsulating:
//! - Reliable **true** random number generator
//! - `littlefs`-based persistent and volatile storage backends
//! - the `UserInterface`, allowing prompts and checks of user presence, among other things
//!
//! The Trussed service can then be constructed, and hands out a configurable number of Trussed
//! client interfaces, which are passed into application constructors – having access to a Trussed
//! client is essentially what makes an app a "Trussed app", and hence very portable, if the app
//! focuses only on implementation of its logic and uses its client for all:
//! - cryptography
//! - storage (keys and files)
//! - user interface
//!
//! Outside of Trussed's domain is the implementation of a "runner", which includes
//! - bring-up of the platform (e.g., in embedded, initialization of all peripherals)
//! - setup and wiring of all components (internally, [`interchange`][interchange] is used)
//! - implementation of external interfaces (e.g. USB, NFC, CLI, HTTP)
//! - implementation of dispatch between (possibly multiple) interfaces and (possibly multiple)
//!   apps, including serialization/deserialization of interface-level protocols (we recommend use of
//!   [`serde`][serde] and, again, [`interchange`][interchange]).
//! - scheduling of all the components involved (e.g., in embedded, we recommend [`RTIC`][rtic], an
//!   efficient, minimal scheduler which uses the hardware's interrupt controller directly. On
//!   PCs, there are of course many competing options).
//!
//! The reason for splitting out all this additional infrastructure is a general cryptographic
//! principle of doing one thing and doing that one thing well (although... Trussed does do quite a
//! lot of things), but also flexibility, as different platforms may have very different
//! capabilities, use async/await instead of RTIC, etc. etc.
//!
//!
//! [trussed]: https://trussed.dev
//! [interchange]: https://docs.rs/interchange/
//! [serde]: https://serde.rs
//! [rtic]: https://rtic.rs

/// In real life we would use `no_std`-compatible errors, and define `thiserror` wrappers.
/// Here, we are somewhat untyped and just use `anyhow`.
pub use anyhow::Result;

pub mod authenticator;
pub mod cli;
pub mod platform;

#[cfg(feature = "include-main-in-lib-for-docs")]
pub mod main;
