# trussed-totp-pc-tutorial

This is a simple application implementing OATH TOTP, built on [Trussed™][trussed].

To try it out, run `make install`, and then for instance
```
trussed-totp-pc-tutorial register alice@trussed.dev JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
```
This registers a credential, which is stored in `state.littlefs2`.

To generate a one-time password, run
```
trussed-totp-pc-tutorial authenticate alice@trussed.dev
```

For more logging prefix commands with, e.g., `RUST_LOG=debug`.

[trussed]: https://trussed.dev

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
