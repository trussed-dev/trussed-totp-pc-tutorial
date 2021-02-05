BINARY := trussed-totp-pc-tutorial
LABEL := alice@trussed.dev
SECRET := JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP

register:
	$(BINARY) register $(LABEL) $(SECRET)

register-dev:
	cargo run -- register $(LABEL) $(SECRET)

authenticate:
	$(BINARY) authenticate $(LABEL)

authenticate-dev:
	cargo run -- authenticate $(LABEL)

install:
	cargo install --path . --locked
