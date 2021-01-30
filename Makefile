LABEL := alice@trussed.dev
SECRET := JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP

register:
	cargo run -- register $(LABEL) $(SECRET)

authenticate:
	cargo run -- authenticate $(LABEL)
