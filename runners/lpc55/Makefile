BOARD := lpcxpresso55
DEVELOP := --features board-$(BOARD),develop
PROVISIONER := --features board-$(BOARD),develop-provisioner

# builds firmware bundle with development features,
# i.e., no encrypted storage, etc.
build-dev:
	cargo build --release $(DEVELOP)
	cargo objcopy --release $(DEVELOP) -- -O binary app.bin

# builds firmware bundle as before, *including* provisioner app
build-pro:
	cargo build --release $(PROVISIONER)
	cargo objcopy --release $(PROVISIONER) -- -O binary provisioner.bin

# Solo 2 Hacker: production-style build with encrypted storage.
# This requires the device to be provisioned for PRINCE/PUF.
build-release:
	cargo build --release --features board-solo2
	cargo objcopy --release --features board-solo2 -- -O binary app-solo2.bin

# Solo 2 Hacker: development build without encrypted storage.
build-hacker:
	cargo build --release --features board-solo2,develop
	cargo objcopy --release --features board-solo2,develop -- -O binary app-solo2.bin

# Solo 2 Hacker recovery build: plain storage plus forced filesystem format.
build-hacker-recovery:
	cargo build --release --features board-solo2,develop,format-filesystem
	cargo objcopy --release --features board-solo2,develop,format-filesystem -- -O binary app-solo2.bin

.PHONY: today-as-minor-version
today-in-days:
	python -c "from datetime import date as d; print((d.today() - d(2020, 1, 1)).days)"

run-dev:
	cargo run --release $(DEVELOP)

run-pro:
	cargo run --release $(PROVISIONER)

bacon:
	bacon

jlink:
	../../scripts/bump-jlink
	JLinkGDBServer -strict -device LPC55S69 -if SWD -vd


PACK_VERSION := $(shell wget -O - -qq https://mcuxpresso.nxp.com/cmsis_pack/repo/NXP.pidx|grep LPC55S69|python -c'import sys; print(sys.stdin.read().rsplit("version=\"", 1)[1].split("\"", 1)[0])')
PACK := NXP.LPC55S69_DFP.$(PACK_VERSION).pack
get-cmsis-pack:
	wget -qq https://mcuxpresso.nxp.com/cmsis_pack/repo/$(PACK) -O ./lpc55s69.pack
