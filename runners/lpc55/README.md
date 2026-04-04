# LPC55 runner

The entire firmware that runs all the things.

## Solo 2 Hacker builds

For a standalone Solo 2 Hacker, the safest custom-firmware path is the `develop`
variant because it disables encrypted storage (`no-encrypted-storage`).

- `make build-hacker`
  Builds `board-solo2,develop` and writes `app-solo2.bin`.
- `make build-hacker-recovery`
  Builds `board-solo2,develop,format-filesystem` and forces a filesystem format on first boot.
- `make build-release`
  Builds the PRINCE/PUF-backed production-style image. Use this only if the device is
  provisioned for encrypted storage.


### Logging

The easy + fast way to log is to use the `log-rtt` feature.
Listening on port `19021` (e.g. via `netcat localhost 19021`) outputs the RTT message output
from `JLinkGDBServer -strict -device LPC55S69 -if SWD -vd`.

The slower alternative (although not so bad due to `delog` bundling) is to use the `log-semihosting` feature.
Both at once does not work, neither does `log-serial`.

Additionally, logging features need to be turned on.
An example invocation: `cargo run --release --features board-lpcxpresso55,develop,log-rtt,fido-authenticator/log-all` 
