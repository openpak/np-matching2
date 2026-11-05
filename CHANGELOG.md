# Changelog

## v0.1.3

Fix: the firmware's real hello (TLS 1.2, eight RSA-kex suites incl. the 00ff SCSV, one signature_algorithms extension; 80 bytes) was classified as
not-firmware and sent down the D2R path, so the PS3 login never reached the agent. Classifier now accepts old-block suites plus
signature_algorithms/renegotiation_info only; tested with the captured hello.

## v0.1.2

Short hellos are logged (hex).

## v0.1.1

The front routes a hello that names the Matching2 host (SNI) to the agent as well, whatever extensions it carries.

## v0.1.0

First release: the PS3 Matching2 handshake (0x1001 ping, 0x1002 login with NP ticket verification, 0x1003 renew, 0x1008 world list),
sessions in Postgres, world counts from the matchmaking core, the no-SNI front (firmware hello vs everything else), erasure, and a
headless test client. Room commands (0x32xx) are logged as unimplemented until captured from a real game.
