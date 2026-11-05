# Changelog

## v0.1.11

`NP_CAPTURE_DIR`: every non-polling request and reply is appended as redacted hex JSON lines (daily file, 0600, 90 days) so a real console's Matching2 traffic can be recorded.

## v0.1.10

0x1209 reply carries the room-server list (0x02: one 0x0a entry = port + host name). Found with Pier's PPU trace: with no entry vsh dereferences a null pointer in its done handler (0x29ae9c) and the emulator freezes.

## v0.1.9

Log volume: per-request lines and per-connection lines are Debug (`NP_LOG_LEVEL=debug`); normal level logs one summary line a minute with per-command counts, replies missing and average ms, plus logins, errors and the first unimplemented/unknown request per command per minute (with redacted hex).

## v0.1.8

0x1209 (first room-family request after Terraria's Start Game) answered with the required element only.

## v0.1.7

GetUserInfoList entries carry the user's display name (0x0c) as well as the NpId.

## v0.1.6

0x1007 = GetUserInfoList is answered (each requested user with its NpId only; no joined rooms yet).

## v0.1.5

0x1007 (MAC'd with the passphrase, seen from Terraria's Join Game screen) is captured as redacted hex.

## v0.1.4

Unimplemented commands are logged with the request hex (secrets redacted), so room commands can be captured from a real game.

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
