# Changelog

## v0.1.1

The front routes a hello that names the Matching2 host (SNI) to the agent as well, whatever extensions it carries.

## v0.1.0

First release: the PS3 Matching2 handshake (0x1001 ping, 0x1002 login with NP ticket verification, 0x1003 renew, 0x1008 world list),
sessions in Postgres, world counts from the matchmaking core, the no-SNI front (firmware hello vs everything else), erasure, and a
headless test client. Room commands (0x32xx) are logged as unimplemented until captured from a real game.
