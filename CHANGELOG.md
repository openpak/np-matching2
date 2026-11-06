# Changelog

## v0.2.8

Room members stay alive while their console is logged in: every 30 s the agent heartbeats each account with an unexpired login session (renewed by 0x1003). The per-connection keepalive was not enough on hardware: the console's room-server connection ends after the room is created and its later 0x1001/0x1007 traffic carries no account, so the core reaped a real PS3 host 5 minutes after creating its room (2026-11-06, prds#28).

## v0.2.7

No identity copies in the core (owner rule, prds#145): rooms no longer carry an `owner_name` attribute and no display name is sent to the
core on create or join. The owner's and members' NpIds are read from the account core (np link online id; an account without one shows
its core display name cut to 16) each time a room is listed or joined.

PS3 search, join and the world count stay inside network `np` (before, a PS3 search also listed the Wii U rooms the NEX mirror writes,
and a join could land in one). `NP_MATCHING_CROSS_NETWORKS=wiiu` (default empty) lists the other networks' rooms of the same compat
group; a join into one is refused and logged until the cross-network relay exists (phase 3).

## v0.2.6

Real consoles get the agent as an IP (NP_MATCHING_HOST=145.241.199.19, paired with np-community NP_MATCHING_AGENT): the PS3 resolves the agent name outside the DNS catcher, and vsh checks the no-SNI leaf CN against that host, so the leaf now carries the IP. A hello with SNI `matching.np.community.playstation.net` (front.AgentName) still reaches the agent, so the headless testclient keeps working; the testclient always sends that name. First real-PS3 room created on 2026-11-06 (prds#28).

## v0.2.5

A room member is heartbeated in the core every 30 s while its room-server connection is open (the console's keepalive bytes carry no account); before, the core reaped the host after 5 minutes.

## v0.2.4

testclient offers the RSA key-exchange suites the agent's TLS requires.

## v0.2.3

`np-matching2 testclient <online id>`: a headless second player run inside the container (ticket issued with the agent's key for an existing test account) that logs in, searches and joins the newest room; for the two-client test.

## v0.2.2

The room-server connection (0x2001 onwards, seen live in Pier) carries no communication id: the title and login are found by the request's session MAC.

## v0.2.1

SearchRoom (0x1200/0x120c) and JoinRoom (0x3201) over the core. Search lists the open rooms of the title in the searcher's group (`compat` forced to `old-gen-1.2.4`);
rooms carry an `owner_name` attribute. Join resolves the room from the request (candidates documented in the code) with a logged fallback to the newest room, and replies with the six elements the
firmware requires (member id 0x16, tokens, room id, room data, member list). Room id = server 1 << 48 | first 48 bits of the session id. **INFERRED** (to be confirmed by the first real capture): the
SearchRoom request filters (ignored), the way JoinRoom names its room, the RoomDataExternal head fields (flag attr, max slot) and the room-data head. Tested against a real matchmaking core.

## v0.2.0

Rooms over the matchmaking core: 0x3200 (CreateJoinRoom) creates a `room` session under the title key (attributes `compat=old-gen-1.2.4`, `console=ps3`, the console's request without tokens in `data`) and
replies with the five elements the firmware's parser requires (tokens 0x24/0x21, room id 0x3a, room data 0x71, creator as member 0x4b); 0x1202 updates the session data; 0x3202 leaves it.
Layouts decoded statically from vsh (no console or emulator run yet); field meanings partly inferred from the API structs. The adapter keeps no room state.

## v0.1.12

0x2001 (second step of CreateJoinRoom) answered with the room-server list, from the firmware's reply parser; unverified live.

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
