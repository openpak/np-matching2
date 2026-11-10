# Changelog

## v0.2.16

Member NpIds follow each console's RT realm (prds#175, prds#145). Every NpId the agent emits (CreateJoinRoom self, JoinRoom member list, MemberJoined event, SearchRoom owner, GetUserInfoList) used the fixed options `ptnpps3`. The firmware derives a console's NpId from its RT JID `<id>@<cc>.<cc>.np.playstation.net/ps3` (options `<cc><cc>ps3`, §30), so Terraria activated signaling toward an NpId no RT connection matched and the PS3 killed the signaled one after 60 s (§32). The options are now `<cc><cc>ps3` with cc = the account's core country, normalized as np-account does for the ticket (lower case, `us` by default). The test client and `ticket` mode issue tickets with that country, no longer a fixed `pt`.

## v0.2.14

New `np-matching2 ticket <online id>` mode: prints a fresh NP ticket for the account (resolved through the account core, signed with the agent's key) and nothing else. It signs headless NP participants in as an account — first user is the Terraria relay's RT signaling probe (`terraria signalprobe`).

## v0.2.13

Room messages: SendRoomChatMessage (0x3208) and SendRoomMessage (0x320a) are answered and forwarded to the room's other members as the matching message events (0x3209 chat / 0x320b message, room-key MAC'd), with the 16-byte destination passed through and echoed (protocol doc §24). The test client gains a `msg` mode that sends one broadcast room message and holds the join for a minute.

## v0.2.12

The headless test client can publish a member endpoint on JoinRoom like a real console (`NP_TESTCLIENT_PUBLIC_IP`: element 0x6e = public IPv4, 0x13 = NAT type) and can hold the join open (`testclient <id> hold`, 180 s). For the PS3 relay's signaling capture: a host that is told about the new member has an address to signal to (prds#145).

## v0.2.11

A request signed with a newer login's key on a connection pinned to an older login is re-resolved against the active logins instead of being refused as "no session for request". Real PS3 (2026-11-07): the console logged in twice, sent the CreateJoinRoom first step (0x1209) signed with the second login's key on the plain connection pinned to the first, and got no reply, so the hosted world never became a room.

## v0.2.10

Cross-play is always on (owner rule, prds#145): PS3 search lists the Wii U rooms of the same compat group by default;
`NP_MATCHING_CROSS_NETWORKS` is gone, `NP_MATCHING_CROSSPLAY_OFF=1` is an incident kill switch. A join into a Wii U room is answered
with ROOM_FULL (result byte 0x19, inferred mapping of 0x80022b19) instead of silence, logged as "cross-play join not yet supported
(relay pending)" and counted, until the relay exists.

## v0.2.9

Pieces for a real two-player join (prds#28; interfaces shared with the cross-network relay, prds#145):
- **Keepalive echo.** A lone 0x00 on a plain connection is answered with 0x00. On hardware the console closed its main agent connection about 20 s after the server last sent anything, so a host had no open connection to receive room events.
- **Room keys.** Each member gets a 16-byte room key, kept in `m2_room_keys`. The 0x3200/0x3201 reply tokens 0x24 and 0x21 both carry it as AES-128-ECB(session key[:16]), matching what the firmware does with the token (vsh 0x2903a8). Room requests MAC'd with the room key (0x3202 leave on a fresh connection) are resolved by that MAC and answered with the same key. Before this, a console's leave was refused. 0x1202 on a fresh connection finds the member's latest room.
- **Peer address.** The console's own 0x6e (4 bytes, its public IPv4) and 0x13 (NAT type, inferred) from 0x3200/0x3201 are published in the core with SetEndpoints as a `udp` endpoint on port 3658. Every member's 0x4b now carries its address and NAT type back to the other members, in the join reply and in events.
- **Room events** (`NP_MATCHING_ROOM_EVENTS=1`, default off): one core Watch per logged-in plain connection. MEMBER_JOINED becomes event 0x320c (the joiner's 0x4b, 64-bit room id at header +8, MAC with the receiver's room key). Codes come from the firmware's event table and handlers; the header layout is inferred. Left/owner events wait for element 0x62.

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
