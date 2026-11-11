# Changelog

## v0.2.27

Why a PS3 host left its Terraria room 0.7 s after creating it under v0.2.26 (prds#145; research ps3/matching2-protocol.md §41).

- **Each member's NpId is the one its console uses for itself.** The console's own NpId (login and 0x3200 element 0x0b) is PS3Test +
  `ptnpps3`; we listed the owner as PS3Test + `ptptps3`. vsh 4.93 0x1e4950 puts every member whose NpId differs from its own
  (sceNpUtilCmpNpId 0x1f79bc: options 0..4 must match) into its signalling table, so with v0.2.26's mesh/star option the owner activated
  signalling toward itself, and Terraria left the room. The agent now keeps the 8 option bytes from each login's 0x0b and emits them
  wherever that account's NpId appears (member lists, search owners, member and owner events). Accounts without a login keep the derived
  `<cc><cc>ps3`. Golden test `agent.TestMemberNpIdIsTheConsolesOwn` uses the recorded bytes.
- `NP_MATCHING_SIGOPT_OFF=1` returns every room's 0x6d empty again (pre-v0.2.26 behaviour), as a fallback switch for hardware runs.

## v0.2.26

Why no PS3 host ever started signalling toward a member (prds#145; research ps3/matching2-protocol.md §40).

- **Room data internal echoes the host's signalling option (0x6d).** A host's 0x3200 carries its SceNpMatching2SignalingOptParam as element
  0x6d (Terraria 01.12 `01 00..` = mesh, Minecraft 01.84 `02 00..` = star with the owner as hub, recorded 2026-11-11). The firmware's
  signalling manager (vsh 4.93 0x1e4950, on the CreateJoinRoom/JoinRoom done) reads the option only from the reply's room data 0x6d
  (0x29cb6c stores it at room+0x48, 0x288bf4 serves it), and 0x1e4274 calls ActivateConnection toward a member only for type 1, or type 2
  when one side is the hub. We returned 0x6d empty, so the type was 0 and no PS3 ever offered, as host or joiner. The option is now stored as
  room attr `b6d` in the core (members-only) and returned in the create and join replies. Bridged (Minecraft) rooms carry star `02 00..`.
- Neither game signals on its own: Terraria 01.12 imports no `sceNpSignaling*` function (only Matching2's RegisterSignalingCallback and
  SignalingGetConnectionStatus), the same model as Minecraft. Golden test: `agent.TestSignalingOptionIsEchoedInRoomData`.

## v0.2.25

Room events as the PS3 takes them, from the 2026-11-11 hardware experiment and a vsh 4.93 decode (prds#145; research ps3/matching2-protocol.md §39).

- **MemberJoined (0x320c) carries the 0x3a room id by default.** That form made a real PS3 host (Minecraft 01.84 and Terraria) answer with
  request 0x1203 48-117 ms later. The 0x3a element is not what gets the event accepted. The handler (vsh 0x2c8968) raises 0x1101 to the game
  first (0x2c8c24). Only after that, and only on the room owner, does it echo the 0x3a value back in an internal request (0x289404, type 0x1a).
  So the 0x1203 proves the game got the join. Whether the variants without 0x3a also got through can't be seen.
- **The owner's 0x1203 gets ALREADY_JOINED (result 0x30).** Its done (0x299364) never completes a type-0x1a request, so an empty success made
  the host rebuild and resend it until its 30 s timeout (223 and 234 resends live). Any non-zero result except 0x0e ends it at once and
  silently: types 0x1a-0x1c never call the game back (0x290f48). The 0x1203 at the end of a console's own JoinRoom (type 0x0a, told apart by
  the request id, `wire.ReqType`) still gets the empty success it needs. It logs `matching2 host acknowledged member join`.
- **MemberLeft (0x320f) and UpdatedRoomDataInternal (0x320e) carry 0x3a too.** The owner answers with 0x1204 and 0x120a. Both complete on an
  empty reply (dones 0x299394, 0x2993c4), so each one confirms that the event was accepted. 0x120a used to go unanswered and is now answered
  empty. RoomDestroyed has no follow-up and stays without 0x3a.
- **OwnerChanged (0x3212) is pushed.** It carries 0x16 new owner id, 0x0b NpId, 0x62 cause and 0x3a (schema 0x689350). Its handler (0x2c7530) is
  the only place that moves a member's owner pointer, and MemberLeft only clears the slot. In a migrating PS3 room the host's leave used to
  leave every other PS3 with an owner pointer to a freed member, which the game reads unchecked (§34). The agent now remembers the owner each
  connection's console knows and sends OwnerChanged before the old owner's MemberLeft (and on the core's owner_changed).
- **The MemberJoined experiment is removed** (`agent/experiment.go`, `NP_MATCHING_EVENT_EXPERIMENT`). Connection ids and the recorder stay.
- Golden tests: `wire.TestRoomEventsGolden` (0x320c/0x320f with 0x3a, new 0x3212), `TestAttrRepliesGolden` (0x320e), and
  `agent.TestOwnerFollowUpsAnswered`, which uses the recorded Minecraft 0x1203 request.

## v0.2.24

MemberJoined diagnosis for the next hardware run (prds#145; research ps3/matching2-protocol.md §38). Live run 8 on v0.2.23: the PS3 host still
ignored the 0x320c. A static re-check of vsh 4.93 found no byte mismatch (receive path, MAC, room handle, member parser, listener dispatch and the
Terraria callback filter all accept our event), so this release makes the next run decisive instead of guessing a fix.

- **Connection ids.** Every agent connection gets a per-process id. It is in every request log line (`conn`), in `matching2 event sent`, in a new
  `matching2 conn closed` line (account, remote, age) and in every recorder line.
- **Recorder records pushed events.** With `NP_CAPTURE_DIR`, each pushed 0x32xx packet is a line with `pushed: true`, the event code, the
  connection id and the full packet (no secrets in it: a room-key MAC, member ids and NpIds).
- **`NP_MATCHING_EVENT_EXPERIMENT=1`** (off by default, needs `NP_MATCHING_ROOM_EVENTS=1`): on a join, the host gets the MemberJoined in every
  unproven variant, 5 s apart: the plain event on the room connection, the same bytes on each other open connection of the host (latest room
  request first), a member element without 0x59/0x6e, and the event with the optional 0x3a room id. A MemberLeft on the previous connection
  goes before each next variant, so an accepted variant does not make the next one a duplicate. Each attempt logs `matching2 experiment`
  (n, variant, conn). The first non-polling request from the host logs `matching2 experiment: host request` and stops the run. Remove after use.
- `wire.TestRoomEventsGolden` also pins that the event member element equals the create-reply member (same vsh parser 0x2c3580) and that the room
  handle and member id match the console's own live-8 0x320a header.

## v0.2.23

Room events go out the way the firmware takes them (prds#145; research ps3/matching2-protocol.md §37, static decode of vsh 4.93).

- **Only on the room's own connection.** The console gives each room its own agent connection (opened by the 0x1209 done, reopened by the 0x2001
  done, which then sends 0x3200/0x3201 on it) and looks up the MAC key of a 0x32xx event by the connection it arrives on (vsh 0x2b4bd8 ->
  0x29ba04); on any other connection the event is dropped with 0x80022335. Every logged-in connection of an account used to push every event
  (live7 pushed 0x320c twice). Now only the connection that sent the room's 0x3200/0x3201 sends its events.
- **MemberLeft (0x320f) and RoomDestroyed (0x3213) are pushed.** Element 0x62 is a u8 event cause (vsh element table), not undecoded. MemberLeft =
  0x16 leaver id + 0x0b leaver NpId + 0x62 (schema 0x689380, handler 0x2c7978, which needs the leaver in the receiver's member table at +14 and
  0x16); RoomDestroyed = 0x62 (schema 0x689338, handler 0x2c7494). Cause from the core reason: leave 1, kicked 2, anything else 5. Without
  MemberLeft a host kept the leaver's slot, and a later MemberJoined for that slot was dropped (0x800223e4 at 0x2c896c).
- `wire.TestRoomEventsGolden` pins 0x320c, 0x320f and 0x3213 byte for byte and checks them against the console's key derivation (AES-128-ECB
  decryption of the 0x24 token, vsh 0x2903a8) and room/member lookups.

## v0.2.22

Bridge routes for Minecraft cross-play (prds#177, common/minecraft docs/session-mapping.md), on the HTTP listener, bearer `NP_BRIDGE_KEY` (the routes are off
without it):

- `GET /internal/bridge/rooms`: the Minecraft rooms real PS3s host (id, room id, owner account, slots, the 184-byte session data), bridged rooms left out.
- `PUT/DELETE /internal/bridge/rooms/{game}`: a bridged room kept for a player hosting on another console, who is not connected here: created under
  the host's account with the game id as the core session's unique key, the golden attribute shapes of a real host (0x55 + 0x56, 0x57 + 0x58, the
  host's 0x59), no owner migration, renewed by every PUT (the core reaps it 300 s after the last one). It has no room key and no console connection,
  so a real console on the same account does not see it. The net version must be 0x0884.
- `GET /internal/bridge/joins?after=N`: every JoinRoom on a bridged room with the joiner, the member data, the endpoint and the whole request
  (secrets redacted); logged in full as `matching2 bridged join`. The reply is the normal JoinRoom reply.
- A room search returns the new core attribute `bridge` on bridged rooms (`RoomInfo.Bridge`).

## v0.2.21

Minecraft: PlayStation 3 Edition (NPEB01899 01.84, NP communication id NPWR05636_00) can host (prds#177, prds#163; research minecraft-lce/ps3-0184-vs-wiiu-2026-11-10.md, ps3/matching2-protocol.md §35). Terraria's create and join replies are byte-identical (`wire.TestCreateJoinReplyGolden` unchanged).

- **Per-title settings.** `NP_MATCHING_TITLES` entries take an optional `compat` (the room compatibility group, default Terraria's `old-gen-1.2.4`) and `status` (the byte in the 0x1001 reply's element 0x1d = {server id 1, status}). The title key `minecraft` defaults to group `lce-ps3-0884` and status 1: Minecraft will not host unless the server is "available".
- **Attributes, stored in the matchmaking core.** The two internal bins 0x57/0x58, the two external bins 0x55/0x56 and the searchable ints 0x4c-0x53 of a request are session attrs in the core (they survive an agent restart); each member's 0x59 is that member's data. The attribute id is the TLV element id (firmware builders 0x2b9628, 0x2b9ca0, 0x2b9d60, 0x2b9754). The ints and external bins are searchable in the core, because the core shows a non-member only searchable attrs and a joiner reads the external ones before it is a member.
- **Served.** 0x3200 and 0x3201 return the stored internal bins and each member's 0x59; 0x1202 and 0x1207 (SetRoomDataExternal) store external attrs; 0x3204 (SetRoomDataInternal, reply with the required 0x70) stores the owner's internal bins; 0x3206 and 0x3207 set and read a member's 0x59; 0x3211 kicks through the core; 0x1208 (GetRoomDataExternalList) lists the named rooms with the asked attrs; 0x1200/0x120c SearchRoom now applies int filters (operator order EQ NE LT LE GT GE is inferred) and lists the external attrs; 0x1005, 0x1203 and 0x1204 answer empty.
- **Events.** UpdatedRoomDataInternal (0x320e) and UpdatedRoomMemberDataInternal (0x320d) are pushed to the other members when the owner or a member changes the data (with `NP_MATCHING_ROOM_EVENTS=1`). MemberLeft, Kickedout and RoomDestroyed need element 0x62 (not decoded): they are logged, not pushed.
- **Unproven on a console.** The first request of each of 0x1005, 0x1203, 0x1204, 0x1207, 0x1208, 0x3204, 0x3206, 0x3207 and 0x3211 is logged at WARN with its redacted hex ("statically decoded command, first sight").
- A 0x32xx room command on a connection that never sent a session-MAC'd request is now resolved through the member's room key (it logged "unknown title" before).
- Fixed the stale `TestHandshake` event-header assertion (v0.2.17 moved the room handle to +12).

## v0.2.20

Hosting with a real room on the console (prds#145; research matching2-protocol §34). v0.2.16's own member id 1 sat in slot 0, the firmware's owner pointer, so its create done failed with 0x800223ff (vsh 0x29a378 -> 0x29ec18) and the console never had a room; that is why 0x1202 never followed on v0.2.16. v0.2.17/v0.2.18 (id 0x10) let the create complete, and the firmware handed Terraria a member list with owner = NULL, because no member carried the owner flag (vsh 0x29e864). Terraria dereferences it unchecked (EBOOT 0x126bc0/0x126be4) and froze. Member ids are `no << 4` again, and the room owner's member element carries flag attr 0x80000000 in the create reply, in the join reply's member list (core `is_owner`, else the lowest member number) and in events. The golden test now pins those bytes.

## v0.2.19

Hosting first: the 0x3200 create reply and 0x3201 join reply are byte-identical to v0.2.16 again (prds#145). v0.2.18 still froze Terraria on a real PS3 right after the room was created (2026-11-10 21:11Z); the host's own member id 16 (v0.2.17's `no << 4`) was the last create-reply difference from v0.2.16. Member ids on the wire are the plain member number again everywhere (member element, 0x3201 own id, room message sender, MemberJoined +14). The kind-4 event header keeps the room handle 1 at +12, so MemberJoined events should now reach the room; the slot-id part of the v0.2.17 event fix is not active. `wire.TestCreateJoinReplyGolden` pins both replies to the v0.2.16 bytes.

## v0.2.18

Room data carries the room id at head[16..24] again. v0.2.17 zeroed those bytes and a real PS3 froze in Terraria right after the 0x3200 create reply (2026-11-10 21:05Z); with the id there the same console hosted on every earlier version. The event header and member id changes of v0.2.17 stay.

## v0.2.17

Room events and member ids as the firmware reads them (prds#145, vsh 4.93 decode in protocol doc §33). The kind-4 header carried the 64-bit room id at +8; the firmware instead finds the room by the u16 at +12 (compared with head[0..2] of the room data it got in its 0x3200/0x3201 reply, the server id 1) and takes the subject member id from the u16 at +14, so every MemberJoined and room message event was dropped with 0x80022335 (room not found) before reaching the game. Events now carry the room handle 1 at +12 and the member id at +14. Member ids are slot ids (`slot << 4`): the firmware indexes members by id>>4 and slot 0 aliases the room's own-member pointer, so ids 1, 2, 3 all fell in slot 0 (0x800223ff, slot taken). The room data head no longer writes the room id into the 16-byte slot map (2 bits per slot); the map is zero.

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
