# Protocol: np-matching2

Layouts, framing, MACs and the handshake are in `wire/wire.go` (header comment) and the private research note
`research/ps3/matching2-protocol.md` sections 3 to 13. Summary of what the agent does:

| Command | Connection | Key | Reply |
| --- | --- | --- | --- |
| `0x1001` | plain | first 16 bytes of the title passphrase | element `0x1d` `{u16 0001, u8 00}` (meaning unknown) |
| `0x1002` | TLS | none | `0x14` session id, `0x22` session key (20 bytes), `0x23` and `0x5d` tokens, `0x74` lifetime (600 s) |
| `0x1003` | plain | session key | `0x5d` new token; extends the session |
| `0x1008` | plain | session key | world list: one world (id 1) with the core's room and member counts |

A request after login carries no identity; the agent finds the login whose key verifies the MAC. Every request is logged with its
command, title and (when known) account; element values are never logged. Unknown commands are logged as `unimplemented` with the
element ids and size.

## Room handling and the unified Terraria service (card #145)

`np-matching2` keeps only the wire and login sessions; rooms go to the matchmaking core through `agent.Core`. To become the PS3
adapter of `openpak/terraria` later, room calls will follow the plan in `prds/repos/terraria-unified-plan.md`: sessions of kind `room` under the neutral
title key `terraria`, searchable attributes `compat` (`old-gen-1.2.4` for PS3) and `console` (`ps3`), the console's own room struct kept in the session `data`
blob and each player's in the member `data`. Nothing about a room is stored here; the adapter only maps the firmware's ids (room id, member id, server/world id) to
core session ids and member numbers per connection (rebuilt from `GetSession`/`SearchSessions` after a reconnect).

Status of the room flow (see the private research note, sections 16 and 17): the firmware's CreateJoinRoom is the multi-step 0x1209 -> 0x2001 -> 0x3200 -> 0x1202;
only the first step has been observed and it is answered minimally.
