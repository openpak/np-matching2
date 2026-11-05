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
