# np-matching2

The PS3 Matching2 agent (the server a console's `matching.np.community.playstation.net` entry points at), an adapter over the
neutral [matchmaking core](https://github.com/openpak/matchmaking): the agent keeps the firmware's wire and login sessions; rooms,
members and search live in the core.

* Plain TCP `:3480` (0x1001, then the session's requests) and TLS `:8443` (the 0x1002 login).
* **No-SNI front.** The firmware's TLS hello has no SNI, so it cannot be routed by name. Traefik's no-SNI router points here; `front`
  tells a firmware hello (no extensions) from everything else and sends the rest down the old Diablo II Resurrected path (TLS 1.2
  terminated here, plaintext to `NP_NOSNI_TARGET`).
* Titles: Terraria (NPWR04270_00) and Minecraft: PlayStation 3 Edition (NPWR05636_00), each with its own compat group and server status. Room attributes (internal/external bins, searchable ints) and each member's 0x59 live in the matchmaking core, never in this process.
* `client/` is a headless Matching2 client that speaks the console side of the wire.
* HTTP `:8538`: `/healthz`, `DELETE /internal/accounts/{account}/data` (Bearer `ACCOUNT_ERASE_KEY`).

Config in [example.env](example.env). Deploy sample in [deploy/](deploy/). AGPL-3.0-only.
