# FreedomDesk

**Open-source, free forever. A TeamViewer replacement you own.**

FreedomDesk is a lightweight remote desktop built in Rust. It aims to match or beat TeamViewer, AnyDesk, RustDesk, Parsec, Chrome Remote Desktop, Splashtop, NoMachine and MeshCentral — without subscriptions, telemetry, or a vendor middleman.

Part of the [FreedomOffice](https://github.com/mar0der/FreedomOffice) family: Petar’s quest to replace every paid tool he uses with one he built and gave to the world.

## Why

TeamViewer and friends are commercial, expensive, and often hostile to personal/free use. FreedomDesk is:

- **Free for everyone** — personal and commercial, no seat limits
- **Self-hostable** — your rendezvous/relay, or Tailscale-only with no public server at all
- **Security-first** — end-to-end encryption, key pinning, 2FA, consent prompts, audit log
- **Lightweight** — Rust, small binary, hardware encode when available
- **Cross-platform** — Linux (Wayland + X11), macOS, Windows; mobile viewers later

## Status

Early planning / P0 MVP. See [SPEC.md](SPEC.md) for the full feature set, architecture, threat model and milestones. See [STATUS.md](STATUS.md) for current work.

**First real use case:** remote support for family in Bulgaria over Tailscale.

## Docs

| File | What |
|------|------|
| [SPEC.md](SPEC.md) | Full product + architecture spec |
| [STATUS.md](STATUS.md) | Living status for the PO agent |
| [CLAUDE.md](CLAUDE.md) | Standing rules for the Claude Code PO |
| [LICENSE](LICENSE) | AGPL-3.0 |

## Licence

GNU Affero General Public License v3.0 (AGPL-3.0). Same spirit as RustDesk: keep the community version free forever, including the self-hosted server. See SPEC.md for why AGPL was chosen over MIT/Apache.

## Contributing

Not open for external PRs yet — the PO on the21th is building the P0 MVP. Issues and ideas welcome once the first Linux host↔viewer loop works.

## Author

[mar0der](https://github.com/mar0der) (Petar Petkov)
