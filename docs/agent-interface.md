# Agent interface: FreedomDesk for AI agents

Two front doors to the same operations:

* `freedomdesk agent <cmd>`: one-shot commands, JSON on stdout (errors are JSON too, exit code 1).
* `freedomdesk mcp`: a stdio [MCP](https://modelcontextprotocol.io) server (JSON-RPC 2.0, protocol revision 2025-06-18) for Claude Code, Claude Desktop and other MCP clients.

Every call is a short session: connect (Noise, pinned host key) -> act -> disconnect. The host sees an ordinary viewer named `agent@<this machine>`.

## Status

"Verified" means I ran it in this repo's tests on loopback (see "Tests"). Nothing below has been run against a real host machine.

| Feature | State |
|---|---|
| `machines` (known_hosts, no network) | Works, unit tested, run via the real binary |
| `screenshot` (PNG file / base64 / MCP image) | Works against a loopback stand-in host using the real Noise handshake and real H.264 encoder/decoder. Not run against `host.rs` or a real X display |
| `click`, `type`, `key` | Wire events verified on the stand-in host (positions, buttons, double click, modifier order). Whether the real host's XTest injection reacts correctly is unverified here, as is Wayland (the host has no input backend there) |
| `clipboard set` | Negotiation and message verified on the stand-in; real host clipboard not exercised |
| `clipboard get` | Limited by the protocol: returns the next clipboard **change** after connecting, cannot read the current clipboard. Errors clearly if not negotiated |
| `status` | Works on the stand-in: host name, screen/video size, clipboard caps, round trip time. **Lock/login screen: "unknown"**, and "input accepted" (view-only host?): "unknown". The protocol carries neither; use a screenshot |
| MCP server (initialize, tools/list, tools/call, ping, errors) | Unit tested; smoke-tested over real stdio with the built binary. Not tested with Claude Code / Claude Desktop / Grok Bot clients yet: the config snippets below follow their documented formats but are unverified |
| Allowlist, `allow_input`, `allow_clipboard`, rate limit, kill switch, audit | Unit tested (policy and MCP flow); allowlist before `Hello` verified on loopback; kill switch and `agent.toml` revocation during a slow consent wait verified on loopback for click, key, type and clipboard set |
| CLI policy mode (`FREEDOMDESK_AGENT_MCP_ONLY` / `cli_requires_policy`) | Config parsing, the shared rate-limit file and the authorise path are unit tested; not run end to end through the CLI binary |
| macOS / Windows hosts | Not applicable yet: depends on the host backends |

Known limits: no scroll/drag/mouse-move tools yet; screenshots are sent at the host's video size (default <= 1920x1080), no downscaling or zoom; each call is a new session, so unless the agent's fingerprint is authorised on the host (`freedomdesk authorize`) the human at the host gets a consent prompt for **every** call.

## Setup

1. On the host (the machine to control), run `freedomdesk host` as usual. Add `--clipboard` if you want clipboard tools.
2. On the agent's machine, learn the agent's identity: `freedomdesk id`. On the host: `freedomdesk authorize <that fingerprint> --label agent` (unattended) or leave it out and the host user clicks Allow each call.
3. Pin the host once, deliberately, with its fingerprint (read it from `freedomdesk id` on the host, ideally over a second channel):

   ```sh
   freedomdesk agent status the20th:47801 --expect-fingerprint ABCD-EFGH-IJKL-MNOP-QRST-UVWX
   ```
   An agent never trusts a new host implicitly. Without the pin and without `--expect-fingerprint`, calls fail before any network traffic. MCP tools have no fingerprint parameter at all: the human pins hosts.
4. For MCP, create `agent.toml` in the config dir (`~/.config/freedomdesk/`, or `--config-dir`, or `$FREEDOMDESK_CONFIG_DIR`):

   ```toml
   # Hosts the agent may reach (fingerprints from `freedomdesk agent machines`).
   allow_hosts = ["ABCD-EFGH-IJKL-MNOP-QRST-UVWX"]
   # Read-only is the default. Uncomment to let the agent click/type/press keys:
   # allow_input = true
   # "none" (default) | "read" | "write" (write also needs allow_input = true)
   # allow_clipboard = "none"
   # rate_limit_per_minute = 30
   # Make `freedomdesk agent ...` obey this file too (see Security model):
   # cli_requires_policy = true
   ```
   Only this TOML subset is understood (booleans, integers, strings, string arrays, comments). An invalid file makes every call fail rather than fall back to something looser. The file is re-read on each call, so edits apply immediately.

### Claude Code

```sh
claude mcp add freedomdesk -- freedomdesk mcp
# a non-default config dir:
claude mcp add freedomdesk -- freedomdesk --config-dir ~/.config/freedomdesk mcp
```

or in the project's `.mcp.json`:

```json
{
  "mcpServers": {
    "freedomdesk": {
      "command": "freedomdesk",
      "args": ["mcp"]
    }
  }
}
```

### Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "freedomdesk": {
      "command": "/usr/local/bin/freedomdesk",
      "args": ["mcp"]
    }
  }
}
```

### Generic MCP client / Grok Bot style

Any client that spawns a stdio server and speaks newline-delimited JSON-RPC:

```json
{
  "servers": {
    "freedomdesk": {
      "transport": "stdio",
      "command": "freedomdesk",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

Key names differ between clients (`mcpServers` vs `servers`, `type: "stdio"`); only `command` and `args` matter. Manual test:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
              '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | freedomdesk mcp
```

## Tools

| Tool | Hints | Needs |
|---|---|---|
| `freedomdesk_machines` | read-only | nothing |
| `freedomdesk_screenshot {host}` | read-only; returns an `image` | host in `allow_hosts` |
| `freedomdesk_status {host}` | read-only | host in `allow_hosts` |
| `freedomdesk_click {host,x,y,button?,double?}` | destructive | `allow_input` |
| `freedomdesk_type {host,text}` | destructive | `allow_input` |
| `freedomdesk_key {host,combo}` | destructive | `allow_input` |
| `freedomdesk_clipboard_get {host,wait_seconds?}` | read-only | `allow_clipboard` = read or write; host `--clipboard` |
| `freedomdesk_clipboard_set {host,text}` | destructive | `allow_clipboard = "write"` and `allow_input`; host `--clipboard` |

Coordinates are pixels of the screenshot image (the first decoded frame of the same call is used for scaling). Key combos: modifiers `ctrl alt shift super` joined with `+`, then one key: a character, `F1`-`F12`, `Enter Escape Tab Backspace Delete Insert Home End PageUp PageDown Up Down Left Right Space Print`. Examples: `ctrl+c`, `alt+F4`, `ctrl+alt+Delete`. Tool errors come back as `isError: true` results; malformed arguments and unknown tools are JSON-RPC `-32602`.

Annotations are hints for clients, not enforcement; enforcement is the policy below.

## CLI examples

```sh
freedomdesk agent machines
freedomdesk agent screenshot the20th --out /tmp/screen.png      # JSON: path, width, height, ...
freedomdesk agent screenshot the20th                             # JSON includes png_base64
freedomdesk agent click the20th 640 360 --button right --double
freedomdesk agent type the20th "hello"$'\n'
freedomdesk agent key the20th ctrl+alt+Delete
freedomdesk agent clipboard set the20th "text"        # or `-` to read stdin
freedomdesk agent clipboard get the20th --wait 20
freedomdesk agent status the20th
```
Success: `{"ok":true,...}`. Failure: `{"ok":false,"error":"..."}` and exit code 1. `--timeout N` bounds the wait for the first frame.

By default the CLI is the human's own tool: it is **not** subject to `agent.toml` (whoever can run it can already run `freedomdesk view`). It honours the kill switch for input and it audits. With `FREEDOMDESK_AGENT_MCP_ONLY=1` or `cli_requires_policy = true` it obeys `agent.toml` like the MCP server (see Security model).

## Security model

* **Identity and pinning.** Same Noise identity and `known_hosts` as the viewer. Hosts must be pinned (or given with `--expect-fingerprint`, which pins on match); no trust-on-first-use from agents; a changed key is refused.
* **Allowlist (MCP).** Only hosts whose fingerprint is in `allow_hosts` can be reached, none by default. Checked before any network traffic for pinned hosts, and again after the Noise handshake and before `Hello` is sent. For a host that is not allowed, the host still sees a TCP connection and our public key (the handshake), but no `Hello`, no viewer name and no consent prompt.
* **Read-only by default (MCP).** Input and clipboard tools return an error unless enabled in `agent.toml`.
* **`allow_input = true` is, in effect, arbitrary code execution on the host.** Keyboard and mouse control lets the agent open a terminal (`super`, `ctrl+alt+t`), run commands, install software, or read files, with the privileges of the logged-in user (and of a root session if one is unlocked). Only enable it for a model and a host you would hand a keyboard to.
* **Input is re-checked after connecting.** The host's consent wait can last minutes. After the connection is up and before every click, key press, typed character and clipboard write, the kill switch and (for MCP, and for the CLI in policy mode) `agent.toml` are read again, so disabling input during the wait takes effect.
* **Kill switch.** If `FREEDOMDESK_AGENT_KILL` is set in the environment (not empty, not `0`/`false`) or a file named `FREEDOMDESK_AGENT_KILL` exists in the config dir (a file that cannot be stat'ed, e.g. for permissions, counts as present: it fails closed), click/type/key/clipboard-set are refused at once, and a `type` in progress stops between characters. The file is the live switch (`touch ~/.config/freedomdesk/FREEDOMDESK_AGENT_KILL`); the environment variable is fixed when the MCP server process starts.
* **Rate limit.** `rate_limit_per_minute` (default 30) over all MCP tool calls.
* **Audit.** One line per call in `<config>/audit.log`: time, source (`mcp`/`cli`), action, host, outcome, and sizes or positions. Never typed text or clipboard contents; a lone printable key press (including shifted or uppercase, e.g. `P`, `shift+a`, `Ж`) is not logged at all. Failures log only a coarse class (`not_pinned`, `not_allowed`, `invalid_input`, `connection`, ...), never the error text, because error text can echo what the caller sent. Control characters are stripped from logged values. Denied and rate-limited calls are logged too. Appending stops at 10 MiB with one final marker line; rotate or remove the file to resume.
* **Limits.** MCP messages over 1 MiB are rejected and skipped; screenshots over 32 Mpixel are refused (8K fits).
* **Host consent still applies.** The host user is prompted (or the agent's fingerprint is on the host's `authorized_viewers`). The host's own `--view-only` and clipboard flags win over anything configured here.
* **Passwords.** Typing into a lock or login screen needs `allow_input`, and the tool descriptions tell the model that passwords must be entered by the human. This is guidance, not a guarantee: a model with `allow_input` can type anything. Do not enable input on machines where you would not trust the model with a keyboard.
* **Prompt injection.** Screenshots are untrusted input: text on a remote screen can try to instruct the model. The server's `instructions` say so; the real defences are a human in the loop on the client side and a narrow allowlist.
* **The MCP policy only holds if the agent cannot bypass the MCP server.** `agent.toml` and the kill-switch file live in a directory the agent's own user can write. An agent with a shell or file-write access can edit `agent.toml`, run `freedomdesk agent ...` directly (the CLI ignores `agent.toml` by default), or use `freedomdesk view` with your identity key. Therefore:
  * Run the MCP server for **shell-less** clients (no Bash tool, no file-write tool, or running in a sandbox that cannot reach the config dir).
  * Set `FREEDOMDESK_AGENT_MCP_ONLY=1` in the environment (or `cli_requires_policy = true` in `agent.toml`): then the CLI also obeys `agent.toml` (same authorisation, a rate limit shared across processes in `<config>/agent.rate`, host allowlist) and refuses what the policy refuses, and an invalid `agent.toml` makes it refuse everything. This only helps against a model that cannot unset the variable or edit the file; for a client with a shell it is a speed bump, not a boundary.
  * For a hard boundary, put the config dir and identity key in a location the agent's user cannot write (a separate account that runs the MCP server), which is outside what this release sets up.
* **Not covered.** The MCP stdio transport has no authentication of its own, and local malware running as you can read your identity key regardless of this feature.

## Tests

`cargo test --workspace --locked`: `agent.rs` (key combos, PNG round trip, coordinate mapping, audit redaction, pin/allowlist precheck, kill-switch file), `mcp.rs` (initialize, list, call, ping, unknown method, parse/invalid request, invalid params, read-only default, opt-in, kill switch, rate limit, malformed config fails closed, audit contents), and `agent_loopback.rs`: a loopback integration test against a stand-in host in the test (real Noise, real H.264, real capability negotiation). The repo has no fake-capture seam in `host.rs`, so a test through the real host (capture + XTest) needs an X server (e.g. Xvfb) and is not included.
