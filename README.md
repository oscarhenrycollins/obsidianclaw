# OcO — Obsidian Plugin

OpenClaw tab for Obsidian

Your vault becomes the workspace. Your AI lives in a document tab. No browser tabs, no separate apps — just your notes and your AI, side by side.

> **🍴 Forked from [ObsidianClaw](https://github.com/oscarhenrycollins/obsidianclaw)** by [Humanity Labs](https://humanitylabs.org). This is **OcO** — a personal fork that grew its own identity. Not affiliated with or endorsed by the original authors. Maintained by [@bighill](https://github.com/bighill). Want the official plugin? Search **OpenClaw** under **Settings → Community plugins → Browse**.

## Features

- **Chat tab** — Talk to your AI agent from a dedicated Obsidian tab
- **Streaming responses** — See replies appear in real-time
- **Markdown rendering** — Code blocks, lists, links rendered natively
- **@-mention vault files** — Type `@` to attach any note as context
- **Drag-and-drop + paste images** — Attach screenshots and images inline
- **Tool call visibility** — See files read/written, commands run, pages fetched
- **Multi-session tabs** — Multiple conversations side by side
- **Cross-device sync** — Chat history and tool calls persist via Obsidian Sync
- **Dark/light theme** — Follows your Obsidian theme automatically

## Prerequisites

Before you install the plugin, you'll need:

- [OpenClaw](https://openclaw.ai) gateway running on this machine (or somewhere reachable)
- Gateway bound to loopback: `openclaw config set gateway.bind loopback && openclaw gateway restart`
- **A small patch to OpenClaw** so it accepts Obsidian's `app://obsidian.md` origin — see below.

### One-time OpenClaw patch (required)

Obsidian's renderer loads from `app://obsidian.md`. Per the URL spec, custom schemes have a "null" origin, so vanilla OpenClaw rejects the websocket handshake from Obsidian. This plugin needs a one-line fallback added to OpenClaw's origin check.

Apply the patch manually on your **gateway machine**:

1. Download and review [`scripts/patch-openclaw.sh`](scripts/patch-openclaw.sh):
   ```bash
   curl -fsSL https://raw.githubusercontent.com/bighill/oco-obsidian-plugin/main/scripts/patch-openclaw.sh -o /tmp/patch-openclaw.sh
   # Review the file before running it as root
   cat /tmp/patch-openclaw.sh
   ```
2. Run it with `sudo`:
   ```bash
   sudo bash /tmp/patch-openclaw.sh
   ```

The script is idempotent, backs up the file it edits, and restarts the gateway.

> ⚠️ **Re-run this after every `openclaw update`** — gateway upgrades wipe the patch. We're tracking an upstream fix so this requirement can be removed.

> 🔒 Never pipe a remote script directly into `sudo bash`. Always download, inspect, and run locally.

## Install

This plugin is **not** published to the Obsidian community store — install it with BRAT or build it yourself.

### BRAT (recommended)

1. Install **BRAT**
2. **BRAT → Add Beta Plugin**
3. Use repo: `bighill/oco-obsidian-plugin`

### Manual

See [Building from Source](#building-from-source) below.

## Connect

After install, a welcome notice prompts you to configure the connection:

1. **Open Settings → OcO → Connection**
2. **Gateway URL:**
   - Default: `ws://127.0.0.1:18789`
   - Custom: `ws://<your-host>:18789`
3. **Auth Token:** from `~/.openclaw/openclaw.json` → `gateway.auth.token`
4. Click **Reconnect**
5. **Approve the device** from the OpenClaw dashboard or CLI:
   ```bash
   openclaw devices list
   openclaw devices approve <requestId>
   ```

Done. The device is remembered permanently.

> If connection fails, first confirm gateway health:
> `openclaw status`

## Commands

| Command | Description |
|---------|-------------|
| `OcO: Open chat in new tab` | Open a new chat tab |
| `OcO: Ask about current note` | Send the active note as context |
| `OcO: Reconnect to gateway` | Re-establish the connection |

## Troubleshooting

**"Could not connect" / "Disconnected"** — Most common cause: the gateway stopped. Run `openclaw gateway restart`. If that fixes it, the gateway had crashed. Also check: Is the URL correct (`ws://127.0.0.1:18789`)? Is the token right?

**Connection rejected right after an OpenClaw update** — `openclaw update` wipes the origin-check patch. Re-run the [one-time OpenClaw patch](#one-time-openclaw-patch-required) on your gateway machine.

**"Pairing required"** — Every new device needs a one-time approval. Run `openclaw devices list` and `openclaw devices approve <requestId>` on your gateway machine, or approve from the dashboard.

**Switching devices** — Force-quit Obsidian and reopen. It picks up synced data from the other device.

## Security

Three layers: **localhost binding** keeps the port internal, **gateway token** authenticates connections, and **Ed25519 device keys** fingerprint each device. Your keys never leave your machine.

## Building from Source

```bash
git clone https://github.com/bighill/oco-obsidian-plugin.git
cd oco-obsidian-plugin
npm install
npm run build
```

Copy `main.js`, `manifest.json`, and `styles.css` to `.obsidian/plugins/openclaw/`.

## Links

- [This repo](https://github.com/bighill/oco-obsidian-plugin) — what you're looking at
- [OpenClaw](https://openclaw.ai) — The AI agent framework
- [Bot Setup Guide](https://botsetupguide.com) — Full setup walkthrough

## Credits

Original work © [Humanity Labs](https://humanitylabs.org), distributed under the MIT License.

- Upstream repo: [`oscarhenrycollins/obsidianclaw`](https://github.com/oscarhenrycollins/obsidianclaw)
- Official site: [obsidianclaw.ai](https://obsidianclaw.ai)

This fork keeps the upstream MIT license and exists only to track personal changes on top of that work. All credit for the original plugin goes to the Humanity Labs team.

## License

MIT — see upstream [Credits](#credits). Original copyright retained; fork modifications by [@bighill](https://github.com/bighill).
