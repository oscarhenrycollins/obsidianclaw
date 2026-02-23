# ObsidianClaw

**Chat with your [OpenClaw](https://openclaw.ai) AI agent directly from Obsidian.**

Your vault becomes the workspace. Your AI lives in the sidebar. No browser tabs, no separate apps — just your notes and your AI, side by side.

## Features

- **Chat sidebar** — Talk to your AI agent from any Obsidian tab
- **Streaming responses** — See replies appear in real-time
- **Markdown rendering** — Code blocks, lists, links rendered natively
- **Tool call visibility** — See files read/written, commands run, pages fetched
- **Cross-device sync** — Chat history and tool calls persist via Obsidian Sync
- **"Ask about this note"** — Send any note as context with one command
- **Dark/light theme** — Follows your Obsidian theme automatically

## Install

> **Beta:** Pending approval in the Obsidian Community Plugin store ([PR #10465](https://github.com/obsidianmd/obsidian-releases/pull/10465)). Install via BRAT for now.

1. In Obsidian, go to **Settings → Community Plugins → Browse**
2. Search **BRAT** → Install → Enable
3. Go to **Settings → BRAT → Add Beta Plugin**
4. Enter: `oscarhenrycollins/obsidianclaw`

That's it. BRAT installs the plugin and keeps it updated. Works on desktop and mobile.

## Connect

The setup wizard opens automatically after install:

1. **Gateway URL:** `ws://<your-tailscale-ip>:18789`
2. **Auth Token:** from `~/.openclaw/openclaw.json` → `gateway.auth.token`
3. Click **Test connection**
4. **Approve the device** from the OpenClaw dashboard or CLI:
   ```bash
   openclaw devices list
   openclaw devices approve <requestId>
   ```

Done. The device is remembered permanently.

### Prerequisites

- [OpenClaw](https://openclaw.ai) gateway running somewhere (Mac, Linux, Raspberry Pi)
- [Tailscale](https://tailscale.com/download) on all your devices
- Gateway bound to Tailscale: `openclaw config set gateway.bind tailnet && openclaw gateway restart`

## Commands

| Command | Description |
|---------|-------------|
| `OpenClaw: Toggle chat sidebar` | Open/close the chat panel |
| `OpenClaw: Ask about current note` | Send the active note as context |
| `OpenClaw: Reconnect to gateway` | Re-establish the connection |
| `OpenClaw: Run setup wizard` | Re-run the onboarding flow |

## Troubleshooting

**"Could not connect"** — Is Tailscale running on both devices? Is the gateway URL correct (`ws://<tailscale-ip>:18789`)? Is the token right?

**"Pairing required"** — Every new device needs a one-time approval. Run `openclaw devices list` and `openclaw devices approve <requestId>` on your gateway machine, or approve from the dashboard.

**Switching devices** — Force-quit Obsidian and reopen. It picks up synced data from the other device.

## Security

Three layers: **Tailscale** encrypts all traffic (WireGuard VPN), **gateway token** authenticates connections, and **Ed25519 device keys** fingerprint each device. Your keys never leave your machine.

## Building from Source

```bash
git clone https://github.com/oscarhenrycollins/obsidianclaw.git
cd obsidianclaw
npm install
npm run build
```

Copy `main.js`, `manifest.json`, and `styles.css` to `.obsidian/plugins/openclaw/`.

## Links

- [ObsidianClaw](https://obsidianclaw.ai) — Official site
- [OpenClaw](https://openclaw.ai) — The AI agent framework
- [Bot Setup Guide](https://botsetupguide.com) — Full setup walkthrough
- [Humanity Labs](https://humanitylabs.org) — Built by Humanity Labs

## License

MIT
