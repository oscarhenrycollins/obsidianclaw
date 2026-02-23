# ObsidianClaw

**Chat with your [OpenClaw](https://openclaw.ai) AI agent directly from Obsidian.**

Your vault becomes the workspace. Your AI lives in the sidebar. No browser tabs, no separate apps — just your notes and your AI, side by side.

## Features

- **Chat sidebar** — Talk to your AI agent from any Obsidian tab
- **Streaming responses** — See replies appear in real-time as they're generated
- **Markdown rendering** — Code blocks, lists, links, and formatting rendered natively
- **Message history** — Full conversation history synced from the gateway
- **"Ask about this note"** — Send any note as context with one command
- **Auto-reconnect** — Handles disconnections gracefully with exponential backoff
- **Device authentication** — Ed25519 keypair for secure scope authorization
- **Tool call visibility** — See exactly what your agent does: files read/written, commands run, pages fetched — with clickable links
- **Cross-device sync** — Tool calls and chat history persist across devices via Obsidian Sync
- **Dark/light theme** — Follows your Obsidian theme automatically

## Requirements

- [OpenClaw](https://openclaw.ai) gateway running on a machine with [Tailscale](https://tailscale.com)
- [Tailscale](https://tailscale.com/download) installed on all devices (creates a secure private network)
- Gateway auth token (from `~/.openclaw/openclaw.json`)

## Installation

The plugin is pending approval in the Obsidian Community Plugin store ([PR #10465](https://github.com/obsidianmd/obsidian-releases/pull/10465)). In the meantime, install via **BRAT**:

1. Install [BRAT](https://github.com/TfTHacker/obsidian42-brat) from Obsidian Community Plugins
2. Open BRAT settings → **Add Beta Plugin**
3. Enter: `oscarhenrycollins/obsidianclaw`
4. BRAT installs the latest release automatically and keeps it updated

This works on **both desktop and mobile** — install BRAT on each device, add the same repo, and you're set.

## Setup

### 1. Configure the gateway for Tailscale

On the machine running OpenClaw:

```bash
# Bind gateway to Tailscale interface
openclaw config set gateway.bind tailnet

# Restart to apply
openclaw gateway restart

# Get your Tailscale IP
tailscale ip -4
# → 100.x.x.x
```

### 2. Connect the plugin

Open Obsidian → the setup wizard runs automatically:

- **Gateway URL:** `ws://100.x.x.x:18789` (your Tailscale IP from step 1)
- **Auth Token:** from `~/.openclaw/openclaw.json` → `gateway.auth.token`
- Click **Test connection**

### 3. Approve device pairing

Each new device generates a unique Ed25519 keypair and requests pairing. Approve it from the OpenClaw dashboard (`http://100.x.x.x:18789/`), or via CLI:

```bash
openclaw devices list
openclaw devices approve <requestId>
```

After approval, the device is remembered permanently. Pair once per device — it syncs across reinstalls via Obsidian Sync.

## Security Architecture

ObsidianClaw uses **three layers of security**:

### Layer 1: Network Encryption (Tailscale/WireGuard)

All traffic between devices travels over Tailscale's WireGuard mesh VPN. Even though the WebSocket uses `ws://` (not `wss://`), the underlying network traffic is encrypted end-to-end. Only your authenticated Tailscale devices can see each other.

### Layer 2: Gateway Token Authentication

Every connection requires a valid auth token that matches the gateway's configured `gateway.auth.token`. This prevents unauthorized access even within your Tailnet.

### Layer 3: Device Fingerprinting (Ed25519)

Each ObsidianClaw installation generates a unique Ed25519 keypair:

- **Private key** stays in your Obsidian vault's plugin data (never transmitted)
- **Public key** is registered with the gateway during pairing
- Every connection is signed with a timestamp + nonce to prevent replay attacks
- Device pairing requires explicit approval — no device can self-authorize

This is the same security model used by OpenClaw's official Control UI.

### What's stored locally

| Data | Location | Purpose |
|------|----------|---------|
| Auth token | Plugin data (`data.json`) | Gateway authentication |
| Ed25519 keypair | Plugin data (`data.json`) | Device identity |
| Gateway URL | Plugin data (`data.json`) | Connection target |

Your token and keys never leave your machine except to authenticate with your own gateway.

## Commands

| Command | Description |
|---------|-------------|
| `OpenClaw: Toggle chat sidebar` | Open/close the chat panel |
| `OpenClaw: Ask about current note` | Send the active note as context |
| `OpenClaw: Reconnect to gateway` | Re-establish the connection |
| `OpenClaw: Run setup wizard` | Re-run the onboarding flow |

## Troubleshooting

### "Could not connect"

1. **Is OpenClaw running?** Check with `openclaw gateway status`
2. **Correct URL?** Should be `ws://<tailscale-ip>:18789`
3. **Token correct?** Copy from `~/.openclaw/openclaw.json` → `gateway.auth.token`
4. **Tailscale connected?** Run `tailscale status` on both machines
5. **On mobile?** Make sure Tailscale VPN is active on your phone

### "Pairing required"

First connection from a new device needs approval:

```bash
openclaw devices list          # Find the pending request
openclaw devices approve <id>  # Approve it
```

### "Missing scope: operator.write"

The device isn't paired or was paired without proper scopes. Remove and re-pair:

```bash
openclaw devices list
openclaw devices revoke --device <deviceId> --role operator
```

Then reconnect from Obsidian — a new pairing request will be created.

### Switching between devices

ObsidianClaw works on both desktop and mobile. When switching between devices:

1. **Force-quit Obsidian** on the device you're switching to (swipe up on iOS, Cmd+Q on Mac)
2. **Reopen Obsidian** — it picks up synced data and loads the latest chat history
3. Everything works perfectly from that point — full history, tool calls, and streaming

This is because tool call events are only sent to the device that initiated the request. The other device syncs the results via Obsidian Sync's `data.json`. A quick restart ensures it loads the latest state.

### Messages not appearing

If you send a message but don't see a response streaming:
- The plugin shares the `main` session with other channels (Telegram, etc.)
- Responses should stream in real-time via the chat sidebar
- Try disconnecting and reconnecting via Settings → OpenClaw → Reconnect

## Configuration

Access settings via Obsidian Settings → OpenClaw:

| Setting | Default | Description |
|---------|---------|-------------|
| Gateway URL | `ws://100.x.x.x:18789` | Tailscale WebSocket URL to your gateway |
| Auth Token | (empty) | Gateway authentication token |
| Session Key | `main` | Which session to chat in |

## Building from Source

```bash
git clone https://github.com/oscarhenrycollins/obsidianclaw.git
cd obsidianclaw
npm install
npm run build
```

Copy `main.js`, `manifest.json`, and `styles.css` to your vault's `.obsidian/plugins/openclaw/` folder.

## Links

- [ObsidianClaw](https://obsidianclaw.ai) — Official site
- [OpenClaw](https://openclaw.ai) — The AI agent framework
- [Bot Setup Guide](https://botsetupguide.com) — Full setup walkthrough
- [Humanity Labs](https://humanitylabs.org) — Creators of ObsidianClaw

## License

MIT
