# ObsidianClaw

**Official OpenClaw plugin for Obsidian** — chat with your AI agent from inside your vault.

Your vault is the agent's workspace. Everything your AI writes appears instantly in Obsidian. Everything you write, the AI can see. ObsidianClaw adds a chat sidebar so you never need to leave Obsidian.

## Features

- **Chat sidebar** — talk to your OpenClaw agent from the right sidebar
- **Streaming responses** — see tokens appear in real-time as the AI thinks
- **Markdown rendering** — assistant messages render with full Obsidian formatting
- **"Ask about this note"** — command palette action sends the current note as context
- **Auto-reconnect** — reconnects automatically if the connection drops
- **Connection status** — green/red dot shows gateway status at a glance
- **Native theme** — matches your Obsidian theme automatically

## Requirements

- [OpenClaw](https://openclaw.ai) running on your machine (or reachable via Tailscale)
- Obsidian 1.0.0+

## Installation

### Manual (recommended for now)

1. Download the latest release (`main.js`, `manifest.json`, `styles.css`)
2. Create folder: `<vault>/.obsidian/plugins/obsidianclaw/`
3. Copy the three files into it
4. Restart Obsidian
5. Enable "OpenClaw" in Settings → Community Plugins

### From source

```bash
git clone https://github.com/humanitylabs-org/obsidianclaw.git
cd obsidianclaw
npm install
npm run build
```

Copy `main.js`, `manifest.json`, and `styles.css` to your vault's plugin folder.

## Setup

1. Open Settings → OpenClaw
2. Set **Gateway URL** to your OpenClaw WebSocket address:
   - Local: `ws://127.0.0.1:18789` (default)
   - Remote via Tailscale: `ws://100.x.x.x:18789`
3. Set **Auth Token** if your gateway requires authentication
4. Click **Reconnect**
5. Click the chat icon (💬) in the left ribbon to open the sidebar

## Commands

| Command | Description |
|---------|-------------|
| **Toggle chat sidebar** | Open/focus the chat panel |
| **Ask about current note** | Send the active note as context |
| **Reconnect to gateway** | Re-establish the WebSocket connection |

## How it works

ObsidianClaw connects to your OpenClaw gateway via WebSocket — the same protocol used by the OpenClaw Control UI and macOS app. It sends and receives messages through the `chat.send`, `chat.history`, and `chat.abort` methods.

Because your Obsidian vault **is** the OpenClaw workspace, the agent can read and write files directly. When it creates or edits a note, you see the change instantly in Obsidian. When you edit a note, the agent can see your changes through its file tools.

## Privacy

- All communication is between Obsidian and your own OpenClaw gateway
- No data is sent to Humanity Labs or any third party
- The LLM provider configured in OpenClaw processes your messages (same as Telegram/any other channel)

## Development

```bash
npm install
npm run dev    # watch mode
npm run build  # production build
```

## License

MIT — [Humanity Labs](https://humanitylabs.org)
