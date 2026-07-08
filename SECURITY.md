# Security Model

> This document covers **OcO** (the bighill fork of ObsidianClaw), an unofficial fork of [`oscarhenrycollins/obsidianclaw`](https://github.com/oscarhenrycollins/obsidianclaw). The security model below is inherited from upstream; report issues found in this fork to the fork maintainer (see [Reporting Vulnerabilities](#reporting-vulnerabilities)).

OcO connects your Obsidian vault to an OpenClaw gateway. This document explains how the connection is secured and what data flows where.

## Threat Model

OcO is designed for **personal use** — your devices, your gateway, your data. The security model assumes:

- You control both the Obsidian client and the OpenClaw gateway
- Network access is restricted to localhost by default (127.0.0.1)
- Cross-device access should use a private tunnel (e.g., WireGuard, Tailscale) rather than exposing the port

## Three-Layer Security

### 1. Network Layer: Localhost Binding

By default, the gateway binds to **loopback only** (`127.0.0.1`). Traffic never leaves your machine:

- **No external ports exposed**
- **No network traversal needed**
- **`ws://` is fine over localhost** because the data never crosses a network boundary

For cross-device setups, put a private tunnel (e.g., WireGuard, Tailscale, SSH port-forward) in front of the gateway rather than binding to a public interface.

### 2. Application Layer: Token Authentication

The gateway requires a shared secret (token) for every WebSocket connection:

- Token is configured in `~/.openclaw/openclaw.json` on the gateway
- Same token must be provided by the plugin
- Tokens are compared using constant-time comparison to prevent timing attacks
- Rate limiting protects against brute-force attempts

### 3. Device Layer: Ed25519 Fingerprinting

Each OcO installation has a unique cryptographic identity:

- **Ed25519 keypair** generated via WebCrypto API on first run
- **Device ID** = SHA-256 hash of the public key
- **Every connection is signed** with: device ID, client ID, role, scopes, timestamp, token, and server nonce
- **Replay protection** via server-issued nonce and timestamp validation (±10 minute window)
- **Pairing required** — new devices must be explicitly approved by the gateway operator

This prevents:
- Stolen tokens from being used on unauthorized devices
- Replay attacks using captured handshakes
- Scope escalation without re-pairing

## Data Flow

```
OcO Plugin  ←→  localhost / private tunnel  ←→  OpenClaw Gateway
     ↓                                              ↓
  Plugin Data                                   Agent Session
  (data.json)                                   (transcript)
  - Auth token                                  - Chat history
  - Ed25519 keys                                - Tool outputs
  - Gateway URL                                 - Agent state
```

### What stays local to Obsidian:
- Plugin settings
- Vault contents (only sent when you explicitly use "Ask about this note")

### What is stored inside the vault (`.obsidian/plugins/openclaw/data.json`):
- **Auth token**
- **Ed25519 private key** and public key
- Gateway URL

Because these values live in the vault's plugin data directory, they are included in **Obsidian Sync**, manual vault backups, and any other sync/copy mechanism that covers the vault. They are **not encrypted at rest** by the plugin. Keep this in mind when enabling sync or sharing vault backups.

### What's sent to the gateway:
- Auth token (for authentication)
- Public key + signature (for device verification)
- Chat messages you type
- Note content (only when you use the "Ask about this note" command or @-mention)

### What the gateway does NOT receive:
- Your full vault contents
- Your Obsidian settings
- Your private key
- Any data you don't explicitly send

## Recommendations

1. **Keep the gateway bound to loopback** — avoid `0.0.0.0` unless you know what you're doing
2. **Use a strong, unique token** — generate with `openssl rand -hex 24`
3. **Review paired devices** periodically — `openclaw devices list`
4. **Revoke unused devices** — `openclaw devices revoke --device <id> --role operator`
5. **Keep OpenClaw updated** — security patches are applied regularly

## Reporting Vulnerabilities

If you find a security issue, please report it responsibly:
- **This fork:** email alex@bighill.org, or open a private advisory at <https://github.com/bighill/oco-obsidian-plugin/security/advisories>
- **Upstream issues** (present in the original plugin): report to the original authors at security@humanitylabs.org
- Do not open a public GitHub issue for security vulnerabilities