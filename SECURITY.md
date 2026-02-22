# Security Model

ObsidianClaw connects your Obsidian vault to an OpenClaw gateway. This document explains how the connection is secured and what data flows where.

## Threat Model

ObsidianClaw is designed for **personal use** — your devices, your gateway, your data. The security model assumes:

- You control both the Obsidian client and the OpenClaw gateway
- Network access is restricted to your devices (via Tailscale or localhost)
- You trust the machines in your Tailnet

## Three-Layer Security

### 1. Network Layer: Tailscale WireGuard

For cross-device setups, all traffic flows over [Tailscale](https://tailscale.com), which uses WireGuard encryption:

- **End-to-end encrypted** between your devices
- **No ports exposed** to the public internet
- **Identity-based access** — only your authenticated devices can connect
- The `ws://` protocol over Tailscale is effectively as secure as `wss://` because WireGuard encrypts at the network layer

For same-machine setups, traffic stays on localhost (127.0.0.1) and never touches the network.

### 2. Application Layer: Token Authentication

The gateway requires a shared secret (token) for every WebSocket connection:

- Token is configured in `~/.openclaw/openclaw.json` on the gateway
- Same token must be provided by the plugin
- Tokens are compared using constant-time comparison to prevent timing attacks
- Rate limiting protects against brute-force attempts

### 3. Device Layer: Ed25519 Fingerprinting

Each ObsidianClaw installation has a unique cryptographic identity:

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
Obsidian Plugin  ←→  [Tailscale WireGuard]  ←→  OpenClaw Gateway
     ↓                                              ↓
  Plugin Data                                   Agent Session
  (data.json)                                   (transcript)
  - Auth token                                  - Chat history
  - Ed25519 keys                                - Tool outputs
  - Gateway URL                                 - Agent state
```

### What stays local to Obsidian:
- Your private key (never transmitted)
- Plugin settings
- Vault contents (only sent when you explicitly use "Ask about this note")

### What's sent to the gateway:
- Auth token (for authentication)
- Public key + signature (for device verification)
- Chat messages you type
- Note content (only when you use the "Ask about this note" command)

### What the gateway does NOT receive:
- Your full vault contents
- Your Obsidian settings
- Your private key
- Any data you don't explicitly send

## Recommendations

1. **Use Tailscale** for cross-device setups — never expose your gateway to the public internet
2. **Use a strong, unique token** — generate with `openssl rand -hex 24`
3. **Review paired devices** periodically — `openclaw devices list`
4. **Revoke unused devices** — `openclaw devices revoke --device <id> --role operator`
5. **Keep OpenClaw updated** — security patches are applied regularly

## Reporting Vulnerabilities

If you find a security issue, please report it responsibly:
- Email: security@humanitylabs.org
- Do not open a public GitHub issue for security vulnerabilities
