# TorChat - P2P Encrypted Messenger over Tor

Peer-to-peer encrypted chat application using Tor onion services. No central server, direct 1-to-1 communication only.

## Features

- **P2P Architecture**: Direct peer-to-peer, no central server
- **Tor Network**: All communication through Tor onion services
- **End-to-End Encryption**: X25519 + ChaCha20-Poly1305
- **Persistent Identity**: Automatic keypair generation on first run
- **Local Storage**: SQLite database for contacts and messages
- **GUI**: Fyne-based cross-platform interface

## Tech Stack

- Go 1.22+
- Fyne (GUI)
- Tor via bine library
- SQLite database
- X25519 key exchange
- ChaCha20-Poly1305 encryption

## Quick Start

### Prerequisites

- Go 1.22+
- C compiler (for SQLite)
  - Windows: MinGW or MSVC
  - Linux: `sudo apt install build-essential`
  - macOS: `xcode-select --install`
- **Tor executable**:
  - **Option 1**: Download [Tor Browser](https://www.torproject.org/download/), extract `tor.exe` from `Browser/TorBrowser/Tor/` and place in `tor-chat-go/tor/` directory
  - **Option 2**: Install Tor system-wide and add to PATH

### Run

```bash
cd tor-chat-go
go mod download
go run ./cmd/torchat
```

### Build

```bash
# Linux/macOS
go build -o torchat ./cmd/torchat

# Windows
go build -o torchat.exe ./cmd/torchat
```

## Usage

1. **First Launch**: Wait for Tor bootstrap (~30-60 seconds)
2. **Get Your Identity**: Click "My Identity" to view onion address & public key
3. **Add Contact**: Click "Add Contact", enter their onion address + public key
4. **Verify Fingerprint**: Always verify fingerprints via second channel
5. **Chat**: Select contact, type message, send (both must be online)

## Data Directory

- Windows: `%APPDATA%\TorChat`
- Linux/macOS: `~/.torchat`

Contains:
- `identity/identity.json` - Your private key (KEEP SECRET!)
- `tor/` - Tor data and hidden service
- `chat.db` - SQLite database

## Security Notes

- **Verify fingerprints** with contacts via voice/in-person
- **Backup your identity** securely
- **Both users must be online** to exchange messages
- No forward secrecy (static keys)
- Messages stored locally unencrypted (database only)

## License

MIT License
