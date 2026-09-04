# Installation Guide 📦

Quick-start guides for Windows and Linux.

## Windows: Standalone Executable

**No Python required.** Just download and run.

### Option 1: Direct Download (Recommended)

1. Download `blackout.exe` from [GitHub Releases](https://github.com/kiacoder/blackout-kit/releases/tag/v1.1.1)
2. Run it:
   ```bash
   .\blackout.exe
   ```
3. First run shows a welcome screen → Choose **Terminal CLI** or **Windows App**

### Option 2: Chocolatey

```powershell
choco install blackout-kit
blackout
```

### Option 3: Direct Path (No PATH setup needed)

```powershell
cd Downloads
.\blackout.exe
```

---

## Linux: Native Runtime

**No Python required for daemon.** CLI tools (optional) need Python 3.10+.

### Debian / Ubuntu

```bash
# Download the binary
wget https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout-engine-linux-amd64
chmod +x blackout-engine-linux-amd64

# Run daemon in background
./blackout-engine-linux-amd64 daemon &

# (Optional) Install Python CLI tools
pip install blackout-kit-cli
blackout setup
```

### Fedora / RHEL / CentOS

```bash
wget https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout-engine-linux-amd64
chmod +x blackout-engine-linux-amd64
./blackout-engine-linux-amd64 daemon &
```

### Arch Linux

Via AUR (when available):
```bash
yay -S blackout-kit
blackout daemon &
```

### Docker / Container

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl
RUN curl -Lo /usr/local/bin/blackout \
  https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout-engine-linux-amd64
RUN chmod +x /usr/local/bin/blackout
CMD ["blackout", "daemon"]
```

---

## Verification

### Windows

```powershell
blackout --version
blackout doctor --local-only
```

### Linux

```bash
./blackout-engine-linux-amd64 --version
./blackout-engine-linux-amd64 doctor --local-only
```

---

## Platform-Specific Setup

### Windows: Enable Proxy Auto-Config (Optional)

If you want Windows to automatically route traffic through Blackout Kit:

1. Open **Settings** → **Network & Internet** → **Proxy**
2. Set **Manual proxy setup** → **Use a proxy server**
3. Address: `127.0.0.1`, Port: `8080` (default Blackout Kit port)

### Linux: System-Wide Proxy (Optional)

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

Or edit `~/.profile` or `~/.bashrc`:
```bash
echo 'export http_proxy=http://127.0.0.1:8080' >> ~/.bashrc
echo 'export https_proxy=http://127.0.0.1:8080' >> ~/.bashrc
```

---

## Quick Start: First Connection

### Windows

```powershell
blackout setup           # Interactive checklist
blackout connect         # Start connection
blackout status          # Check status
blackout stop            # Stop connection
```

### Linux

```bash
./blackout-engine-linux-amd64 daemon &        # Start daemon in background
sleep 1
./blackout-engine-linux-amd64 setup           # Interactive checklist
./blackout-engine-linux-amd64 connect         # Start connection
./blackout-engine-linux-amd64 status          # Check status
./blackout-engine-linux-amd64 stop            # Stop connection
```

---

## Upgrade

### Windows (Chocolatey)

```powershell
choco upgrade blackout-kit
```

### Windows (Manual)

1. Download new `blackout.exe` from releases
2. Stop any running connection: `blackout stop`
3. Replace the old executable with the new one
4. Run the new version: `.\blackout.exe`

### Linux

```bash
wget https://github.com/kiacoder/blackout-kit/releases/download/v1.1.1/blackout-engine-linux-amd64
chmod +x blackout-engine-linux-amd64
# Kill old process
pkill -f "blackout-engine-linux-amd64"
# Start new one
./blackout-engine-linux-amd64 daemon &
```

---

## Uninstall

### Windows (Chocolatey)

```powershell
choco uninstall blackout-kit
```

### Windows (Manual)

1. Delete `blackout.exe`
2. Delete settings folder: `%APPDATA%\blackout-kit\`

### Linux

```bash
pkill -f "blackout-engine-linux-amd64"
rm ./blackout-engine-linux-amd64
rm -rf ~/.blackout-kit/
```

---

## Troubleshooting

### "Port 8080 already in use"

Change the port in settings:
- **Windows:** `blackout settings` → Proxy Port
- **Linux:** Edit `~/.blackout-kit/settings.json`, change `local_proxy_port`

### "Engine binary not found"

Download missing engine:
- **Windows:** `blackout setup` → "Install missing runtime"
- **Linux:** Ensure you have the correct `blackout-engine-linux-amd64` for your architecture

### "Connection timeout"

Check connectivity and upstream config:
```bash
blackout doctor --local-only      # Windows
blackout doctor --local-only      # Linux (with Python CLI)
```

---

## Next Steps

1. ✅ Install and verify with `doctor`
2. 📋 Run `setup` for guided configuration
3. 🔐 Add a proxy config or VPN profile
4. 🚀 Connect and test with `status`
5. 📚 See [SECURITY.md](SECURITY.md) for security details

---

## Support

- **Issues:** https://github.com/kiacoder/blackout-kit/issues
- **Security:** See [SECURITY.md](SECURITY.md)
- **Docs:** https://github.com/kiacoder/blackout-kit/blob/main/README.md
