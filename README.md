# NetScan Studio

NetScan Studio is a desktop network scanning application built with Python and PyQt5. It combines Socket, Nmap, and Scapy based workflows behind one GUI, with live progress, command preview, configurable scan modes, and exportable reports.

## Preview

![NetScan Studio UI](https://github.com/user-attachments/assets/f98bebcc-7fd7-4ac7-8e45-972e4fbd69a7)


## Highlights

- Works across Windows, Linux, Kali Linux, and macOS.
- Supports `Quick`, `Standard`, and `Deep` scan modes.
- Uses Socket, Nmap, Scapy, or Hybrid execution depending on the selected mode/tool.
- Keeps the command preview aligned with the actual scan configuration.
- Shows live scan progress, status text, elapsed time, and state-aware progress colors.
- Exports reports in `TXT`, `JSON`, and `CSV`.
- Stores config, logs, and generated reports in platform-appropriate user directories instead of cluttering the repo.

## Platform Compatibility

NetScan Studio is designed to run on:

- Windows 10/11
- Linux distributions such as Ubuntu, Debian, Kali Linux, Fedora, Arch
- macOS

Some scan capabilities depend on system privileges:

- `TCP Connect` scans work without elevated privileges on all supported platforms.
- Raw packet based scans such as `SYN`, `ACK`, `FIN`, `UDP`, and Scapy analysis typically require administrator/root privileges.
- If a raw Nmap scan type is selected without the needed privileges, NetScan Studio safely falls back to `TCP Connect` and shows a compatibility note in the UI.
- Scapy analysis requires elevated privileges and compatible packet capture support on the host OS.

## Requirements

- Python `3.9+`
- `PyQt5`
- `Nmap` installed for Nmap and Hybrid scanning
- Administrator/root privileges for raw packet scan types and Scapy features

## Installation

1. Clone or extract the project.
2. Open a terminal in the project directory:

```bash
cd netscan_studio
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Install Nmap for your platform.

### Windows

1. Download Nmap from `https://nmap.org/download.html`.
2. During installation, allow Npcap installation if prompted.
3. Make sure `nmap.exe` is available in `PATH`.

Common location:

```text
C:\Program Files\Nmap\nmap.exe
```

### Ubuntu / Debian / Kali Linux

```bash
sudo apt update
sudo apt install nmap
```

### Fedora

```bash
sudo dnf install nmap
```

### Arch Linux

```bash
sudo pacman -S nmap
```

### macOS

With Homebrew:

```bash
brew install nmap
```

## Running The App

```bash
python main.py
```

## Using NetScan Studio

1. Enter a target such as an IP address or hostname.
2. Choose a scan mode:
   Quick: fast checks, lightweight.
   Standard: balanced Nmap-based scan.
   Deep: broader analysis with advanced features.
3. Review or change the recommended tool.
4. Adjust scan options such as ports, service detection, or scan type.
5. Start the scan and watch the live status section update.
6. Export the results if needed.

## Scan Engines

### Socket

- Fast and lightweight
- Good for quick checks and common port validation
- No external Nmap dependency required

### Nmap

- Best for detailed host and service scanning
- Supports scan type, service detection, OS detection, host discovery, and scripts
- Used in Standard mode by default

### Scapy

- Used for advanced packet-level analysis
- Best suited for elevated environments
- Used in Deep mode when available and appropriate

### Hybrid

- Combines fast checks and deeper follow-up scanning
- Useful when you want quick visibility plus richer details

## Progress And Status

The status section now reports:

- Live percentage updates while scanning
- Intermediate progress counts
- Elapsed time during the scan
- Color-coded progress states

Progress color meaning:

- Blue: active scan
- Green: completed
- Orange: stopped
- Red: failed

## Updates

Update checks are manual. The app does not check GitHub automatically on startup anymore.

To check for updates, use:

```text
Help > Check for Updates
```

The updater now expects one uploaded release `.zip` package for each GitHub release.

Recommended release asset naming:

- `netscan-studio-universal.zip`

Selection behavior:

- If exactly one uploaded `.zip` asset exists in the release, the app uses it.
- If multiple uploaded `.zip` assets exist, the app prefers one whose name includes `universal`, `portable`, or `generic`.
- If no uploaded release zip exists, the app falls back to the GitHub source archive.
- If the current app directory looks like a development checkout, the updater stages the package but does not overwrite the working tree automatically.

## Release Workflow

Keep `tests/` in the repository for development, but do not ship it inside the end-user release zip.

Build the first release package with:

```bash
python scripts/build_release.py
```

This creates:

- `dist/netscan-studio-universal/`
- `dist/netscan-studio-universal.zip`

The universal release zip includes the application source and excludes development-only content such as:

- `tests/`
- `.git/`
- `dist/`
- `logs/`
- `__pycache__/`
- local virtual environments

Suggested first GitHub release flow:

1. Commit your repo changes.
2. Push the branch to GitHub.
3. Create tag `v1.0.0`.
4. Create a GitHub release for `v1.0.0`.
5. Upload `dist/netscan-studio-universal.zip` as the release asset.

## Storage Locations

NetScan Studio uses per-user platform directories for runtime data.

### Configuration

- Windows: `%LOCALAPPDATA%\NetScan Studio\config.json`
- Linux/Kali: `~/.config/netscan-studio/config.json`
- macOS: `~/Library/Application Support/NetScan Studio/config.json`

### Logs

- Windows: `%LOCALAPPDATA%\NetScan Studio\logs\`
- Linux/Kali: `${XDG_STATE_HOME:-~/.local/state}/netscan-studio/logs/`
- macOS: `~/Library/Application Support/NetScan Studio/logs/`

### Generated Reports

- Windows: `%LOCALAPPDATA%\NetScan Studio\reports\`
- Linux/Kali: `~/.config/netscan-studio/reports/`
- macOS: `~/Library/Application Support/NetScan Studio/reports/`

## Project Structure

```text
netscan_studio/
|-- main.py
|-- command/
|-- core/
|-- engines/
|-- processing/
|-- reports/
|-- setup/
|-- scripts/
|-- tests/
|-- ui/
|-- update/
|-- utils/
|-- LICENSE
|-- README.md
`-- requirements.txt
```

## Troubleshooting

### Nmap not found

- Confirm Nmap is installed.
- Verify it runs in a terminal with:

```bash
nmap --version
```

- On Windows, check that `C:\Program Files\Nmap\` is installed and available to the app.

### Raw scans fall back to TCP Connect

- This is expected when the app is not running with administrator/root privileges.
- Run the app with elevated privileges if you explicitly need raw packet scan types.

### Scapy analysis fails to start

- Run the app as administrator/root.
- Make sure packet capture support is available on the OS.

### DNS or update check issues

- Manual update checks require outbound internet access to GitHub.

## Development Notes

- `tests/test_scan_logic.py` contains regression coverage for scan mode and preview behavior.
- Generated cache and log folders should not be committed.
- Runtime data is intentionally stored outside the repository when possible.

## License

MIT License. See `LICENSE`.
