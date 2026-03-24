#  NetScan Studio

**Scan smarter. Analyze deeper.**

A comprehensive, intelligent network scanning platform with multi-engine support and professional reporting.

---

##  Overview

NetScan Studio is a GUI-based network scanner that combines multiple scanning engines (Socket, Nmap, Scapy) into a single intuitive application. It features intelligent tool recommendation, dynamic configuration, and professional reporting capabilities.

**Version:** 1.0.0  
**Author:** Mr.Sima  
**License:** MIT

---

##  Features

### Core Scanning
- **Multi-Engine Support:** Socket (fast), Nmap (detailed), Scapy (advanced)
- **3-Tier Scan Modes:** Quick, Standard, Deep
- **Intelligent Tool Recommendation:** Auto-selects best tool per mode
- **Dynamic Configuration:** Context-aware UI options

### Advanced Capabilities
- **Nmap Integration:**
  - Scan types (-sT, -sS, -sA, etc.)
  - Host discovery options (-Pn, -sn)
  - Service detection (-sV)
  - Script engine with categories
  
- **Command Intelligence:** 
  - Live command preview
  - Bidirectional UI ↔ Command sync
  - Manual command editing

- **Professional Reporting:**
  - Scan configuration summary
  - Structured results
  - Executive insights
  - Export formats: TXT, JSON, CSV

### Insights Engine
- Intelligent risk assessment
- Security recommendations
- Service-specific analysis

### Cross-Platform
- Automatic OS detection (Windows/Linux/macOS)
- Platform-specific dependency management
- Guided installation process

### Update Management
- GitHub-connected version checking
- Auto-notification system
- One-click update access

---

## 📦 Installation

### Prerequisites
- Python 3.7+
- PyQt5
- Nmap (for full functionality)

### Quick Start

1. **Clone/Extract Project**
```bash
cd netscan_studio
```

2. **Install Python Dependencies**
```bash
pip install -r requirements.txt
```

3. **Install Nmap** (if not installed)

**Windows:**
- Download from https://nmap.org/download.html
- Run installer and add to PATH

**Linux (Ubuntu/Debian):**
```bash
sudo apt install nmap
```

**macOS:**
```bash
brew install nmap
```

4. **Run Application**
```bash
python main.py
```

---

##  Usage Guide

### Basic Scanning

1. **Enter Target**
   - IP address (e.g., 192.168.1.1)
   - Hostname (e.g., example.com)

2. **Select Scan Mode**
   - **Quick:** Fast socket-based scan (~30 seconds)
   - **Standard:** Detailed Nmap scan (~2-5 minutes)
   - **Deep:** Multi-engine analysis (~5-10 minutes)

3. **Choose Tool** (Auto-selected based on mode)
   - Socket (fast checks)
   - Nmap (detailed scanning)
   - Scapy (packet analysis)

4. **Advanced Options** (Optional)
   - Scan type (-sS, -sT, etc.)
   - Service detection
   - Nmap scripts
   - Port ranges

5. **Start Scan & View Results**
   - Real-time progress
   - Open ports table
   - Insights & recommendations
   - Professional report

### Exporting Results

Export scan results in multiple formats:
- **TXT:** Human-readable report
- **JSON:** Machine-readable structure
- **CSV:** Spreadsheet-compatible

---

## 🏗️ Architecture

```
UI Layer (PyQt5 GUI)
        ↓
Controller Layer (ScannerManager)
        ↓
Scanner Manager (Pipeline Engine)
        ↓
┌────────────┬────────────┬────────────┐
│   Socket   │   Nmap     │   Scapy    │
│   Engine   │   Engine   │   Engine   │
└────────────┴────────────┴────────────┘
        ↓
Processing (Insights + Parser)
        ↓
Output (Reports + UI)
```

---

## 📁 Project Structure

```
netscan_studio/
├── main.py                 # Entry point
├── ui/
│   ├── main_window.py     # PyQt5 GUI
│   └── components/        # UI components
├── core/
│   ├── scanner_manager.py # Main orchestrator
│   └── config_manager.py  # Configuration
├── engines/
│   ├── socket_engine.py   # Fast scanning
│   ├── nmap_engine.py     # Full scanning
│   └── scapy_engine.py    # Advanced analysis
├── command/
│   └── command_builder.py # Command generation
├── processing/
│   └── insights_engine.py # Analysis
├── reports/
│   └── report_generator.py# Reporting
├── setup/
│   ├── dependency_manager.py
│   └── platform_detector.py
├── update/
│   └── update_manager.py  # GitHub updates
├── utils/
│   ├── version.py
│   ├── logger.py
│   └── helpers.py
└── requirements.txt
```

---

## ⚙️ Configuration

Configuration is stored in platform-specific locations:

- **Windows:** `%APPDATA%\Local\NetScan Studio\config.json`
- **Linux:** `~/.config/netscan-studio/config.json`
- **macOS:** `~/Library/Application Support/NetScan Studio/config.json`

Customize:
- Theme (dark/light)
- Scanning defaults
- Nmap arguments
- Auto-update settings

---

##  Tutorials

### Running a Quick Scan
1. Enter IP: `192.168.1.1`
2. Mode: Quick
3. Click "Start Scan"
4. Results appear in ~30 seconds

### Advanced Nmap Scan
1. Enter target
2. Mode: Standard
3. Enable "Service Detection" & "OS Detection"
4. Add Nmap scripts (Vulnerability category)
5. Customize scan type: SYN Scan
6. Click "Start Scan"

### Deep Analysis
1. Enter target
2. Mode: Deep
3. Tool: Scapy (or auto-selected)
4. Options: TTL analysis, Firewall detection
5. Run full pipeline

---

##  License

MIT License - Feel free to use and modify

---

##  Troubleshooting

### "Nmap not found"
- **Solution:** Install Nmap from official website and add to PATH
- **Verify:** Run `nmap --version` in terminal

### "Failed to install packages"
- **Solution:** Run with admin privileges or use virtual environment
```bash
python -m venv venv
# Activate venv, then install
```

### "Connection refused"
- **Solution:** Ensure target is reachable
- **Check:** Ping target first

---

##  Future Enhancements

- Network graph visualization
- AI-based scan recommendations
- Scan history dashboard
- Integration with ReconVault
- Custom scan profiles
- Batch scanning

---

**Happy Scanning! 🔍**
