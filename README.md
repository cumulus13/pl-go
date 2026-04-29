# pl-go

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go" alt="Go Version">
  <img src="https://img.shields.io/github/v/release/cumulus13/pl-go?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/actions/workflow/status/cumulus13/pl-go/release.yml?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/github/license/cumulus13/pl-go?style=flat-square" alt="License">
</p>

**pl-go** is a fast, colorful, cross-platform process inspector with full network connection detail, parent/child process trees, kill, restart, watch mode, JSON output, and zero WMI usage on Windows.

```
001. chrome.exe [17416] 98.64 MB LIC-X\LICFACE (running)
    START_TIME : 26/04/28 23:30:15:140
    NAME   : chrome.exe
    PID    : 17416
    EXE    : C:\Program Files\Google\Chrome Dev\Application\chrome.exe
    MEM    : 98.64 MB
    CMD    : chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService ...
    CPU    : 0.2
    USER   : LIC-X\LICFACE
    CWD    : C:\Program Files\Google\Chrome Dev\Application
    ├─ 🐬 [local=192.168.1.10:19447] [remote=74.125.24.188:5228] (fd:-1, type:TCP, family:AF_INET) | STATUS: ESTABLISHED
    ├─ 🐬 [local=192.168.1.10:25036] [remote=18.97.36.76:443]    (fd:-1, type:TCP, family:AF_INET) | STATUS: ESTABLISHED
    └─ 🧱 [local=0.0.0.0:5353]       [remote=0.0.0.0:0]          (fd:-1, type:UDP, family:AF_INET) | STATUS: ──
```

---

## Features

- **Full process detail** — name, PID, exe path, full command line, working directory, user, memory (RSS), CPU%, start time with millisecond precision
- **Network connections** — TCP/UDP IPv4 and IPv6, local/remote address + port, connection status (ESTABLISHED, LISTEN, etc.), socket type and family; no WMI on Windows
- **Parent/child trees** — visualise process hierarchies with configurable depth
- **Kill & restart** — terminate or restart by name, PID, port, or last-started
- **Watch mode** — live auto-refresh like `top`
- **JSON output** — pipe-friendly structured output
- **Field selector** — show only the fields you care about
- **Filters** — by name, PID, cmdline, username, port, minimum memory
- **Table mode** — compact tabular layout
- **Color + emoji** — 24-bit colour, emoji status icons, identical to the Python original
- **No-color mode** — for scripts and log files
- **Cross-platform** — Windows (no WMI), Linux (`/proc`), macOS

---

## Platform internals

| Concern | Windows | Linux / macOS |
|---|---|---|
| Process enumeration | `psapi.EnumProcesses` | `gopsutil` → `/proc` |
| CMD / CWD | `ReadProcessMemory` on PEB | `/proc/pid/cmdline`, `/proc/pid/cwd` |
| Network connections | `iphlpapi.GetExtendedTcpTable` / `GetExtendedUdpTable` | `/proc/net/tcp`, `/proc/net/udp` |
| Terminal width | `kernel32.GetConsoleScreenBufferInfo` | `unix.IoctlGetWinsize` |
| **WMI used?** | **Never** | N/A |

The PEB `ReadProcessMemory` approach recovers full `CMD` and `CWD` for sandboxed processes (Chrome renderers, Edge WebView, etc.) that block the standard `NtQueryInformationProcess` call gopsutil uses.

---

## Installation

### Pre-built binary (recommended)

Download the latest release for your platform from the [Releases](https://github.com/cumulus13/pl-go/releases) page:

| Platform | File |
|---|---|
| Windows 64-bit | `pl-windows-amd64.exe` |
| Windows 32-bit | `pl-windows-386.exe` |
| Linux 64-bit | `pl-linux-amd64` |
| Linux ARM64 | `pl-linux-arm64` |
| macOS Intel | `pl-darwin-amd64` |
| macOS Apple Silicon | `pl-darwin-arm64` |

### Build from source

```bash
git clone https://github.com/cumulus13/pl-go.git
cd pl-go
go mod tidy
go build -o pl .          # Linux / macOS
go build -o pl.exe .      # Windows
```

**Requirements:** Go 1.22+

---

## Usage

```
pl [global options] command [command options]
```

### Flags

| Flag | Short | Description |
|---|---|---|
| `--list` | `-l` | List processes |
| `--all` | `-a` | Show all processes (no filter) |
| `--filter NAME` | `-f` | Filter by process name, PID, or cmdline |
| `--pid PID` | `-i` | Show a specific process by PID |
| `--port PORT` | `-p` | Filter by port number (local or remote) |
| `--user USERNAME` | `-u` | Filter by username |
| `--min-mem MB` | | Only show processes using ≥ N MB RAM |
| `--networks` | `-N` | Show network connections for each process |
| `--network` | `-n` | Show only processes that have network connections |
| `--table` | `-t` | Display in table format |
| `--last N` | `-z` | Show last N started processes |
| `--desc` | | Sort newest first |
| `--asc` | | Sort oldest first (default) |
| `--sort-mem` | `-m` | Sort by memory usage (RSS) |
| `--show-parent` | `-P` | Show parent process tree |
| `--show-child` | `-C` | Show child process tree |
| `--depth N` | `-d` | Limit parent/child tree depth (0 = unlimited) |
| `--no-tree` | | Suppress parent/child tree lines |
| `--kill` | `-k` | Terminate matching process |
| `--force` | | Force kill all matches (use with `-k -p`) |
| `--restart` | `-r` | Restart matching process |
| `--watch N` | `-w` | Auto-refresh every N seconds |
| `--json` | `-j` | Output as JSON |
| `--fields LIST` | | Show only selected fields (comma-separated) |
| `--no-filter-cmd` | `--nfc` | Disable filtering by command line |
| `--no-color` | | Disable color output |

**Available fields:** `name`, `pid`, `exe`, `mem`, `cmd`, `cpu`, `user`, `cwd`, `net`, `start_time`

---

## Examples

```bash
# List all processes
pl -l -a

# Filter by name (matches name, PID, or cmdline)
pl -f chrome

# Filter by name only (ignore cmdline)
pl -f chrome --nfc

# Show specific PID
pl -i 1234

# Show processes using port 8080
pl -p 8080

# Show only processes with network connections
pl -n -l

# Show network connections for filtered processes
pl -f nginx -N

# Last 10 processes, sorted newest first
pl -l -z 10 --desc

# Sort all by memory usage descending
pl -l -a -m --desc

# Filter by user
pl -l -u root

# Show processes using >= 100 MB RAM
pl -l --min-mem 100

# Table format
pl -l -a -t

# Table format, selected columns only
pl -l -a -t --fields name,pid,mem,cpu

# Show parent tree
pl -f python -P

# Show child tree with max depth 2
pl -f nginx -C -d 2

# Kill process by name
pl -f myapp -k

# Kill process on port 3000
pl -p 3000 -k

# Force kill all processes on port 80
pl -p 80 -k --force

# Kill the most recently started process
pl -z 1 -k --desc

# Restart process by name
pl -f myapp -r

# Restart process on port 8000
pl -p 8000 -r

# Watch mode — refresh every 3 seconds
pl -f chrome -w 3

# Watch mode — all processes, network only, every 2 seconds
pl -n -l -w 2

# JSON output
pl -f nginx -j

# JSON output, piped to jq
pl -l -a -j | jq '.[] | {pid, name, mem_mb}'

# No color (for scripts / log files)
pl -l -a --no-color

# Show only name, pid, mem, net fields
pl -f chrome -N --fields name,pid,mem,net
```

---

## JSON output schema

```json
[
  {
    "pid": 1234,
    "name": "nginx",
    "exe": "/usr/sbin/nginx",
    "cmd": "nginx: master process /usr/sbin/nginx",
    "cwd": "/",
    "user": "root",
    "mem_mb": 5.23,
    "cpu_percent": 0.1,
    "running": true,
    "start_time": "24/03/15 08:22:11:045",
    "connections": [
      {
        "fd": "5",
        "family": "AF_INET",
        "type": "TCP",
        "laddr": "0.0.0.0",
        "lport": 80,
        "raddr": "0.0.0.0",
        "rport": 0,
        "status": "LISTEN"
      }
    ]
  }
]
```

---

## Network connection icons

| Icon | Meaning |
|---|---|
| 🐬 | ESTABLISHED connection |
| 💥 | LISTEN socket |
| 🧱 | UDP / no remote (NONE) |
| 🩲 | Other TCP state (TIME_WAIT, CLOSE_WAIT, etc.) |

---

## Project structure

```
pl-go/
├── main.go                # Core logic, CLI, rendering (platform-agnostic)
├── net_linux.go           # Network via /proc/net/tcp* (Linux/macOS)
├── net_windows.go         # Network via iphlpapi GetExtendedTcpTable (Windows, no WMI)
├── procs_unix.go          # Process list via gopsutil (Linux/macOS)
├── procs_windows.go       # Process list via psapi.EnumProcesses (Windows, no WMI)
├── prochelper_unix.go     # fmtStartTimeMS, getCmdlineCwd passthrough (Linux/macOS)
├── prochelper_windows.go  # PEB ReadProcessMemory for CMD/CWD, millisecond timestamps
├── termsize_unix.go       # Terminal width via unix.IoctlGetWinsize
└── termsize_windows.go    # Terminal width via kernel32.GetConsoleScreenBufferInfo
```

Build tags (`//go:build windows` / `//go:build !windows`) ensure only the correct file is compiled per platform. The `go build` toolchain selects automatically.

---

## Comparison with Python original

| Feature | Python `pl11.py` | `pl-go` |
|---|---|---|
| Startup time | ~120 ms | ~5 ms |
| Memory usage | ~25 MB | ~4 MB |
| Binary | requires Python + pip | single static `.exe` / ELF |
| CMD for sandboxed procs | ✅ psutil | ✅ PEB ReadProcessMemory |
| CWD for sandboxed procs | ✅ psutil | ✅ PEB → fallback dirname(exe) |
| Network connections | ✅ full detail | ✅ full detail (no WMI) |
| Port number accuracy | ✅ | ✅ (fixed winPort endianness) |
| IPv6 connections | ✅ | ✅ |
| Start time precision | milliseconds | milliseconds |
| 24-bit color | ✅ rich | ✅ gookit/color |
| Watch mode | ❌ | ✅ |
| JSON output | ❌ | ✅ |
| Field selector | ❌ | ✅ |
| Username filter | ❌ | ✅ |
| Min-memory filter | ❌ | ✅ |
| WMI on Windows | ❌ never | ❌ never |

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/shirou/gopsutil/v3` | Cross-platform process info (name, exe, mem, cpu, ppid) |
| `github.com/gookit/color` | 24-bit terminal color and styled output |
| `github.com/urfave/cli/v2` | CLI flag parsing |
| `golang.org/x/sys` | Unix ioctl (terminal size) and Windows syscall wrappers |

---

## Building for all platforms

```bash
# Linux
GOOS=linux   GOARCH=amd64  go build -ldflags="-s -w" -o dist/pl-linux-amd64 .
GOOS=linux   GOARCH=arm64  go build -ldflags="-s -w" -o dist/pl-linux-arm64 .

# macOS
GOOS=darwin  GOARCH=amd64  go build -ldflags="-s -w" -o dist/pl-darwin-amd64 .
GOOS=darwin  GOARCH=arm64  go build -ldflags="-s -w" -o dist/pl-darwin-arm64 .

# Windows
GOOS=windows GOARCH=amd64  go build -ldflags="-s -w" -o dist/pl-windows-amd64.exe .
GOOS=windows GOARCH=386    go build -ldflags="-s -w" -o dist/pl-windows-386.exe .
```

The `-ldflags="-s -w"` strips debug symbols, reducing binary size by ~30%.

---

## License

[MIT](LICENSE)

---

## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)