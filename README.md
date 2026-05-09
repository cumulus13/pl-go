# pl-go

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go" alt="Go Version">
  <img src="https://img.shields.io/github/v/release/cumulus13/pl-go?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/actions/workflow/status/cumulus13/pl-go/release.yml?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/github/license/cumulus13/pl-go?style=flat-square" alt="License">
</p>

**pl-go** is a fast, colorful, cross-platform process inspector — a Go port of [pl11.py](https://github.com/cumulus13/processlist) — with full network connection detail, parent/child process trees, kill, restart, watch mode, JSON output, quick-view modes, and zero WMI usage on Windows.

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
```

With `-N` to show network connections:

```
    ├─ 🐬 [local=192.168.1.10:19447] [remote=74.125.24.188:5228] (fd:-1, type:TCP, family:2) | STATUS: ESTABLISHED
    ├─ 🐬 [local=192.168.1.10:25036] [remote=18.97.36.76:443]    (fd:-1, type:TCP, family:2) | STATUS: ESTABLISHED
    └─ 🧱 [local=0.0.0.0:5353]       [remote=N/A:N/A]            (fd:-1, type:UDP, family:2) | STATUS: ──
```

---

## Features

- **Full process detail** — name, PID, exe path, full command line, working directory, user, memory (RSS), CPU%, start time with millisecond precision
- **Network connections** — TCP/UDP IPv4 and IPv6, local/remote address + port, connection status; shown on demand with `-N` (hidden by default)
- **Quick-view modes** — `--exe`, `--cmd`, `--name`, `--mem`, `--flat` for compact single-line output per process
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
| CMD / CWD | `ReadProcessMemory` on PEB (WoW64-aware) | `/proc/pid/cmdline`, `/proc/pid/cwd` |
| Network connections | `iphlpapi.GetExtendedTcpTable` / `GetExtendedUdpTable` | `/proc/net/tcp`, `/proc/net/udp` |
| Terminal width | `kernel32.GetConsoleScreenBufferInfo` | `unix.IoctlGetWinsize` |
| **WMI used?** | **Never** | N/A |

The PEB `ReadProcessMemory` approach uses `PROCESS_QUERY_LIMITED_INFORMATION` and detects WoW64 (32-bit process on 64-bit Windows) to apply the correct PEB offsets. This recovers full `CMD` and `CWD` for sandboxed processes (Chrome renderers, Edge WebView, etc.) that block the standard `NtQueryInformationProcess` call.

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
pl [global options]
```

### Flags

#### Listing & filtering

| Flag | Short | Description |
|---|---|---|
| `--list` | `-l` | List processes |
| `--all` | `-a` | Show all processes (no filter) |
| `--filter NAME` | `-f` | Filter by process name, PID, or cmdline |
| `--pid PID` | `-i` | Show a specific process by PID |
| `--port PORT` | `-p` | Filter by port number (local or remote) |
| `--user USERNAME` | `-u` | Filter by username |
| `--min-mem MB` | | Only show processes using ≥ N MB RAM |
| `--no-filter-cmd` | `--nfc` | Disable filtering by command line |

#### Sorting

| Flag | Short | Description |
|---|---|---|
| `--last N` | `-z` | Show last N started processes |
| `--desc` | | Sort newest first |
| `--asc` | | Sort oldest first (default) |
| `--sort-mem` | `-m` | Sort by memory usage (RSS) |

#### Display modes

| Flag | Short | Description |
|---|---|---|
| `--networks` | `-N` | Show network connections per process *(default: hidden — pass `-N` to enable)* |
| `--network` | `-n` | Show only processes that have network connections |
| `--table` | `-t` | Display in table format |
| `--fields LIST` | | Show only selected fields (comma-separated) |
| `--no-color` | | Disable color output |

#### Quick-view modes — compact single-line output per process

| Flag | Modifier | Output format |
|---|---|---|
| `--exe` | | `001. /path/to/exe` |
| `--cmd` | | `001. full command line...` |
| `--name` | | `001. name [pid]` |
| `--mem` | | `001. name  mem` |
| `--mem` | `--percent` | `001. name  mem \| total / usage%` |
| `--flat` | | `001. name [pid] (mem / cpu%) [N port(s)]` |
| `--flat` | `--time` | `001. start_time  name [pid] (mem / cpu%) [N port(s)]  USER` |

#### Process trees

| Flag | Short | Description |
|---|---|---|
| `--show-parent` | `-P` | Show parent process tree |
| `--show-child` | `-C` | Show child process tree |
| `--depth N` | `-d` | Limit parent/child tree depth (0 = unlimited) |
| `--no-tree` | | Suppress parent/child tree lines |

#### Actions

| Flag | Short | Description |
|---|---|---|
| `--kill` | `-k` | Terminate matching process (use with `-f`, `-z 1`, or `-p`) |
| `--force` | | Force kill all matches (use with `-k -p`) |
| `--restart` | `-r` | Restart matching process (use with `-f`, `-z 1`, or `-p`) |
| `--watch N` | `-w` | Auto-refresh every N seconds |
| `--json` | `-j` | Output as JSON |

**Available `--fields` values:** `name`, `pid`, `exe`, `mem`, `cmd`, `cpu`, `user`, `cwd`, `net`, `start_time`

> `net` is only shown when `-N` is passed or explicitly added via `--fields name,pid,net,...`.

---

## Examples

### Basic listing

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

# Show only processes WITH network connections
pl -n -l

# Show network connections per process  ← requires -N
pl -f nginx -N

# Last 10 processes, newest first
pl -l -z 10 --desc

# Sort all by memory, descending
pl -l -a -m --desc

# Filter by user
pl -l -u root

# Show processes using >= 100 MB RAM
pl -l --min-mem 100
```

### Quick-view modes

```bash
# Show only exe paths
pl -f chrome --exe

# Show only command lines
pl -f chrome --cmd

# Show only name + PID — useful for scripting
pl -l -z 20 --name

# Show only name + memory
pl -l -a --mem

# Show name + memory with % of total memory used
pl -l -a --mem --percent

# Flat one-liner per process (with connection count if any)
pl -l -z 10 --flat

# Flat with start time and username
pl -f chrome --flat --time
```

### Quick-view output examples

```
# --name
001. chrome.exe [4012]
002. chrome.exe [13360]
003. nginx [1234]

# --mem
001. chrome.exe  537.62 MB
002. chrome.exe  279.64 MB
003. nginx  5.23 MB

# --mem --percent
001. chrome.exe  537.62 MB | 11585.07 MB / 4.64%
002. chrome.exe  279.64 MB | 11585.07 MB / 2.41%
003. nginx  5.23 MB | 11585.07 MB / 0.05%

# --flat
001. chrome.exe [4012] (537.62 MB / 0.5%)  2 port(s)
002. chrome.exe [13360] (279.64 MB / 2.5%)
003. nginx [1234] (5.23 MB / 0.1%)  3 port(s)

# --flat --time
001. 26/04/28 22:40:20:085  chrome.exe [4012] (537.62 MB / 0.5%)  2 port(s)   LIC-X\LICFACE
002. 26/04/28 22:40:23:217  chrome.exe [13360] (279.64 MB / 2.5%)  LIC-X\LICFACE
003. 24/03/15 08:22:11:045  nginx [1234] (5.23 MB / 0.1%)  3 port(s)   root
```

### Table & field selection

```bash
# Table format
pl -l -a -t

# Table with selected columns
pl -l -a -t --fields name,pid,mem,cpu

# Show name, pid, mem and network connections
pl -f nginx -N --fields name,pid,mem,net
```

### Process trees

```bash
# Show parent tree
pl -f python -P

# Show child tree, max depth 2
pl -f nginx -C -d 2
```

### Kill & restart

```bash
# Kill by name
pl -f myapp -k

# Kill by port
pl -p 3000 -k

# Force kill all processes on port 80
pl -p 80 -k --force

# Kill the most recently started process
pl -z 1 -k --desc

# Restart by name
pl -f myapp -r

# Restart by port
pl -p 8000 -r
```

### Watch & JSON

```bash
# Watch mode — refresh every 3 seconds
pl -f chrome -w 3

# Watch mode flat — all processes, every 2 seconds
pl -l -a --flat -w 2

# JSON output
pl -f nginx -j

# Pipe to jq
pl -l -a -j | jq '.[] | {pid, name, mem_mb}'

# No color output
pl -l -a --no-color
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
        "fd": "-1",
        "family": "2",
        "type": "TCP",
        "laddr": "0.0.0.0",
        "lport": 80,
        "raddr": "N/A",
        "rport": -1,
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
├── main.go                # Core logic, CLI, all rendering (platform-agnostic)
├── net_unix.go            # Network via /proc/net/tcp* (Linux/macOS)
├── net_windows.go         # Network via iphlpapi GetExtendedTcpTable (Windows, no WMI)
├── procs_unix.go          # Process list via gopsutil (Linux/macOS)
├── procs_windows.go       # Process list via psapi.EnumProcesses (Windows, no WMI)
├── prochelper_unix.go     # fmtStartTimeMS, getCmdlineCwd passthrough (Linux/macOS)
├── prochelper_windows.go  # WoW64-aware PEB ReadProcessMemory for CMD/CWD
├── termsize_unix.go       # Terminal width via unix.IoctlGetWinsize
└── termsize_windows.go    # Terminal width via kernel32.GetConsoleScreenBufferInfo
```

Build tags (`//go:build windows` / `//go:build !windows`) ensure only the correct file is compiled per platform — `go build` selects automatically.

---

## Comparison with Python original

| Feature | Python `pl11.py` | `pl-go` |
|---|---|---|
| Startup time | ~120 ms | ~5 ms |
| Memory usage | ~25 MB | ~4 MB |
| Binary | requires Python + pip | single static `.exe` / ELF |
| CMD for sandboxed procs | ✅ psutil | ✅ PEB (WoW64-aware) |
| CWD for sandboxed procs | ✅ psutil | ✅ PEB read |
| Network connections | ✅ full detail | ✅ full detail (no WMI) |
| UDP deduplication | ✅ | ✅ |
| N/A remote for UDP/LISTEN | ✅ | ✅ |
| Port number accuracy | ✅ | ✅ fixed endianness |
| IPv6 connections | ✅ | ✅ |
| Start time precision | milliseconds | milliseconds |
| 24-bit color | ✅ rich | ✅ gookit/color |
| Watch mode | ❌ | ✅ |
| JSON output | ❌ | ✅ |
| Field selector | ❌ | ✅ |
| Quick-view modes | ❌ | ✅ `--exe` `--cmd` `--name` `--mem` `--flat` |
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

`-ldflags="-s -w"` strips debug symbols, reducing binary size by ~30%.

---

## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)

---

## License

[MIT](_LICENSE)
