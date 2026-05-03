# Changelog

All notable changes to pl-go are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [7.2.5] - 2026-04-30

### Added
- Cross-platform Go port of Python pl11.py
- Windows: process enumeration via `psapi.EnumProcesses` (no WMI)
- Windows: network connections via `iphlpapi.GetExtendedTcpTable/UdpTable` (no WMI)
- Windows: CMD and CWD recovery via `ReadProcessMemory` on PEB — works for sandboxed processes (Chrome, Edge WebView, etc.)
- IPv6 TCP and UDP connection support on Windows
- Start time with millisecond precision (`YY/MM/DD HH:MM:SS:mmm`)
- Watch mode (`-w N`) — auto-refresh every N seconds
- JSON output (`-j`) with full process + connection schema
- Field selector (`--fields name,pid,mem,...`)
- Username filter (`-u`)
- Minimum memory filter (`--min-mem MB`)
- Tree depth limiter (`-d N`)
- `--no-tree` flag to suppress parent/child rendering
- `--no-color` flag for scripts and log files
- Direct PID lookup (`-i PID`)
- Error lines printed inline (matching Python behavior) when process dies mid-scan

### Fixed
- Windows port parsing (`winPort`) — was reading wrong bytes, all ports showed as 0
- fd field now shows `-1` on Windows (matching Python's behavior — no per-socket fd concept)
- `gather()` error in listProcesses now prints inline instead of silently skipping

### Changed
- Rewritten as multi-file project with Go build tags for clean platform separation
- `fmtStartTimeMS` replaces `time.Unix(ms/1000).Format(...)` — sub-second precision restored
