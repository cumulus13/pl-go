// File: main.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/urfave/cli/v2"
)

// ─── text wrap ────────────────────────────────────────────────────────────────

func wrapText(text, prefix string) string {
	maxWidth := termWidth() // platform-specific
	re := regexp.MustCompile(`([A-Z_]+\s+:\s*)$`)
	continuationPrefix := prefix
	if m := re.FindStringIndex(prefix); m != nil {
		label := prefix[m[0]:]
		base := prefix[:m[0]]
		continuationPrefix = base + strings.Repeat(" ", len(label))
	} else {
		r := strings.NewReplacer("├", "│", "└", " ")
		continuationPrefix = r.Replace(prefix)
	}
	available := maxWidth - len(prefix) - 2
	if available <= 20 {
		available = 60
	}
	if len(text) <= available {
		return text
	}
	words := strings.Fields(text)
	var lines []string
	var cur []string
	curLen := 0
	for _, w := range words {
		add := len(w)
		if len(cur) > 0 {
			add++
		}
		if curLen+add <= available {
			cur = append(cur, w)
			curLen += add
		} else {
			if len(cur) > 0 {
				lines = append(lines, strings.Join(cur, " "))
			}
			cur = []string{w}
			curLen = len(w)
		}
	}
	if len(cur) > 0 {
		lines = append(lines, strings.Join(cur, " "))
	}
	return strings.Join(lines, "\n"+continuationPrefix)
}

// ─── global flags ─────────────────────────────────────────────────────────────

var noColor bool

func maybeColor(fn func(string) string, s string) string {
	if noColor {
		return s
	}
	return fn(s)
}

// ─── colour helpers ────────────────────────────────────────────────────────────

func cHex(hex, text string) string   { return maybeColor(func(s string) string { return color.HEX(hex).Sprint(s) }, text) }
func cHexB(hex, text string) string  { return maybeColor(func(s string) string { return color.HEX(hex, true).Sprint(s) }, text) }
func cBg(fg, bg, text string) string { return maybeColor(func(s string) string { return color.HEXStyle(fg, bg).Sprint(s) }, text) }

func rName(s string) string      { return cHexB("#00FFFF", s) }
func rPidBadge(s string) string  { return cBg("#FFFFFF", "#55007F", s) }
func rMemBadge(s string) string  { return cBg("#FF0000", "#FFAA7F", s) }
func rUserBadge(s string) string { return cHex("#5555FF", s) }
// func rRunning(ok bool) string {
// 	if ok {
// 		return cHex("#FFFF00", "(running)")
// 	}
// 	return cBg("#FFFFFF", "#FF0000", "???")
// }
func rStatus(status string) string {
	switch strings.ToLower(status) {
	case "running":
		return cHex("#FFFF00", "(running)")

	case "suspended":
		return cBg("#000000", "#FFFF00", "(suspended)")

	case "stopped":
		return cBg("#FFFFFF", "#FF0000", "(stopped)")

	default:
		return cBg("#FFFFFF", "#550000", "(" + status + ")")
	}
}
func rNameVal(s string) string { return cHex("#00AAFF", s) }
func rPidVal(s string) string  { return cBg("#FFFFFF", "#550000", s) }
func rExeVal(s string) string  { return cHex("#AAAA7F", s) }
func rMemVal(s string) string  { return cBg("#FFFFFF", "#00007F", s) }
func rCmdVal(s string) string  { return cHex("#00FFFF", s) }
func rCpuVal(s string) string  { return cHex("#00AA00", s) }
func rUserVal(s string) string { return cHex("#5555FF", s) }
func rCwdVal(s string) string  { return cHex("#FFAA7F", s) }
func rCounter(s string) string { return cHex("#55FF00", s) }
func rParentLabel() string     { return cHexB("#FF00FF", "PARENT:") }
func rChildLabel() string      { return cHexB("#00FF00", "CHILD:") }

// ─── NetConn (shared between platforms) ──────────────────────────────────────

type NetConn struct {
	Fd     string `json:"fd"`
	Family string `json:"family"`
	Type   string `json:"type"`
	Laddr  string `json:"laddr"`
	Lport  int    `json:"lport"`
	Raddr  string `json:"raddr"`
	Rport  int    `json:"rport"`
	Status string `json:"status"`
}

// checkPort checks if the process uses a given port (local or remote).
func checkPort(pid int32, port int) bool {
	for _, c := range getConnections(pid) { // platform-specific
		if c.Lport == port || c.Rport == port {
			return true
		}
	}
	return false
}

func renderConn(c NetConn, isLast bool, indent string) string {
	chr := "├─"
	if isLast {
		chr = "└─"
	}
	var statusStr string
	switch c.Status {
	case "ESTABLISHED":
		statusStr = cBg("#000000", "#FFFF00", "ESTABLISHED")
	case "LISTEN":
		statusStr = cBg("#FFFF00", "#0000FF", "LISTEN")
	case "NONE":
		statusStr = cHex("#00FFFF", "──")
	default:
		statusStr = cBg("#FFFF00", "#FF0000", c.Status)
	}
	netIcon := "🐬"
	if c.Status == "LISTEN" {
		netIcon = "💥"
	} else if c.Status == "NONE" {
		netIcon = "🧱"
	} else if c.Status != "ESTABLISHED" {
		netIcon = "🩲"
	}
	var typeStr string
	switch c.Type {
	case "TCP":
		typeStr = cBg("#FFFFFF", "#55007F", "TCP")
	case "UDP":
		typeStr = cBg("#FFFFFF", "#5500FF", "UDP")
	default:
		typeStr = cBg("#FFFFFF", "#FF0000", "N/A")
	}
	// Format local addr — always has a port
	laddrStr := fmt.Sprintf("%s:%d", c.Laddr, c.Lport)
	laddr := cBg("#FFFFFF", "#005500", laddrStr)

	// Format remote addr — show N/A:N/A when port is -1 (UDP / LISTEN with no remote)
	var raddrStr string
	if c.Rport == -1 || c.Raddr == "N/A" {
		raddrStr = "N/A:N/A"
	} else {
		raddrStr = fmt.Sprintf("%s:%d", c.Raddr, c.Rport)
	}
	raddr := cBg("#AAFFFF", "#AA0000", raddrStr)

	// family: show integer like Python (2=AF_INET, 23=AF_INET6) for exact parity
	familyStr := c.Family
	switch c.Family {
	case "AF_INET":
		familyStr = "2"
	case "AF_INET6":
		familyStr = "23"
	}

	return fmt.Sprintf("%s%s %s [local=%s] [remote=%s] (fd:%s, type:%s, family:%s) | STATUS: %s",
		indent, chr, netIcon, laddr, raddr, c.Fd, typeStr, familyStr, statusStr)
}

// ─── process info ─────────────────────────────────────────────────────────────

type ProcInfo struct {
	Pid       int32     `json:"pid"`
	Name      string    `json:"name"`
	Exe       string    `json:"exe"`
	Cmd       string    `json:"cmd"`
	Cwd       string    `json:"cwd"`
	User      string    `json:"user"`
	MemMB     float64   `json:"mem_mb"`
	CPU       float64   `json:"cpu_percent"`
	Running   bool      `json:"running"`
	StartTime string    `json:"start_time"`
	Conns     []NetConn `json:"connections"`
	Status    string    `json:"status"`
}

func gather(p *process.Process) (*ProcInfo, error) {
	mem, err := p.MemoryInfo()
	if err != nil {
		return nil, err
	}
	name, _ := p.Name()
	exe, _ := p.Exe()
	rawCmd, _ := p.Cmdline()
	rawCwd, _ := p.Cwd()
	user, _ := p.Username()
	cpu, _ := p.CPUPercent()
	running, _ := p.IsRunning()
	ct, _ := p.CreateTime()
	status := getProcessStatus(p.Pid)

	// Platform-aware CMD/CWD resolution:
	// On Windows, sandboxed processes (Chrome renderers, etc.) block gopsutil's
	// NtQueryInformationProcess read. getCmdlineCwd() falls back to direct
	// ReadProcessMemory on the PEB, then dirname(exe) as last resort.
	// On Linux, getCmdlineCwd() is a no-op passthrough.
	cmd, cwd := getCmdlineCwd(p.Pid, rawCmd, rawCwd, exe)

	return &ProcInfo{
		Pid: p.Pid, Name: name, Exe: exe, Cmd: cmd,
		Cwd: cwd, User: user,
		MemMB:     float64(mem.RSS) / 1024 / 1024,
		CPU:       cpu,
		Running:   running,
		Status:    status,
		StartTime: fmtStartTimeMS(ct), // platform-specific, includes milliseconds
		Conns:     getConnections(p.Pid),
	}, nil
}

func fieldEnabled(fields map[string]bool, name string) bool {
	if len(fields) == 0 {
		return true
	}
	return fields[strings.ToLower(name)]
}

func renderBlock(info *ProcInfo, prefix, detailPrefix string, fields map[string]bool) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("%s%s [%s] %s %s %s\n",
		prefix,
		rName(info.Name), rPidBadge(fmt.Sprintf("%d", info.Pid)),
		rMemBadge(fmt.Sprintf("%.2f MB", info.MemMB)),
		// rUserBadge(info.User), rRunning(info.Running),
		rUserBadge(info.User), rStatus(info.Status),
	))
	if fieldEnabled(fields, "start_time") && info.StartTime != "" {
		sb.WriteString(fmt.Sprintf("%sSTART_TIME : %s\n", detailPrefix, info.StartTime))
	}
	if fieldEnabled(fields, "name") {
		sb.WriteString(fmt.Sprintf("%sNAME   : %s\n", detailPrefix, rNameVal(info.Name)))
	}
	if fieldEnabled(fields, "pid") {
		sb.WriteString(fmt.Sprintf("%sPID    : %s\n", detailPrefix, rPidVal(fmt.Sprintf("%d", info.Pid))))
	}
	if fieldEnabled(fields, "exe") {
		sb.WriteString(fmt.Sprintf("%sEXE    : %s\n", detailPrefix, rExeVal(wrapText(info.Exe, detailPrefix+"EXE    : "))))
	}
	if fieldEnabled(fields, "mem") {
		sb.WriteString(fmt.Sprintf("%sMEM    : %s\n", detailPrefix, rMemVal(fmt.Sprintf("%.2f MB", info.MemMB))))
	}
	if fieldEnabled(fields, "cmd") {
		sb.WriteString(fmt.Sprintf("%sCMD    : %s\n", detailPrefix, rCmdVal(wrapText(info.Cmd, detailPrefix+"CMD    : "))))
	}
	if fieldEnabled(fields, "cpu") {
		sb.WriteString(fmt.Sprintf("%sCPU    : %s\n", detailPrefix, rCpuVal(fmt.Sprintf("%.1f", info.CPU))))
	}
	if fieldEnabled(fields, "user") {
		sb.WriteString(fmt.Sprintf("%sUSER   : %s\n", detailPrefix, rUserVal(info.User)))
	}
	if fieldEnabled(fields, "cwd") {
		sb.WriteString(fmt.Sprintf("%sCWD    : %s\n", detailPrefix, rCwdVal(wrapText(info.Cwd, detailPrefix+"CWD    : "))))
	}
	if fieldEnabled(fields, "net") {
		for i, conn := range info.Conns {
			sb.WriteString(renderConn(conn, i == len(info.Conns)-1, detailPrefix) + "\n")
		}
	}
	return sb.String()
}

// ─── parent / child helpers ───────────────────────────────────────────────────

func getParents(pid int32, depth int) []*process.Process {
	var parents []*process.Process
	p, err := process.NewProcess(pid)
	if err != nil {
		return nil
	}
	for d := 0; depth == 0 || d < depth; d++ {
		ppid, err := p.Ppid()
		if err != nil || ppid <= 0 {
			break
		}
		parent, err := process.NewProcess(ppid)
		if err != nil {
			break
		}
		parents = append(parents, parent)
		p = parent
	}
	return parents
}

func getChildren(pid int32, all []*process.Process) []*process.Process {
	var out []*process.Process
	for _, p := range all {
		ppid, err := p.Ppid()
		if err == nil && ppid == pid {
			out = append(out, p)
		}
	}
	return out
}

func renderTree(procs []*process.Process, netOnly bool, baseIndent string,
	fields map[string]bool, depth, maxDepth int, all []*process.Process) {
	if maxDepth > 0 && depth >= maxDepth {
		return
	}
	for i, p := range procs {
		isLast := i == len(procs)-1
		treeChar := "├── "
		detailChar := "│   "
		if isLast {
			treeChar = "└── "
			detailChar = "    "
		}
		info, err := gather(p)
		if err != nil {
			continue
		}
		if netOnly && len(info.Conns) == 0 {
			continue
		}
		fmt.Print(renderBlock(info, baseIndent+treeChar, baseIndent+detailChar, fields))
		if all != nil {
			grandChildren := getChildren(p.Pid, all)
			if len(grandChildren) > 0 {
				renderTree(grandChildren, netOnly, baseIndent+detailChar, fields, depth+1, maxDepth, all)
			}
		}
	}
}

// ─── no-process banner ────────────────────────────────────────────────────────

func printNoProcess() {
	hexColors := []string{
		"#FF0000", "#00FF00", "#0000FF", "#FFFF00", "#FF00FF", "#00FFFF",
		"#FF5555", "#55FF55", "#5555FF", "#FFFF55", "#FF55FF", "#55FFFF",
	}
	fmt.Println()
	fmt.Print("😞 🚯 😵 😂 🎸 🎵️ ⛔ ☣️ 🔜 ")
	for _, ch := range "N-O  P-R-O-C-E-S-S  F-O-U-N-D" {
		if ch != ' ' {
			fmt.Print(color.HEX(hexColors[rand.Intn(len(hexColors))], true).Sprint(string(ch)))
		} else {
			fmt.Print(" ")
		}
	}
	fmt.Println(" ◾")
}

// ─── table printer ────────────────────────────────────────────────────────────

func printTable(rows [][]string, fields map[string]bool) {
	allHeaders := []string{"NO", "NAME", "PID", "MEM", "CPU", "EXE", "CMD", "USER", "START_TIME", "CWD"}
	fieldKeys := []string{"", "name", "pid", "mem", "cpu", "exe", "cmd", "user", "start_time", "cwd"}

	var headers []string
	var colIdx []int
	for i, h := range allHeaders {
		if i == 0 || fieldEnabled(fields, fieldKeys[i]) {
			headers = append(headers, h)
			colIdx = append(colIdx, i)
		}
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for ci, origI := range colIdx {
			if origI >= len(row) {
				continue
			}
			cap := len(row[origI])
			if origI == 6 && cap > 40 {
				cap = 40
			}
			if cap > widths[ci] {
				widths[ci] = cap
			}
		}
	}
	sep := "+"
	for _, w := range widths {
		sep += strings.Repeat("-", w+2) + "+"
	}
	printRow := func(cells []string) {
		fmt.Print("|")
		for i, c := range cells {
			s := c
			if len(s) > widths[i] {
				s = s[:widths[i]-1] + "…"
			}
			fmt.Printf(" %-*s |", widths[i], s)
		}
		fmt.Println()
	}
	fmt.Println(sep)
	printRow(headers)
	fmt.Println(sep)
	for _, row := range rows {
		var selected []string
		for _, origI := range colIdx {
			if origI < len(row) {
				selected = append(selected, row[origI])
			} else {
				selected = append(selected, "")
			}
		}
		printRow(selected)
	}
	fmt.Println(sep)
}

// ─── quick-view render functions ─────────────────────────────────────────────

// renderModeExe: "001. /path/to/exe"
func renderModeExe(idx int, info *ProcInfo) string {
	return fmt.Sprintf("%s %s\n",
		rCounter(fmt.Sprintf("%03d.", idx)),
		rExeVal(info.Exe),
	)
}

// renderModeCmd: "001. full command line..."
func renderModeCmd(idx int, info *ProcInfo) string {
	return fmt.Sprintf("%s %s\n",
		rCounter(fmt.Sprintf("%03d.", idx)),
		rCmdVal(info.Cmd),
	)
}

// renderModeName: "001. chrome.exe [1234]"
func renderModeName(idx int, info *ProcInfo) string {
	return fmt.Sprintf("%s %s [%s]\n",
		rCounter(fmt.Sprintf("%03d.", idx)),
		rName(info.Name),
		rPidBadge(fmt.Sprintf("%d", info.Pid)),
	)
}

// renderModeMem: "001. chrome.exe (537.62 MB)"
// with --percent: "001. chrome.exe (537.62 MB | 11585.07 MB / 4.64%)"
func renderModeMem(idx int, info *ProcInfo, totalMem float64, percent bool) string {
	memStr := cBg("#FFFFFF", "#00007F", fmt.Sprintf("%.2f MB", info.MemMB))
	if percent && totalMem > 0 {
		pct := info.MemMB / totalMem * 100
		memStr = fmt.Sprintf("%s %s %s %s",
			cBg("#FFFFFF", "#00007F", fmt.Sprintf("%.2f MB", info.MemMB)),
			cHexB("#FF55FF", "|"),
			cHexB("#FFFF00", fmt.Sprintf("%.2f MB", totalMem)),
			cHexB("#00FFFF", fmt.Sprintf("/ %.2f%%", pct)),
		)
	}
	return fmt.Sprintf("%s %s %s\n",
		rCounter(fmt.Sprintf("%03d.", idx)),
		rName(info.Name),
		memStr,
	)
}

// renderModeFlat: "001. chrome.exe [1234] (537.62 MB / 2.5%) [12 conns]"
// with --time:    "001. 26/04/29 13:51:08:257  chrome.exe [1234] (537.62 MB / 2.5%) [12 conns] LIC-X\LICFACE"
func renderModeFlat(idx int, info *ProcInfo, withTime bool) string {
	pidPart  := fmt.Sprintf("[%s]", rPidBadge(fmt.Sprintf("%d", info.Pid)))
	memPart  := cBg("#FFFFFF", "#00007F", fmt.Sprintf("%.2f MB", info.MemMB))
	cpuPart  := cHexB("#0000FF", fmt.Sprintf("%.1f%%", info.CPU))
	resource := fmt.Sprintf("(%s / %s)", memPart, cpuPart)

	var connPart string
	if len(info.Conns) > 0 {
		connPart = " " + cBg("#FFFF00", "#005500", fmt.Sprintf(" %d port(s) ", len(info.Conns)))
	}

	if withTime {
		timePart := cHexB("#AAAAAA", info.StartTime)
		userPart := rUserVal(info.User)
		return fmt.Sprintf("%s %s  %s %s %s%s  %s\n",
			rCounter(fmt.Sprintf("%03d.", idx)),
			timePart,
			rName(info.Name),
			pidPart,
			resource,
			connPart,
			userPart,
		)
	}
	return fmt.Sprintf("%s %s %s %s%s\n",
		rCounter(fmt.Sprintf("%03d.", idx)),
		rName(info.Name),
		pidPart,
		resource,
		connPart,
	)
}

// ─── list options ─────────────────────────────────────────────────────────────

type ListOpts struct {
	Filter      string
	PidFilter   int32
	UserFilter  string
	MinMemMB    float64
	ShowNetOnly bool   // -n: show only procs WITH connections
	ShowNets    bool   // -N: show connections per process (default OFF)
	TableMode   bool
	JSONMode    bool
	LastN       int
	SortDesc    bool
	NoFilterCmd bool
	SortMem     bool
	PortFilter  int
	KillIt      bool
	RestartIt   bool
	ShowParent  bool
	ShowChild   bool
	NoTree      bool
	TreeDepth   int
	Fields      map[string]bool
	Exceptions  []string // --exception / -e: exclude processes matching these names
	// quick-view modes
	ModeExe     bool // --exe  → index. exe_path
	ModeCmd     bool // --cmd  → index. cmdline
	ModeName    bool // --name → index. name [pid]
	ModeMem     bool // --mem  → index. name (mem)  or  index. name (mem | X%)
	ModePercent bool // --percent  (modifier for --mem)
	ModeFlat    bool // --flat → index. name [pid] (mem/cpu%) [N ports]
	ModeFlatTime bool // --flat --time → adds start_time and user
	SuspendIt    bool
	ResumeIt     bool
}

// ─── list processes ───────────────────────────────────────────────────────────

func listProcesses(opts ListOpts) {
	selfPid := int32(os.Getpid())

	allProcs, err := getAllProcesses() // platform-specific (no WMI on Windows)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error listing processes:", err)
		return
	}

	// exclude self
	var procs []*process.Process
	for _, p := range allProcs {
		if p.Pid != selfPid {
			procs = append(procs, p)
		}
	}

	// port filter
	if opts.PortFilter > 0 {
		fmt.Printf("\n🔍 %s\n\n", cHexB("#FFFF00",
			fmt.Sprintf("Searching for processes using port %d...", opts.PortFilter)))
		var filtered []*process.Process
		for _, p := range procs {
			if checkPort(p.Pid, opts.PortFilter) {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) == 0 {
			color.Red.Printf("No process found using port %d\n", opts.PortFilter)
			return
		}
		procs = filtered
	}

	// direct PID lookup
	if opts.PidFilter > 0 {
		var filtered []*process.Process
		for _, p := range procs {
			if p.Pid == opts.PidFilter {
				filtered = append(filtered, p)
				break
			}
		}
		if len(filtered) == 0 {
			color.Red.Printf("No process found with PID %d\n", opts.PidFilter)
			return
		}
		procs = filtered
	}

	// sort
	type pt struct {
		p   *process.Process
		ct  int64
		rss uint64
	}
	var sorted []pt
	for _, p := range procs {
		ct, _ := p.CreateTime()
		mem, _ := p.MemoryInfo()
		rss := uint64(0)
		if mem != nil {
			rss = mem.RSS
		}
		sorted = append(sorted, pt{p, ct, rss})
	}
	if opts.SortMem {
		sort.Slice(sorted, func(i, j int) bool {
			if opts.SortDesc {
				return sorted[i].rss > sorted[j].rss
			}
			return sorted[i].rss < sorted[j].rss
		})
	} else {
		sort.Slice(sorted, func(i, j int) bool {
			if opts.SortDesc {
				return sorted[i].ct > sorted[j].ct
			}
			return sorted[i].ct < sorted[j].ct
		})
	}
	if opts.LastN > 0 && opts.LastN < len(sorted) {
		if opts.SortDesc {
			sorted = sorted[:opts.LastN]
		} else {
			sorted = sorted[len(sorted)-opts.LastN:]
		}
	}
	procs = make([]*process.Process, len(sorted))
	for i, s := range sorted {
		procs[i] = s.p
	}

	var tableRows [][]string
	type entry struct {
		n        int
		info     *ProcInfo
		parents  []*process.Process
		children []*process.Process
	}
	var entries []entry
	var jsonOut []ProcInfo
	totalMem := 0.0
	counter := 1

	for _, p := range procs {
		name, _ := p.Name()
		cmd, _ := p.Cmdline()
		user, _ := p.Username()

		// name/pid/cmd filter
		if opts.Filter != "" {
			fl := strings.ToLower(opts.Filter)
			pidStr := strconv.Itoa(int(p.Pid))
			nameMatch := strings.Contains(strings.ToLower(name), fl)
			pidMatch := strings.Contains(pidStr, fl)
			cmdMatch := !opts.NoFilterCmd && strings.Contains(strings.ToLower(cmd), fl)
			if !nameMatch && !pidMatch && !cmdMatch {
				continue
			}
		}

		// exception filter: skip if name, pid, or cmdline matches any exception pattern
		if len(opts.Exceptions) > 0 {
			skip := false
			pidStr := fmt.Sprintf("%d", p.Pid)
			for _, ex := range opts.Exceptions {
				el := strings.ToLower(strings.TrimSpace(ex))
				if el == "" {
					continue
				}
				if strings.Contains(strings.ToLower(name), el) ||
					strings.Contains(pidStr, el) ||
					strings.Contains(strings.ToLower(cmd), el) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
		}

		// user filter
		if opts.UserFilter != "" && !strings.EqualFold(user, opts.UserFilter) {
			continue
		}

		info, err := gather(p)
		// fmt.Printf("info: %v\n", info)
		if err != nil {
			// Print error inline like Python — process died mid-scan
			ct2, _ := p.CreateTime()
			n2, _ := p.Name()
			st2 := fmtStartTimeMS(ct2)
			fmt.Printf("\nError retrieving process info: %v (pid=%d, name=%q)\n    START_TIME : %s\n\n",
				err, p.Pid, n2, st2)
			continue
		}

		// min memory filter
		if opts.MinMemMB > 0 && info.MemMB < opts.MinMemMB {
			continue
		}

		// network-only filter
		if opts.ShowNetOnly && len(info.Conns) == 0 {
			continue
		}

		if opts.JSONMode {
			jsonOut = append(jsonOut, *info)
			totalMem += info.MemMB
			counter++
			continue
		}

		// ── quick-view modes: print immediately and move on ──────────────────
		if opts.ModeExe {
			fmt.Print(renderModeExe(counter, info))
			totalMem += info.MemMB
			counter++
			continue
		}
		if opts.ModeCmd {
			fmt.Print(renderModeCmd(counter, info))
			totalMem += info.MemMB
			counter++
			continue
		}
		if opts.ModeName {
			fmt.Print(renderModeName(counter, info))
			totalMem += info.MemMB
			counter++
			continue
		}
		if opts.ModeMem {
			// totalMem not yet final here; collect into entries for second pass
			entries = append(entries, entry{counter, info, nil, nil})
			totalMem += info.MemMB
			counter++
			continue
		}
		if opts.ModeFlat {
			fmt.Print(renderModeFlat(counter, info, opts.ModeFlatTime))
			totalMem += info.MemMB
			counter++
			continue
		}

		if opts.TableMode {
			tableRows = append(tableRows, []string{
				fmt.Sprintf("%03d", counter), name,
				fmt.Sprintf("%d", p.Pid),
				fmt.Sprintf("%.2f MB", info.MemMB),
				fmt.Sprintf("%.1f", info.CPU),
				info.Exe, info.Cmd, info.User, info.StartTime, info.Cwd,
			})
		} else {
			var parents []*process.Process
			var children []*process.Process
			if opts.ShowParent && !opts.NoTree {
				parents = getParents(p.Pid, opts.TreeDepth)
			}
			if opts.ShowChild && !opts.NoTree {
				children = getChildren(p.Pid, allProcs)
			}
			entries = append(entries, entry{counter, info, parents, children})
		}

		totalMem += info.MemMB
		counter++

		if opts.KillIt {
			if err := p.Terminate(); err == nil {
				fmt.Printf("✅ %s %s %s\n",
					cHexB("#00FFFF", "Success"),
					cHexB("#FF007F", "Terminate"),
					cHexB("#FFFF00", name))
			} else {
				color.Red.Printf("ERROR: %v\n", err)
			}
		} else if opts.RestartIt {
			restartProcess(p)
		} else if opts.SuspendIt {
			doSuspend(p)
		} else if opts.ResumeIt {
			doResume(p)
		}
	}

	// JSON output
	if opts.JSONMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(jsonOut)
		return
	}

	// --mem second pass: totalMem is now final, render with optional %
	if opts.ModeMem {
		for _, e := range entries {
			fmt.Print(renderModeMem(e.n, e.info, totalMem, opts.ModePercent))
		}
		goto summary
	}

	// Table output
	if opts.TableMode {
		printTable(tableRows, opts.Fields)
	} else {
		for _, e := range entries {
			block := renderBlock(e.info, "", "    ", opts.Fields)
			lines := strings.SplitN(block, "\n", 2)
			if len(lines) > 0 {
				lines[0] = rCounter(fmt.Sprintf("%03d.", e.n)) + " " + lines[0]
			}
			fmt.Print(strings.Join(lines, "\n"))
			if len(e.parents) > 0 {
				fmt.Printf("    %s\n", rParentLabel())
				renderTree(e.parents, opts.ShowNetOnly, "    ", opts.Fields, 0, opts.TreeDepth, nil)
			}
			if len(e.children) > 0 {
				fmt.Printf("    %s\n", rChildLabel())
				renderTree(e.children, opts.ShowNetOnly, "    ", opts.Fields, 0, opts.TreeDepth, allProcs)
			}
			fmt.Println()
		}
	}

summary:

	if counter > 1 {
		fmt.Printf("\n📈 %s %s %s %s\n",
			cBg("#FFFFFF", "#00007F", "TOTAL MEM USAGE:"),
			cHexB("#FFFF00", fmt.Sprintf("%.2f MB", totalMem)),
			cHexB("#FF55FF", "~"),
			cHexB("#00FFFF", fmt.Sprintf("%.5f GB", totalMem/1024)),
		)
	} else {
		printNoProcess()
	}
}

// ─── watch mode ───────────────────────────────────────────────────────────────

func watchLoop(interval int, opts ListOpts) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("%s  %s  interval: %ds  Ctrl+C to exit\n\n",
			cHexB("#00FFFF", "● WATCH MODE"),
			cHexB("#FFFF00", time.Now().Format("2006/01/02 15:04:05")),
			interval,
		)
		listProcesses(opts)
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

// ─── kill ─────────────────────────────────────────────────────────────────────

func doKill(p *process.Process) {
	n, _ := p.Name()
	color.Yellow.Printf("\nAttempting to terminate:\n  Name: %s\n  PID:  %d\n", n, p.Pid)
	if err := p.Terminate(); err != nil {
		color.Red.Printf("✗ Failed: %v\n", err)
		return
	}
	time.Sleep(3 * time.Second)
	if running, _ := p.IsRunning(); !running {
		color.Green.Printf("✓ Process %s (PID %d) terminated successfully.\n", n, p.Pid)
	} else {
		color.Yellow.Println("Process didn't terminate gracefully. Forcing kill...")
		p.Kill()
		color.Green.Printf("✓ Process %s (PID %d) killed forcefully.\n", n, p.Pid)
	}
}

func killProcess(filter string, lastN int, sortDesc bool, portFilter int, force bool) {
	allProcs, _ := getAllProcesses()
	if portFilter > 0 {
		var matched []*process.Process
		for _, p := range allProcs {
			if checkPort(p.Pid, portFilter) {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			color.Red.Printf("No process found using port %d\n", portFilter)
			return
		}
		if len(matched) > 1 && !force {
			color.Yellow.Printf("Found %d processes using port %d:\n", len(matched), portFilter)
			for _, p := range matched {
				n, _ := p.Name()
				fmt.Printf("  - %s (PID: %d)\n", n, p.Pid)
			}
			color.Red.Println("\nMultiple processes found. Use --force to kill all of them.")
			return
		}
		for _, p := range matched {
			doKill(p)
		}
		return
	}
	type pt struct {
		p  *process.Process
		ct int64
	}
	var srt []pt
	for _, p := range allProcs {
		ct, _ := p.CreateTime()
		srt = append(srt, pt{p, ct})
	}
	sort.Slice(srt, func(i, j int) bool {
		if sortDesc {
			return srt[i].ct > srt[j].ct
		}
		return srt[i].ct < srt[j].ct
	})
	fl := strings.ToLower(filter)
	for _, item := range srt {
		n, _ := item.p.Name()
		cmd, _ := item.p.Cmdline()
		if fl != "" && (strings.Contains(strings.ToLower(n), fl) ||
			strings.Contains(strings.ToLower(cmd), fl)) {
			doKill(item.p)
			return
		}
	}
	if lastN == 1 && len(srt) > 0 {
		if sortDesc {
			doKill(srt[0].p)
		} else {
			doKill(srt[len(srt)-1].p)
		}
		return
	}
	color.Red.Println("No matching process found to kill.")
}

// ─── restart ──────────────────────────────────────────────────────────────────

func restartProcess(p *process.Process) {
	color.Yellow.Println("Attempting to restart process...\n")
	n, _ := p.Name()

	// Use exe path as the executable — avoids the quoted-path splitting problem
	// that breaks strings.Fields() on paths like "C:\Program Files\...".
	// CmdlineSlice() gives us correctly-parsed argv (handles Windows quoting).
	exePath, err := p.Exe()
	if err != nil || exePath == "" {
		color.Red.Printf("Cannot restart %s: exe path unavailable.\n", n)
		return
	}
	argSlice, _ := p.CmdlineSlice()
	// argSlice[0] is the exe itself; pass the rest as arguments
	var args []string
	if len(argSlice) > 1 {
		args = argSlice[1:]
	}

	cmd, _ := p.Cmdline()
	color.Cyan.Printf("Process: %s (PID %d)\nEXE:     %s\nCommand: %s\n\n", n, p.Pid, exePath, cmd)

	if err := p.Terminate(); err != nil {
		color.Red.Printf("✗ Failed to terminate: %v\n", err)
		return
	}
	time.Sleep(1 * time.Second)
	color.Green.Println("✓ Process terminated")

	newCmd := exec.Command(exePath, args...)
	newCmd.Stdout = os.Stdout
	newCmd.Stderr = os.Stderr
	if err := newCmd.Start(); err != nil {
		color.Red.Printf("✗ Failed to restart: %v\n", err)
		return
	}
	color.Green.Printf("✓ Process restarted with new PID: %d\n", newCmd.Process.Pid)
}

func restartByFilter(filter string, lastN int, sortDesc bool, portFilter int) {
	allProcs, _ := getAllProcesses()
	if portFilter > 0 {
		var matched []*process.Process
		for _, p := range allProcs {
			if checkPort(p.Pid, portFilter) {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			color.Red.Printf("No process found using port %d\n", portFilter)
			return
		}
		if len(matched) > 1 {
			color.Red.Printf("Multiple processes found using port %d. Be more specific.\n", portFilter)
			return
		}
		restartProcess(matched[0])
		return
	}
	type pt struct {
		p  *process.Process
		ct int64
	}
	var srt []pt
	for _, p := range allProcs {
		ct, _ := p.CreateTime()
		srt = append(srt, pt{p, ct})
	}
	sort.Slice(srt, func(i, j int) bool {
		if sortDesc {
			return srt[i].ct > srt[j].ct
		}
		return srt[i].ct < srt[j].ct
	})
	fl := strings.ToLower(filter)
	for _, item := range srt {
		n, _ := item.p.Name()
		cmd, _ := item.p.Cmdline()
		if fl != "" && (strings.Contains(strings.ToLower(n), fl) ||
			strings.Contains(strings.ToLower(cmd), fl)) {
			restartProcess(item.p)
			return
		}
	}
	if lastN == 1 && len(srt) > 0 {
		if sortDesc {
			restartProcess(srt[0].p)
		} else {
			restartProcess(srt[len(srt)-1].p)
		}
		return
	}
	color.Red.Println("No matching process found to restart.")
}

// doSuspend suspends a single process and prints a status line.
func doSuspend(p *process.Process) {
	n, _ := p.Name()
	color.Yellow.Printf("\nAttempting to suspend:\n  Name: %s\n  PID:  %d\n", n, p.Pid)
	if err := suspendProcess(p.Pid); err != nil {
		color.Red.Printf("✗ Failed: %v\n", err)
		return
	}
	fmt.Printf("⏸  %s %s %s\n",
		cHexB("#00FFFF", "Suspended"),
		cHexB("#FF007F", n),
		cHexB("#FFFF00", fmt.Sprintf("PID %d", p.Pid)),
	)
}

// doResume resumes a single previously-suspended process.
func doResume(p *process.Process) {
	n, _ := p.Name()
	color.Yellow.Printf("\nAttempting to resume:\n  Name: %s\n  PID:  %d\n", n, p.Pid)
	if err := resumeProcess(p.Pid); err != nil {
		color.Red.Printf("✗ Failed: %v\n", err)
		return
	}
	fmt.Printf("▶  %s %s %s\n",
		cHexB("#00FF00", "Resumed"),
		cHexB("#FF007F", n),
		cHexB("#FFFF00", fmt.Sprintf("PID %d", p.Pid)),
	)
}

// suspendByFilter finds processes matching filter/lastN/portFilter and suspends them.
// Multiple matches are all suspended (unlike kill which requires --force for ports).
func suspendByFilter(filter string, lastN int, sortDesc bool, portFilter int) {
	allProcs, _ := getAllProcesses()

	if portFilter > 0 {
		var matched []*process.Process
		for _, p := range allProcs {
			if checkPort(p.Pid, portFilter) {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			color.Red.Printf("No process found using port %d\n", portFilter)
			return
		}
		for _, p := range matched {
			doSuspend(p)
		}
		return
	}

	type pt struct {
		p  *process.Process
		ct int64
	}
	var srt []pt
	for _, p := range allProcs {
		ct, _ := p.CreateTime()
		srt = append(srt, pt{p, ct})
	}
	sort.Slice(srt, func(i, j int) bool {
		if sortDesc {
			return srt[i].ct > srt[j].ct
		}
		return srt[i].ct < srt[j].ct
	})

	fl := strings.ToLower(filter)
	found := false
	for _, item := range srt {
		n, _ := item.p.Name()
		cmd, _ := item.p.Cmdline()
		if fl != "" && (strings.Contains(strings.ToLower(n), fl) ||
			strings.Contains(strings.ToLower(cmd), fl)) {
			doSuspend(item.p)
			found = true
			// suspend ALL matches, not just first
		}
	}
	if !found {
		if lastN == 1 && len(srt) > 0 {
			if sortDesc {
				doSuspend(srt[0].p)
			} else {
				doSuspend(srt[len(srt)-1].p)
			}
			return
		}
		color.Red.Println("No matching process found to suspend.")
	}
}

// resumeByFilter finds processes matching filter/lastN/portFilter and resumes them.
func resumeByFilter(filter string, lastN int, sortDesc bool, portFilter int) {
	allProcs, _ := getAllProcesses()

	if portFilter > 0 {
		var matched []*process.Process
		for _, p := range allProcs {
			if checkPort(p.Pid, portFilter) {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			color.Red.Printf("No process found using port %d\n", portFilter)
			return
		}
		for _, p := range matched {
			doResume(p)
		}
		return
	}

	type pt struct {
		p  *process.Process
		ct int64
	}
	var srt []pt
	for _, p := range allProcs {
		ct, _ := p.CreateTime()
		srt = append(srt, pt{p, ct})
	}
	sort.Slice(srt, func(i, j int) bool {
		if sortDesc {
			return srt[i].ct > srt[j].ct
		}
		return srt[i].ct < srt[j].ct
	})

	fl := strings.ToLower(filter)
	found := false
	for _, item := range srt {
		n, _ := item.p.Name()
		cmd, _ := item.p.Cmdline()
		if fl != "" && (strings.Contains(strings.ToLower(n), fl) ||
			strings.Contains(strings.ToLower(cmd), fl)) {
			doResume(item.p)
			found = true
		}
	}
	if !found {
		if lastN == 1 && len(srt) > 0 {
			if sortDesc {
				doResume(srt[0].p)
			} else {
				doResume(srt[len(srt)-1].p)
			}
			return
		}
		color.Red.Println("No matching process found to resume.")
	}
}


// ─── helpers ──────────────────────────────────────────────────────────────────

func parseFields(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	out := map[string]bool{}
	for _, f := range strings.Split(raw, ",") {
		out[strings.TrimSpace(strings.ToLower(f))] = true
	}
	return out
}

// ─── CLI ──────────────────────────────────────────────────────────────────────

func main() {
	app := &cli.App{
		Name:    "pl",
		Usage:   "Process List Viewer",
		Version: "7.2.10",
		Authors: []*cli.Author{
			{Name: "Hadi Cahyadi", Email: "cumulus13@gmail.com"},
		},
		Description: cHexB("#00AAFF", "Fast, colorful process inspector — network, parent/child tree, kill, restart, watch & JSON.\nWindows: uses EnumProcesses+iphlpapi (no WMI). Linux: reads /proc directly."),
		Flags: []cli.Flag{
			// ── original flags ──
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Filter by process `NAME`, PID, or cmdline"},
			&cli.IntFlag{Name: "port", Aliases: []string{"p"}, Usage: "Filter processes by `PORT` number (local or remote)"},
			&cli.BoolFlag{Name: "list", Aliases: []string{"l"}, Usage: "List processes"},
			&cli.BoolFlag{Name: "networks", Aliases: []string{"N"}, Usage: "Show network connections per process (default: hidden)"},
			&cli.BoolFlag{Name: "network", Aliases: []string{"n"}, Usage: "Show only processes with network connections"},
			&cli.BoolFlag{Name: "table", Aliases: []string{"t"}, Usage: "Display in table format"},
			&cli.IntFlag{Name: "last", Aliases: []string{"z"}, Usage: "Show last `N` started processes"},
			&cli.BoolFlag{Name: "desc", Usage: "Sort newest first"},
			&cli.BoolFlag{Name: "asc", Usage: "Sort oldest first (default)"},
			&cli.BoolFlag{Name: "all", Aliases: []string{"a"}, Usage: "Show all processes (no filter)"},
			&cli.BoolFlag{Name: "kill", Aliases: []string{"k"}, Usage: "Terminate matching process (use with -f, -z 1, or -p)"},
			&cli.BoolFlag{Name: "force", Usage: "Force kill all matching processes (use with -k -p)"},
			&cli.BoolFlag{Name: "no-filter-cmd", Aliases: []string{"nfc"}, Usage: "Disable filtering by command line"},
			&cli.StringSliceFlag{Name: "exception", Aliases: []string{"e"}, Usage: "Exclude processes matching `NAME/PID` — repeatable: -e chrome -e svchost"},
			&cli.BoolFlag{Name: "sort-mem", Aliases: []string{"m"}, Usage: "Sort by memory usage (RSS)"},
			&cli.BoolFlag{Name: "restart", Aliases: []string{"r"}, Usage: "Restart process (use with -f, -z 1, or -p)"},
			&cli.BoolFlag{
				Name:    "suspend",
				Aliases: []string{"sp"},
				Usage:   "Suspend (freeze) matching process(es) — use with -f, -z 1, or -p",
			},
			&cli.BoolFlag{
				Name:    "resume",
				Aliases: []string{"pp", "unsuspend"},
				Usage:   "Resume (unfreeze) matching process(es) — use with -f, -z 1, or -p",
			},

			&cli.BoolFlag{Name: "show-parent", Aliases: []string{"P"}, Usage: "Show parent process tree"},
			&cli.BoolFlag{Name: "show-child", Aliases: []string{"C"}, Usage: "Show child process tree"},
			// ── new flags ──
			&cli.IntFlag{Name: "pid", Aliases: []string{"i"}, Usage: "Show specific process by `PID`"},
			&cli.StringFlag{Name: "user", Aliases: []string{"u"}, Usage: "Filter processes by `USERNAME`"},
			&cli.Float64Flag{Name: "min-mem", Usage: "Only show processes using >= `MB` memory"},
			&cli.BoolFlag{Name: "no-tree", Usage: "Suppress parent/child tree lines"},
			&cli.IntFlag{Name: "depth", Aliases: []string{"d"}, Usage: "Limit parent/child tree `DEPTH` (0 = unlimited)"},
			&cli.BoolFlag{Name: "json", Aliases: []string{"j"}, Usage: "Output results as JSON"},
			&cli.IntFlag{Name: "watch", Aliases: []string{"w"}, Usage: "Auto-refresh every `N` seconds (watch mode)"},
			&cli.StringFlag{Name: "fields", Usage: "Comma-separated fields: name,pid,exe,mem,cmd,cpu,user,cwd,net,start_time"},
			&cli.BoolFlag{Name: "no-color", Usage: "Disable color output"},
			// ── quick-view / display mode flags ──
			&cli.BoolFlag{Name: "exe",     Usage: "Show only: index. exe_path"},
			&cli.BoolFlag{Name: "cmd",     Usage: "Show only: index. full_cmdline"},
			&cli.BoolFlag{Name: "name",    Usage: "Show only: index. name [pid]"},
			&cli.BoolFlag{Name: "mem",     Usage: "Show only: index. name (mem)  — combine with --percent for usage %"},
			&cli.BoolFlag{Name: "percent", Usage: "Modifier for --mem: show  index. name (mem | total/usage%)"},
			&cli.BoolFlag{Name: "flat",    Usage: "Flat mode: index. name [pid] (mem/cpu%) [N ports]"},
			&cli.BoolFlag{Name: "time",    Usage: "Modifier for --flat: add start_time and user to flat output"},
		},
		Action: func(c *cli.Context) error {
			noColor = c.Bool("no-color")

			filter := c.String("filter")
			portFilter := c.Int("port")
			pidFilter := int32(c.Int("pid"))
			sortDesc := c.Bool("desc")
			lastN := c.Int("last")
			killIt := c.Bool("kill")
			restartIt := c.Bool("restart")
			suspendIt := c.Bool("suspend")
			resumeIt  := c.Bool("resume")
			watchSec := c.Int("watch")
			fields := parseFields(c.String("fields"))

			doList := c.Bool("list") || c.Bool("all") || filter != "" ||
				portFilter > 0 || pidFilter > 0 || c.Bool("network") ||
				c.Bool("networks") || lastN > 0

			// -N (networks): show connections per process only when flag is passed.
			// By default connections are hidden. If --fields was also passed and
			// contains "net", that is respected as-is.
			showNets := c.Bool("networks")
			if showNets {
				if fields == nil {
					fields = map[string]bool{
						"start_time": true, "name": true, "pid": true, "exe": true,
						"mem": true, "cmd": true, "cpu": true, "user": true, "cwd": true, "net": true,
					}
				} else {
					fields["net"] = true
				}
			} else if fields == nil {
				// nil = show all fields except net (net only on -N)
				fields = map[string]bool{
					"start_time": true, "name": true, "pid": true, "exe": true,
					"mem": true, "cmd": true, "cpu": true, "user": true, "cwd": true,
				}
			} else {
				delete(fields, "net")
			}

			opts := ListOpts{
				Filter:       filter,
				PidFilter:    pidFilter,
				UserFilter:   c.String("user"),
				MinMemMB:     c.Float64("min-mem"),
				ShowNetOnly:  c.Bool("network"),
				ShowNets:     showNets,
				TableMode:    c.Bool("table"),
				JSONMode:     c.Bool("json"),
				LastN:        lastN,
				SortDesc:     sortDesc,
				NoFilterCmd:  c.Bool("no-filter-cmd"),
				SortMem:      c.Bool("sort-mem"),
				PortFilter:   portFilter,
				KillIt:       killIt && filter != "",
				RestartIt:    restartIt && filter != "",
				SuspendIt:    c.Bool("suspend") && filter != "",
				ResumeIt:     c.Bool("resume") && filter != "",
				ShowParent:   c.Bool("show-parent"),
				ShowChild:    c.Bool("show-child"),
				NoTree:       c.Bool("no-tree"),
				TreeDepth:    c.Int("depth"),
				Fields:       fields,
				Exceptions:   c.StringSlice("exception"),
				ModeExe:      c.Bool("exe"),
				ModeCmd:      c.Bool("cmd"),
				ModeName:     c.Bool("name"),
				ModeMem:      c.Bool("mem"),
				ModePercent:  c.Bool("percent"),
				ModeFlat:     c.Bool("flat"),
				ModeFlatTime: c.Bool("time"),
			}
			if c.Bool("all") {
				opts.Filter = ""
			}

			if watchSec > 0 {
				watchLoop(watchSec, opts)
				return nil
			}

			if doList {
				listProcesses(opts)
			}

			if killIt && (lastN == 1 || (portFilter > 0 && filter == "")) {
				killProcess(filter, lastN, sortDesc, portFilter, c.Bool("force"))
			}
			if restartIt && (lastN == 1 || (portFilter > 0 && filter == "")) {
				restartByFilter(filter, lastN, sortDesc, portFilter)
			}
			if suspendIt && (lastN == 1 || (portFilter > 0 && filter == "")) {
				suspendByFilter(filter, lastN, sortDesc, portFilter)
			}
			if resumeIt && (lastN == 1 || (portFilter > 0 && filter == "")) {
				resumeByFilter(filter, lastN, sortDesc, portFilter)
			}


			// if !doList && !killIt && !restartIt && watchSec == 0 {
			if !doList && !killIt && !restartIt && !suspendIt && !resumeIt && watchSec == 0 {
				cli.ShowAppHelp(c)
				color.Red.Println("\nKill (-k) / Restart (-r) only allowed with -f, -z 1, or -p")
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err))
		os.Exit(1)
	}
}
