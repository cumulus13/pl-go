package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

// ─── terminal width ────────────────────────────────────────────────────────────

func termWidth() int {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 {
		return 120
	}
	return int(ws.Col)
}

// ─── text wrap ────────────────────────────────────────────────────────────────

func wrapText(text, prefix string) string {
	maxWidth := termWidth()
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

// ─── global no-color flag ─────────────────────────────────────────────────────

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
func rUserBadge(s string) string { return cHexB("#00AAFF", s) }
func rRunning(ok bool) string {
	if ok {
		return cHexB("#FFFF00", "(running)")
	}
	return cBg("#FFFFFF", "#FF0000", "???")
}
func rNameVal(s string) string { return cHexB("#00AAFF", s) }
func rPidVal(s string) string  { return cBg("#FFFFFF", "#550000", s) }
func rExeVal(s string) string  { return cHexB("#AAAA7F", s) }
func rMemVal(s string) string  { return cBg("#FFFFFF", "#00007F", s) }
func rCmdVal(s string) string  { return cHexB("#00FFFF", s) }
func rCpuVal(s string) string  { return cHexB("#0000FF", s) }
func rUserVal(s string) string { return cHexB("#5555FF", s) }
func rCwdVal(s string) string  { return cHexB("#FFAA7F", s) }
func rCounter(s string) string { return cHexB("#55FF00", s) }
func rParentLabel() string     { return cHexB("#FF00FF", "PARENT:") }
func rChildLabel() string      { return cHexB("#00FF00", "CHILD:") }

// ─── network connections ───────────────────────────────────────────────────────

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

func hexToIPv4(h string) string {
	n, _ := strconv.ParseUint(h, 16, 32)
	return fmt.Sprintf("%d.%d.%d.%d", n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING", "00": "NONE",
}

func getConnections(pid int32) []NetConn {
	inodeToFd := map[string]string{}
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	if entries, err := os.ReadDir(fdDir); err == nil {
		for _, e := range entries {
			link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				inodeToFd[inode] = e.Name()
			}
		}
	}
	var results []NetConn
	for _, proto := range []string{"tcp", "udp", "tcp6", "udp6"} {
		f, err := os.Open(fmt.Sprintf("/proc/net/%s", proto))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			inode := fields[9]
			fd, ok := inodeToFd[inode]
			if !ok {
				continue
			}
			lp := strings.Split(fields[1], ":")
			rp := strings.Split(fields[2], ":")
			if len(lp) < 2 || len(rp) < 2 {
				continue
			}
			state := strings.ToUpper(fields[3])
			stateStr, ok2 := tcpStates[state]
			if !ok2 {
				stateStr = state
			}
			family := "AF_INET"
			if strings.HasSuffix(proto, "6") {
				family = "AF_INET6"
			}
			connType := "TCP"
			if strings.HasPrefix(proto, "udp") {
				connType = "UDP"
			}
			lIP := hexToIPv4(lp[0])
			rIP := hexToIPv4(rp[0])
			lPort, _ := strconv.ParseUint(lp[1], 16, 32)
			rPort, _ := strconv.ParseUint(rp[1], 16, 32)
			results = append(results, NetConn{
				Fd: fd, Family: family, Type: connType,
				Laddr: lIP, Lport: int(lPort),
				Raddr: rIP, Rport: int(rPort),
				Status: stateStr,
			})
		}
		f.Close()
	}
	return results
}

func checkPort(pid int32, port int) bool {
	for _, c := range getConnections(pid) {
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
	laddr := cBg("#FFFFFF", "#005500", fmt.Sprintf("%s:%d", c.Laddr, c.Lport))
	raddr := cBg("#AAFFFF", "#AA0000", fmt.Sprintf("%s:%d", c.Raddr, c.Rport))
	return fmt.Sprintf("%s%s %s [local=%s] [remote=%s] (fd:%s, type:%s, family:%s) | STATUS: %s",
		indent, chr, netIcon, laddr, raddr, c.Fd, typeStr, c.Family, statusStr)
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
}

func gather(p *process.Process) (*ProcInfo, error) {
	mem, err := p.MemoryInfo()
	if err != nil {
		return nil, err
	}
	name, _ := p.Name()
	exe, _ := p.Exe()
	cmd, _ := p.Cmdline()
	cwd, _ := p.Cwd()
	user, _ := p.Username()
	cpu, _ := p.CPUPercent()
	running, _ := p.IsRunning()
	ct, _ := p.CreateTime()
	return &ProcInfo{
		Pid: p.Pid, Name: name, Exe: exe, Cmd: cmd,
		Cwd: cwd, User: user,
		MemMB:     float64(mem.RSS) / 1024 / 1024,
		CPU:       cpu, Running: running,
		StartTime: fmtTime(ct),
		Conns:     getConnections(p.Pid),
	}, nil
}

func fmtTime(ms int64) string {
	return time.Unix(ms/1000, 0).Format("06/01/02 15:04:05")
}

// fieldEnabled returns true if the field is in the allowed set (or set is empty = all).
func fieldEnabled(fields map[string]bool, name string) bool {
	if len(fields) == 0 {
		return true
	}
	return fields[strings.ToLower(name)]
}

// renderBlock builds the coloured info block for one process.
func renderBlock(info *ProcInfo, prefix, detailPrefix string, fields map[string]bool) string {
	var sb strings.Builder

	// header line always shown
	sb.WriteString(fmt.Sprintf("%s%s [%s] %s %s %s\n",
		prefix,
		rName(info.Name), rPidBadge(fmt.Sprintf("%d", info.Pid)),
		rMemBadge(fmt.Sprintf("%.2f MB", info.MemMB)),
		rUserBadge(info.User), rRunning(info.Running),
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

func getChildren(pid int32, all []*process.Process, depth int) []*process.Process {
	if depth == 0 {
		return nil
	}
	var out []*process.Process
	for _, p := range all {
		ppid, err := p.Ppid()
		if err == nil && ppid == pid {
			out = append(out, p)
		}
	}
	return out
}

func renderTree(procs []*process.Process, netOnly bool, baseIndent string, fields map[string]bool, depth, maxDepth int, all []*process.Process) {
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

		// recurse into children of this tree node
		if all != nil {
			grandChildren := getChildren(p.Pid, all, maxDepth-depth)
			if len(grandChildren) > 0 {
				renderTree(grandChildren, netOnly, baseIndent+detailChar, fields, depth+1, maxDepth, all)
			}
		}
	}
}

// ─── no-process banner ────────────────────────────────────────────────────────

func printNoProcess() {
	colors := []string{
		"#FF0000", "#00FF00", "#0000FF", "#FFFF00", "#FF00FF", "#00FFFF",
		"#FF5555", "#55FF55", "#5555FF", "#FFFF55", "#FF55FF", "#55FFFF",
	}
	fmt.Println()
	fmt.Print("😞 🚯 😵 😂 🎸 🎵️ ⛔ ☣️ 🔜 ")
	for _, ch := range "N-O  P-R-O-C-E-S-S  F-O-U-N-D" {
		if ch != ' ' {
			fmt.Print(color.HEX(colors[rand.Intn(len(colors))], true).Sprint(string(ch)))
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

// ─── list options ─────────────────────────────────────────────────────────────

type ListOpts struct {
	Filter      string
	PidFilter   int32
	UserFilter  string
	MinMemMB    float64
	ShowNetOnly bool
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
}

// ─── list processes ───────────────────────────────────────────────────────────

func listProcesses(opts ListOpts) {
	selfPid := int32(os.Getpid())
	allProcs, err := process.Processes()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error listing processes:", err)
		return
	}

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

	// pid filter (direct PID lookup)
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
			pidStr := fmt.Sprintf("%d", p.Pid)
			nameMatch := strings.Contains(strings.ToLower(name), fl)
			pidMatch := strings.Contains(pidStr, fl)
			cmdMatch := !opts.NoFilterCmd && strings.Contains(strings.ToLower(cmd), fl)
			if !nameMatch && !pidMatch && !cmdMatch {
				continue
			}
		}

		// user filter
		if opts.UserFilter != "" && !strings.EqualFold(user, opts.UserFilter) {
			continue
		}

		info, err := gather(p)
		if err != nil {
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
				children = getChildren(p.Pid, allProcs, opts.TreeDepth)
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
		}
	}

	// JSON output
	if opts.JSONMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(jsonOut)
		return
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
		// clear screen
		fmt.Print("\033[H\033[2J")
		fmt.Printf("%s  %s  interval: %ds  press Ctrl+C to exit\n\n",
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
	allProcs, _ := process.Processes()
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
	cmd, _ := p.Cmdline()
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		color.Red.Printf("Cannot restart %s: no command line available.\n", n)
		return
	}
	color.Cyan.Printf("Process: %s (PID %d)\nCommand: %s\n\n", n, p.Pid, cmd)
	if err := p.Terminate(); err != nil {
		color.Red.Printf("✗ Failed to terminate: %v\n", err)
		return
	}
	time.Sleep(1 * time.Second)
	color.Green.Println("✓ Process terminated")
	newCmd := exec.Command(parts[0], parts[1:]...)
	newCmd.Stdout = os.Stdout
	newCmd.Stderr = os.Stderr
	if err := newCmd.Start(); err != nil {
		color.Red.Printf("✗ Failed to restart: %v\n", err)
		return
	}
	color.Green.Printf("✓ Process restarted with new PID: %d\n", newCmd.Process.Pid)
}

func restartByFilter(filter string, lastN int, sortDesc bool, portFilter int) {
	allProcs, _ := process.Processes()
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
			color.Red.Printf("Multiple processes found using port %d. Please be more specific.\n", portFilter)
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

// ─── parse fields flag ────────────────────────────────────────────────────────

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
		Version: "7.1.0",
		Authors: []*cli.Author{
			{Name: "Hadi Cahyadi", Email: "cumulus13@gmail.com"},
		},
		Description: cHexB("#00AAFF", "Fast, colorful process inspector — network, parent/child tree, kill, restart, watch & JSON."),
		Flags: []cli.Flag{
			// ── original flags (all preserved) ──
			&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Filter by process `NAME`, PID, or cmdline"},
			&cli.IntFlag{Name: "port", Aliases: []string{"p"}, Usage: "Filter processes by `PORT` number (local or remote)"},
			&cli.BoolFlag{Name: "list", Aliases: []string{"l"}, Usage: "List processes"},
			&cli.BoolFlag{Name: "networks", Aliases: []string{"N"}, Usage: "Show network connections for each process"},
			&cli.BoolFlag{Name: "network", Aliases: []string{"n"}, Usage: "Show only processes with network connections"},
			&cli.BoolFlag{Name: "table", Aliases: []string{"t"}, Usage: "Display in table format"},
			&cli.IntFlag{Name: "last", Aliases: []string{"z"}, Usage: "Show last `N` started processes"},
			&cli.BoolFlag{Name: "desc", Usage: "Sort newest first"},
			&cli.BoolFlag{Name: "asc", Usage: "Sort oldest first (default)"},
			&cli.BoolFlag{Name: "all", Aliases: []string{"a"}, Usage: "Show all processes (no filter)"},
			&cli.BoolFlag{Name: "kill", Aliases: []string{"k"}, Usage: "Terminate matching process (use with -f, -z 1, or -p)"},
			&cli.BoolFlag{Name: "force", Usage: "Force kill all matching processes (use with -k -p)"},
			&cli.BoolFlag{Name: "no-filter-cmd", Aliases: []string{"nfc"}, Usage: "Disable filtering by command line"},
			&cli.BoolFlag{Name: "sort-mem", Aliases: []string{"m"}, Usage: "Sort by memory usage (RSS)"},
			&cli.BoolFlag{Name: "restart", Aliases: []string{"r"}, Usage: "Restart process (use with -f, -z 1, or -p)"},
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
			&cli.StringFlag{Name: "fields", Usage: "Comma-separated fields to show: name,pid,exe,mem,cmd,cpu,user,cwd,net,start_time"},
			&cli.BoolFlag{Name: "no-color", Usage: "Disable color output"},
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
			watchSec := c.Int("watch")
			fields := parseFields(c.String("fields"))

			doList := c.Bool("list") || c.Bool("all") || filter != "" ||
				portFilter > 0 || pidFilter > 0 || c.Bool("network") ||
				c.Bool("networks") || c.Int("last") > 0

			opts := ListOpts{
				Filter:      filter,
				PidFilter:   pidFilter,
				UserFilter:  c.String("user"),
				MinMemMB:    c.Float64("min-mem"),
				ShowNetOnly: c.Bool("network"),
				TableMode:   c.Bool("table"),
				JSONMode:    c.Bool("json"),
				LastN:       lastN,
				SortDesc:    sortDesc,
				NoFilterCmd: c.Bool("no-filter-cmd"),
				SortMem:     c.Bool("sort-mem"),
				PortFilter:  portFilter,
				KillIt:      killIt && filter != "",
				RestartIt:   restartIt && filter != "",
				ShowParent:  c.Bool("show-parent"),
				ShowChild:   c.Bool("show-child"),
				NoTree:      c.Bool("no-tree"),
				TreeDepth:   c.Int("depth"),
				Fields:      fields,
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

			if !doList && !killIt && !restartIt && watchSec == 0 {
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
