package protect

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/iocs"
	"github.com/FaheemRafiq/pushwarden/internal/platform"
	"github.com/FaheemRafiq/pushwarden/internal/ui"
)

const (
	chain    = "PUSHWARDEN_C2"
	pfAnchor = "com.pushwarden.c2"
	hostsBeg = "# BEGIN PUSHWARDEN C2 SINKHOLE"
	hostsEnd = "# END PUSHWARDEN C2 SINKHOLE"
	winRule  = "PushWarden C2 block"
)

type NetBlocker struct {
	P  *platform.Info
	I  *iocs.IOCs
	UI *ui.UI
	// SysDir overrides the root-owned state directory (tests); see SystemDir.
	SysDir string
	mode   string // firewall backend used by the last BlockIPs
}

func (n *NetBlocker) say(m string) {
	if n.UI != nil {
		n.UI.Info(m)
	}
}

func (n *NetBlocker) sh(name string, args ...string) (int, string, string) {
	return n.P.RunRC(30*time.Second, name, args...)
}

func have(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

func (n *NetBlocker) BlockIPs() bool {
	ips := n.I.MaliciousIPs
	switch {
	case n.P.IsLinux():
		if !have("iptables") && have("nft") {
			n.sh("nft", "add", "table", "inet", "pushwarden")
			n.sh("nft", "add", "chain", "inet", "pushwarden", "out", "{ type filter hook output priority 0 ; }")
			n.sh("nft", "flush", "chain", "inet", "pushwarden", "out")
			n.sh("nft", "add", "rule", "inet", "pushwarden", "out", "ip", "daddr", "{ "+strings.Join(ips, ", ")+" }", "drop")
			n.mode = "nftables"
			n.say(fmt.Sprintf("nftables: dropped outbound traffic to %d C2 IPs (table inet pushwarden)", len(ips)))
			return true
		}
		if !have("iptables") {
			n.say("Neither iptables nor nft found; cannot block at the firewall.")
			return false
		}
		n.sh("iptables", "-N", chain)
		n.sh("iptables", "-F", chain)
		for _, ip := range ips {
			n.sh("iptables", "-A", chain, "-d", ip, "-j", "DROP")
		}
		if rc, _, _ := n.sh("iptables", "-C", "OUTPUT", "-j", chain); rc != 0 {
			if rc, _, se := n.sh("iptables", "-I", "OUTPUT", "1", "-j", chain); rc != 0 {
				n.say("iptables failed: " + strings.TrimSpace(se))
				return false
			}
		}
		n.mode = "iptables"
		n.say(fmt.Sprintf("iptables: chain %s drops outbound traffic to %d C2 IPs", chain, len(ips)))
		return true
	case n.P.IsMac():
		var rules strings.Builder
		for _, ip := range ips {
			rules.WriteString("block drop out quick to " + ip + "\n")
		}
		af := "/etc/pf.anchors/" + pfAnchor
		if err := os.WriteFile(af, []byte(rules.String()), 0o644); err != nil {
			n.say("Need root: sudo pushwarden protect --install")
			return false
		}
		conf, _ := os.ReadFile("/etc/pf.conf")
		if !strings.Contains(string(conf), pfAnchor) {
			add := fmt.Sprintf("\nanchor \"%s\"\nload anchor \"%s\" from \"%s\"\n", pfAnchor, pfAnchor, af)
			_ = os.WriteFile("/etc/pf.conf", []byte(strings.TrimRight(string(conf), "\n")+add), 0o644)
		}
		n.sh("pfctl", "-a", pfAnchor, "-f", af)
		n.sh("pfctl", "-e")
		n.mode = "pf"
		n.say(fmt.Sprintf("pf: anchor %s blocks %d C2 IPs", pfAnchor, len(ips)))
		return true
	case n.P.IsWindows():
		n.sh("netsh", "advfirewall", "firewall", "delete", "rule", "name="+winRule)
		rc, _, se := n.sh("netsh", "advfirewall", "firewall", "add", "rule", "name="+winRule, "dir=out", "action=block", "remoteip="+strings.Join(ips, ","))
		if rc != 0 {
			n.say("netsh failed (run as Administrator): " + strings.TrimSpace(se))
			return false
		}
		n.mode = "windows-firewall"
		n.say(fmt.Sprintf("Windows Firewall: '%s' blocks %d C2 IPs", winRule, len(ips)))
		return true
	}
	return false
}

func (n *NetBlocker) UnblockIPs() {
	switch {
	case n.P.IsLinux():
		n.sh("iptables", "-D", "OUTPUT", "-j", chain)
		n.sh("iptables", "-F", chain)
		n.sh("iptables", "-X", chain)
		n.sh("nft", "delete", "table", "inet", "pushwarden")
	case n.P.IsMac():
		n.sh("pfctl", "-a", pfAnchor, "-F", "all")
	case n.P.IsWindows():
		n.sh("netsh", "advfirewall", "firewall", "delete", "rule", "name="+winRule)
	}
	n.say("Firewall rules removed")
}

func (n *NetBlocker) Status() string {
	switch {
	case n.P.IsLinux():
		if rc, out, _ := n.sh("iptables", "-S", chain); rc == 0 && strings.TrimSpace(out) != "" {
			return fmt.Sprintf("iptables chain %s: %d drop rules", chain, strings.Count(out, "-j DROP"))
		}
		if rc, _, _ := n.sh("nft", "list", "table", "inet", "pushwarden"); rc == 0 {
			return "nftables table active"
		}
	case n.P.IsMac():
		if rc, out, _ := n.sh("pfctl", "-a", pfAnchor, "-sr"); rc == 0 && strings.TrimSpace(out) != "" {
			return fmt.Sprintf("pf: %d rules", strings.Count(out, "block"))
		}
	case n.P.IsWindows():
		if rc, out, _ := n.sh("netsh", "advfirewall", "firewall", "show", "rule", "name="+winRule); rc == 0 && strings.Contains(out, winRule) {
			return "Windows Firewall rule active"
		}
	}
	return "not active"
}

var blockRe = regexp.MustCompile(`(?s)\n*` + regexp.QuoteMeta(hostsBeg) + `.*?` + regexp.QuoteMeta(hostsEnd) + `\n?`)

func (n *NetBlocker) SinkholeHosts() bool {
	hf := n.P.HostsFile()
	b, err := os.ReadFile(hf)
	if err != nil {
		n.say("Cannot read " + hf)
		return false
	}
	content := blockRe.ReplaceAllString(string(b), "\n")
	var blk strings.Builder
	blk.WriteString(hostsBeg + "\n")
	for _, x := range n.I.MaliciousHosts {
		blk.WriteString("0.0.0.0 " + x + "\n")
	}
	blk.WriteString(hostsEnd + "\n")
	if err := os.WriteFile(hf, []byte(strings.TrimRight(content, "\n")+"\n\n"+blk.String()), 0o644); err != nil {
		n.say("Need root/Administrator to edit the hosts file.")
		return false
	}
	n.say(fmt.Sprintf("hosts: sinkholed %d C2 hostnames", len(n.I.MaliciousHosts)))
	return true
}

func (n *NetBlocker) UnsinkholeHosts() {
	hf := n.P.HostsFile()
	if b, err := os.ReadFile(hf); err == nil {
		if os.WriteFile(hf, []byte(blockRe.ReplaceAllString(string(b), "\n")), 0o644) == nil {
			n.say("hosts sinkhole removed")
		}
	}
}
