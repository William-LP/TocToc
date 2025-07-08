package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const ChainName string = "TOCTOC"
const PortsSequenceLength int = 16 // maximum value

type Status string

const (
	Closed Status = "closed"
	Open   Status = "open"
)

type ProtectedPort struct {
	Port          int
	Password      string
	PortsSequence []int
	Status        Status
}

var iptablesManager = IptablesManager{
	ChainName: "TOCTOC",
}

func Check(host string, port string) string {
	res, err := IsPortOpen(host, port)
	if res {
		return fmt.Sprintf("Successfully connected to %s:%s\n", host, port)
	}
	return fmt.Sprintf("Failed to connect to %s:%s: %v\n", host, port, err)

}

func ProtectPort(port string, password string) string {
	res := iptablesManager.CheckRuleExists(port)

	seq := StringToPortSequence(password, port, PortsSequenceLength)
	fmt.Println(seq)

	if res {
		return "Port is already protected by TocToc"
	}
	err := iptablesManager.AddRule(port, password)
	if err != nil {
		return fmt.Sprintf("Couldn't protect the port %s - %v", port, err)
	}
	return fmt.Sprintf("Port %v is now protected", port)
}

func UnprotectPort(port string) string {
	res := iptablesManager.CheckRuleExists(port)
	if !res {
		return "Port is not protected by TocToc"
	}
	rule, err := iptablesManager.GetRuleNumber(port)
	if err != nil {
		return fmt.Sprintf("Couldn't find the rule - %v", err)
	}
	err = iptablesManager.DropRule(rule)
	if err != nil {
		return fmt.Sprintf("Couldn't drole the rule %s - %v", port, err)
	}
	return fmt.Sprintf("Port %v is now unprotected", port)
}

func Install() string {
	if iptablesManager.CheckChainExist() {
		fmt.Printf("iptables chain already exists\n")
	} else {
		err := iptablesManager.CreateChain()
		if err != nil {
			fmt.Printf("Couldn't create iptables chain %s - %v", iptablesManager.ChainName, err)
		}
	}

	err := Daemonize()
	if err != nil {
		fmt.Printf("Couldn't daemonize TocToc - %v", err)
	}
	return "OK"
}

func List() string {
	res, err := iptablesManager.ListRules()
	if err != nil {
		return fmt.Sprintf("Couldn't list rules %v", err)
	}

	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "Port\tStatus\tPassword\tPorts Sequence")
	fmt.Fprintln(w, "----\t--------\t--------\t-------------------------------------------------------------")

	for _, r := range res {
		fmt.Fprintf(w, "%d\t%v\t%s\t%v\n", r.Port, r.Status, r.Password, r.PortsSequence)
	}

	w.Flush()

	return sb.String()
}

func Knock(host string, protectedPort string, password string) string {

	pseq := StringToPortSequence(password, protectedPort, PortsSequenceLength)
	for _, port := range pseq {
		fmt.Printf("Knock on %s:%d...\n", host, port)
		err := RawConnect(host, strconv.Itoa(port))
		if err != nil {
			return fmt.Sprintf("Failed sending knock to %s:%d: %v\n", host, port, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "Port sequence has been sent. The remote port has been toggled."
}
