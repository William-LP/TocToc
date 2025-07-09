package iptables

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const IptablesCustomChain string = "TOCTOC"
const PortsSequenceLength int = 16 // 16 is the maximum value

type Status string

const (
	Closed Status = "closed"
	Open   Status = "open"
)

type ProtectedPort struct {
	PortNumber    int
	PortsSequence []int
	Password      string
	Status        Status
}

type Chain struct {
	Name  string
	Rules []Rule
}

type Iptables struct {
	Chain Chain
}

type Target string

const (
	Drop   Target = "DROP"
	Accept Target = "ACCEPT"
)

type Protocol string

const (
	Tcp Protocol = "tcp"
)

type Rule struct {
	Protocol      Protocol
	ProtectedPort ProtectedPort
	Comment       string
	Target        Target
}

func NewIptables() (*Iptables, error) {

	chain := IptablesCustomChain

	chainExists := func(c string) bool {
		cmd := exec.Command("iptables", "-L", c, "-n")
		err := cmd.Run()
		return err == nil
	}(chain)

	if !chainExists {
		fmt.Printf("Creating iptables chain... ")
		createCmd := exec.Command("iptables", "-N", chain)
		if err := createCmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to create chain %s: %v", chain, err)
		}
		fmt.Printf("OK\n")
	}

	cmd := exec.Command("iptables", "-L", chain, "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %v - %s", err, output)
	}

	lines := strings.Split(string(output), "\n")
	var rules []Rule

	for _, line := range lines {
		if strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "target") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)

		target := Target(fields[0])
		proto := Protocol(fields[1])
		port, _ := strconv.Atoi(strings.TrimPrefix(fields[6], "dpt:"))
		comment := fields[8]

		seq := StringToPortSequence(comment, port, PortsSequenceLength)

		status := Closed
		if target == Accept {
			status = Open
		}

		rules = append(rules, Rule{
			Protocol: proto,
			ProtectedPort: ProtectedPort{
				PortNumber:    port,
				Password:      comment,
				PortsSequence: seq,
				Status:        status,
			},
			Comment: comment,
			Target:  target,
		})
	}

	return &Iptables{
		Chain: Chain{
			Name:  chain,
			Rules: rules,
		},
	}, nil
}

func (iptables *Iptables) AddRule(rule Rule) error {

	for _, r := range iptables.Chain.Rules {
		if r.ProtectedPort.PortNumber == rule.ProtectedPort.PortNumber {
			return fmt.Errorf("a rule for port %v already exist", rule.ProtectedPort.PortNumber)
		}
	}
	cmd := exec.Command("iptables", "-A", iptables.Chain.Name, "-p", string(Tcp), "--dport", strconv.Itoa(rule.ProtectedPort.PortNumber), "-m", "comment", "--comment", rule.Comment, "-j", string(rule.Target))
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	iptables.Chain.Rules = append(iptables.Chain.Rules, rule)
	return nil
}

func (iptables *Iptables) ListRules() []Rule {
	return iptables.Chain.Rules
}

func (iptables *Iptables) RemoveRule(portNumber int) error {
	var rulesToRemove []Rule

	// Collect rules matching the given port
	for _, r := range iptables.Chain.Rules {
		if r.ProtectedPort.PortNumber == portNumber {
			rulesToRemove = append(rulesToRemove, r)
		}
	}

	if len(rulesToRemove) == 0 {
		return fmt.Errorf("no rule for port %v found", portNumber)
	}

	// Delete the matching rules via iptables command
	for _, rule := range rulesToRemove {
		cmd := exec.Command(
			"iptables",
			"-D", iptables.Chain.Name,
			"-p", string(rule.Protocol),
			"--dport", strconv.Itoa(rule.ProtectedPort.PortNumber),
			"-m", "comment",
			"--comment", rule.Comment,
			"-j", string(rule.Target),
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to delete rule for port %d: %v - output: %s", portNumber, err, output)
		}
	}

	// Remove rules from in-memory slice
	var updatedRules []Rule
	for _, r := range iptables.Chain.Rules {
		if r.ProtectedPort.PortNumber != portNumber {
			updatedRules = append(updatedRules, r)
		}
	}
	iptables.Chain.Rules = updatedRules

	return nil
}

func (iptables *Iptables) ToggleRule(rule Rule) error {

	newTargetRule := Drop
	newPortStatus := Closed
	if rule.Target == Drop {
		newTargetRule = Accept
		newPortStatus = Open
	}

	if err := iptables.RemoveRule(rule.ProtectedPort.PortNumber); err != nil {
		return err
	}

	if err := iptables.AddRule(Rule{
		Protocol: Tcp,
		Comment:  rule.Comment,
		Target:   newTargetRule,
		ProtectedPort: ProtectedPort{
			PortNumber:    rule.ProtectedPort.PortNumber,
			PortsSequence: rule.ProtectedPort.PortsSequence,
			Password:      rule.ProtectedPort.Password,
			Status:        newPortStatus,
		},
	}); err != nil {
		return err
	}

	fmt.Printf("Port %d has been %v\n", rule.ProtectedPort.PortNumber, newPortStatus)

	return nil
}

func StringToPortSequence(password string, port int, count int) []int {
	hash := sha256.Sum256([]byte(password + strconv.Itoa(port)))
	ports := []int{}

	for i := 0; i < count && i*2+1 < len(hash); i++ {
		val := binary.BigEndian.Uint16(hash[i*2 : i*2+2])
		port := int(val)

		// we want to generate random ports in the range of 10000 - 65535
		port = 10000 + (port % 55535)
		ports = append(ports, port)
	}

	return ports
}
