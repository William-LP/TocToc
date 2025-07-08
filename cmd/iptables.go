package cmd

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type IptablesManager struct {
	ChainName string
}

func (f *IptablesManager) CheckChainExist() bool {
	cmd := exec.Command("iptables", "-L", f.ChainName, "-n")
	_, err := cmd.CombinedOutput()
	return err == nil
}

func (f *IptablesManager) CreateChain() error {
	cmd := exec.Command("iptables", "-N", f.ChainName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating chain: %v - %s", err, string(output))
	}
	return nil
}

func (f *IptablesManager) DeleteChain() error {
	cmd := exec.Command("iptables", "-X", f.ChainName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting chain: %v - %s", err, string(output))
	}
	return nil
}

func (f *IptablesManager) CheckRuleExists(port string) bool {
	cmd := exec.Command("sh", "-c", "iptables -S "+f.ChainName+" | grep "+port)
	_, err := cmd.CombinedOutput()
	return err == nil
}

func (f *IptablesManager) GetRuleNumber(port string) (string, error) {
	cmd := exec.Command("sh", "-c", "iptables -L "+f.ChainName+" --line-numbers -n | grep "+port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error finding rule: %v - %s", err, string(output)), err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			return fields[0], nil // line number is the first field
		}
	}
	return "", fmt.Errorf("no rule found for port %s", port)
}

func (f *IptablesManager) DropRule(ruleNumber string) error {
	cmd := exec.Command("iptables", "-D", f.ChainName, ruleNumber)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error droping the rule: %v - %s", err, string(output))
	}
	return nil
}

func (f *IptablesManager) AddRule(port string, password string) error {
	cmd := exec.Command("iptables", "-A", f.ChainName, "-p", "tcp", "--dport", port, "-m", "comment", "--comment", password, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error closing port: %v - %s", err, string(output))
	}
	return nil
}
func (f *IptablesManager) ListRules() ([]ProtectedPort, error) {
	cmd := exec.Command("iptables", "-L", f.ChainName, "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error listing rules: %v - %s", err, string(output))
	}

	lines := strings.Split(string(output), "\n")
	portMap := make(map[int]ProtectedPort)

	for _, line := range lines {
		if strings.HasPrefix(line, "target") || strings.HasPrefix(line, "Chain") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		portStr := strings.TrimPrefix(fields[6], "dpt:")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		password := fields[8]
		target := fields[0]

		status := Closed
		if target == "ACCEPT" {
			status = Open
		}

		existing, ok := portMap[port]
		if !ok {
			portMap[port] = ProtectedPort{
				Port:          port,
				Password:      password,
				Status:        status,
				PortsSequence: StringToPortSequence(password, strconv.Itoa(port), PortsSequenceLength),
			}
		}
		if existing.Status == Open {
			portMap[port] = ProtectedPort{
				Port:          portMap[port].Port,
				Password:      password,
				Status:        portMap[port].Status,
				PortsSequence: StringToPortSequence(password, strconv.Itoa(port), PortsSequenceLength),
			}
		}
	}

	var results []ProtectedPort
	for _, v := range portMap {
		results = append(results, v)
	}
	return results, nil
}

func (f *IptablesManager) OpenPort(port string) error {
	cmd := exec.Command("iptables", "-I", f.ChainName, "1", "-p", "tcp", "--dport", port, "-m", "comment", "--comment", "HasBeenKnockedOpen", "-j", "ACCEPT")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error opening port: %v - %s", err, string(output))
	}
	return nil
}
