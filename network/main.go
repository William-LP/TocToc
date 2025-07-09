package network

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/William-LP/toctoc/iptables"
)

var PortsSequence []int

func RawConnect(host string, port string) error {
	timeout := time.Second
	target := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return errors.New(err.Error())
	}
	defer conn.Close()
	return nil
}

func IsPortListening(host string, port string) (bool, error) {
	err := RawConnect(host, port)
	if err != nil {
		return false, err
	}
	return true, nil
}

func HandleConnection(ipt *iptables.Iptables, conn net.Conn) error {
	defer conn.Close()
	port, err := strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
	if err != nil {
		return err
	}
	fmt.Printf("Knock received on port %d\n", port)

	if len(PortsSequence) >= iptables.PortsSequenceLength {
		PortsSequence = PortsSequence[1:]
	}
	PortsSequence = append(PortsSequence, port)

	rules := ipt.Chain.Rules

	for _, rule := range rules {
		if slices.Equal(PortsSequence, rule.ProtectedPort.PortsSequence) {
			ipt.ToggleRule(rule)
		}
	}

	return nil
}
