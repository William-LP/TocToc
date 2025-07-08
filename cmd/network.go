package cmd

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

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

func IsPortOpen(host string, port string) (bool, error) {
	err := RawConnect(host, port)
	if err != nil {
		return false, err
	}
	return true, nil
}

func StringToPortSequence(password string, port string, count int) []int {
	hash := sha256.Sum256([]byte(password + port))
	ports := []int{}

	for i := 0; i < count && i*2+1 < len(hash); i++ {
		val := binary.BigEndian.Uint16(hash[i*2 : i*2+2])
		port := int(val)

		port = 10000 + (port % 55535)
		ports = append(ports, port)
	}

	return ports
}

func handleConnection(f *IptablesManager, conn net.Conn) error {
	defer conn.Close()
	port, err := strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
	if err != nil {
		return err
	}
	fmt.Printf("Knock on port %d\n", port)

	if len(PortsSequence) >= PortsSequenceLength {
		PortsSequence = PortsSequence[1:]
	}
	PortsSequence = append(PortsSequence, port)

	ports, err := f.ListRules()
	if err != nil {
		return err
	}
	for _, protectedPort := range ports {
		if slices.Equal(PortsSequence, protectedPort.PortsSequence) {
			if protectedPort.Status == Closed {
				err := f.OpenPort(strconv.Itoa(protectedPort.Port))
				if err != nil {
					return err
				}
				fmt.Printf("Port %v has been opened !", strconv.Itoa(protectedPort.Port))

			} else {
				rn, err := f.GetRuleNumber(strconv.Itoa(protectedPort.Port))
				fmt.Println(rn)
				if err != nil {
					return err
				}
				err = f.DropRule(rn)
				if err != nil {
					return err
				}
				fmt.Printf("Port %v has been closed !", strconv.Itoa(protectedPort.Port))

			}

		}
	}

	return nil
}
