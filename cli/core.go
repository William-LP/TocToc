package cli

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/William-LP/toctoc/daemon"
	"github.com/William-LP/toctoc/iptables"
	"github.com/William-LP/toctoc/network"
)

func Check(host string, port string) {
	res, err := network.IsPortListening(host, port)
	if res {
		fmt.Printf("Successfully connected to %s:%s\n", host, port)
	} else {
		fmt.Printf("Failed to connect to %s:%s: %v\n", host, port, err)
	}

}

func ProtectPort(port string, password string) {
	ipt, err := iptables.NewIptables()
	if err != nil {
		fmt.Printf("could not work with iptables - %v\n", err)
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		fmt.Printf("port should be a valid integer - %v\n", err)
		return
	}

	if err := ipt.AddRule(iptables.Rule{
		Protocol: iptables.Tcp,
		Target:   iptables.Drop,
		Comment:  password,
		ProtectedPort: iptables.ProtectedPort{
			PortNumber:    p,
			Password:      password,
			PortsSequence: iptables.StringToPortSequence(password, p, iptables.PortsSequenceLength),
		},
	}); err != nil {
		fmt.Printf("rule could not be created - %v\n", err)
		return
	}
	fmt.Printf("Port %v is now protected\n", port)
}

func UnprotectPort(port string) {
	ipt, err := iptables.NewIptables()
	if err != nil {
		fmt.Printf("could not work with iptables - %v\n", err)
		return
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		fmt.Printf("port should be a valid integer - %v\n", err)
		return
	}

	if err := ipt.RemoveRule(p); err != nil {
		fmt.Printf("rule could not be removed - %v\n", err)
		return
	}
	fmt.Printf("Port %v is no more protected\n", port)
}

func Install() {
	if _, err := iptables.NewIptables(); err != nil {
		panic(err)
	}
	if err := daemon.Daemonize(); err != nil {
		panic(err)
	}
}

func List() {
	ipt, err := iptables.NewIptables()
	if err != nil {
		fmt.Printf("could not work with iptables - %v\n", err)
		return
	}
	rules := ipt.ListRules()

	portMap := make(map[int]iptables.ProtectedPort)

	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "Port\tStatus\tPassword\tPorts Sequence")
	fmt.Fprintln(w, "----\t--------\t--------\t-----------------------------------------------------------------------------------------------")

	for _, r := range rules {
		existing, exists := portMap[r.ProtectedPort.PortNumber]
		if !exists {
			portMap[r.ProtectedPort.PortNumber] = r.ProtectedPort
		} else {
			password := r.ProtectedPort.Password

			status := existing.Status
			if r.ProtectedPort.Status == iptables.Open {
				status = iptables.Open
			}

			portMap[r.ProtectedPort.PortNumber] = iptables.ProtectedPort{
				PortNumber:    r.ProtectedPort.PortNumber,
				PortsSequence: r.ProtectedPort.PortsSequence,
				Password:      password,
				Status:        status,
			}
		}
	}

	for _, p := range portMap {
		var seq []string
		for _, port := range p.PortsSequence {
			seq = append(seq, fmt.Sprintf("%d", port))
		}
		fmt.Fprintf(w, "%d\t%v\t%s\t%v\n", p.PortNumber, p.Status, p.Password, strings.Join(seq, ","))
	}

	w.Flush()
	fmt.Print(sb.String())
}

func Knock(host string, protectedPort string, password string) {

	port, err := strconv.Atoi(protectedPort)
	if err != nil {
		fmt.Printf("port should be a valid integer\n")
		return
	}

	pseq := iptables.StringToPortSequence(password, port, iptables.PortsSequenceLength)

	fmt.Println(pseq)

	for _, p := range pseq {
		fmt.Printf("Knock on %s:%d...\n", host, p)
		if err := network.RawConnect(host, strconv.Itoa(p)); err != nil {
			fmt.Printf("Failed sending knock to %s:%d: %v\n", host, p, err)
			return
		}

		time.Sleep(500 * time.Millisecond)
	}
	fmt.Printf("Port sequence has been sent. The remote port has been toggled.\n")
}

func RunServerAgent() string {
	ipt, err := iptables.NewIptables()
	if err != nil {
		return fmt.Sprintf("could not work with iptables - %v\n", err)
	}

	listeners := make(map[int]net.Listener)
	var mu sync.Mutex

	startListener := func(port int) {
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			fmt.Printf("Failed to listen on port %d: %v\n", port, err)
			return
		}
		fmt.Printf("Started listening on port %d\n", port)

		mu.Lock()
		listeners[port] = ln
		mu.Unlock()

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go network.HandleConnection(ipt, conn)
			}
		}()
	}

	rules := ipt.Chain.Rules

	for _, rule := range rules {
		for _, port := range rule.ProtectedPort.PortsSequence {
			startListener(port)
		}
	}

	go func() {
		ticker := time.NewTicker(time.Duration(daemon.PeriodPollingDelayInSeconds) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			iptUpdated, err := iptables.NewIptables()
			if err != nil {
				fmt.Printf("could not refresh iptables rules - %v\n", err)
				continue
			}
			rules := iptUpdated.Chain.Rules

			current := make(map[int]bool)
			for _, rule := range rules {
				for _, port := range rule.ProtectedPort.PortsSequence {
					current[port] = true
				}
			}

			mu.Lock()
			for port := range listeners {
				if !current[port] {
					ln := listeners[port]
					ln.Close()
					delete(listeners, port)
					fmt.Printf("Stopped listening on port %d\n", port)
				}
			}
			mu.Unlock()

			for _, rule := range rules {
				for _, port := range rule.ProtectedPort.PortsSequence {
					mu.Lock()
					_, exists := listeners[port]
					mu.Unlock()
					if !exists {
						startListener(port)
					}

				}

			}
		}
	}()

	select {}

}
