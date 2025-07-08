package cmd

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

const systemdPath string = "/etc/systemd/system/toctocd.service"
const serviceFile string = "./toctocd.service"
const periodPollingDelayInSeconds int = 10

var PortsSequence []int

func Daemonize() error {

	srcFile, err := os.Open(serviceFile)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.CreateTemp("", "toctocd-copy.service")
	if err != nil {
		return err
	}
	defer os.Remove(dstFile.Name())
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	cmd := exec.Command("cp", dstFile.Name(), systemdPath)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	err = CopySelf("/usr/local/bin/toctocd")
	if err != nil {
		log.Fatalf("Failed to install binary: %v", err)
	}

	cmd = exec.Command("systemctl", "daemon-reload")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	cmd = exec.Command("systemctl", "enable", "toctocd.service")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	cmd = exec.Command("systemctl", "start", "toctocd.service")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	return nil
}

func CopySelf(destination string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find executable path: %w", err)
	}

	dst, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	src, err := os.Open(execPath)
	if err != nil {
		return fmt.Errorf("failed to open source binary: %w", err)
	}
	defer src.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	err = os.Chmod(destination, 0755)
	if err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}

func RunAsDaemon(f *IptablesManager) error {
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
				go handleConnection(f, conn)
			}
		}()
	}

	// Initial load
	ports, err := f.ListRules()
	if err != nil {
		return err
	}
	for _, protectedPort := range ports {
		for _, port := range protectedPort.PortsSequence {
			startListener(port)
		}
	}

	go func() {
		ticker := time.NewTicker(time.Duration(periodPollingDelayInSeconds) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			ports, err := f.ListRules()
			if err != nil {
				fmt.Printf("Failed to list rules: %v\n", err)
				continue
			}

			current := make(map[int]bool)
			for _, protectedPort := range ports {
				for _, port := range protectedPort.PortsSequence {
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

			for _, protectedPort := range ports {
				for _, port := range protectedPort.PortsSequence {
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
