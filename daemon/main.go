package daemon

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

const systemdPath string = "/etc/systemd/system/toctocd.service"
const PeriodPollingDelayInSeconds int = 10

var PortsSequence []int

func Daemonize() error {

	templateString := `
[Unit]
Description=TocToc - Port Knocking Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/toctoc daemon
Restart=always
User=root

[Install]
WantedBy=multi-user.target
`

	if _, err := os.Stat(systemdPath); err == nil {
		fmt.Printf("Systemd service file already exists at %s. Skipping creation.\n", systemdPath)
	} else if os.IsNotExist(err) {
		err = os.WriteFile(systemdPath, []byte(templateString), 0644)
		if err != nil {
			return fmt.Errorf("failed to write systemd file: %w", err)
		}
		fmt.Printf("Systemd service file written to %s... OK\n", systemdPath)
	} else {
		return fmt.Errorf("could not check systemd path: %w", err)
	}

	binPath := "/usr/local/bin/toctoc"
	if _, err := os.Stat(binPath); err == nil {
		fmt.Printf("Binary already exists at %s. Skipping copy.\n", binPath)
	} else if os.IsNotExist(err) {
		err = CopySelf(binPath)
		if err != nil {
			return fmt.Errorf("failed to copy binary: %w", err)
		}
		fmt.Printf("Binary copied to %s... OK\n", binPath)
	} else {
		return fmt.Errorf("could not check binary path: %w", err)
	}

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	if err := exec.Command("systemctl", "enable", "toctocd.service").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	if err := exec.Command("systemctl", "start", "toctocd.service").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("TocToc daemon installed and started successfully.\n")
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
