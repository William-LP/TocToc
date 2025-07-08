# TocToc

TocToc - A Simple Port Knocking CLI

## Quick Start

```bash
# install
go install github.com/William-LP/TocToc@latest

# setup TocToc
sudo toctoc install

# protect SSH port with a strong password
sudo toctoc protect 22 P@ssW0rd

# check the port is protected
sudo toctoc list

# remove toctoc protection
sudo toctoc unprotect 22
```

**Why sudo?**

Because TocToc uses **iptables** under the hood. 

Plus the `toctoc install` command will configure **TocToc** as a daemon on the server.

## What is Port Knocking ?

[Port knocking](https://en.wikipedia.org/wiki/Port_knocking) hides services behind closed ports. To "unlock" the port:
- The client sends a sequence of connection attempts to specific closed ports (the "knock").
- If the sequence is correct, a firewall rule dynamically opens the hidden port.

## Features
- Check if TCP ports are open
- Secure services via port knocking
- Trigger remote port opening with a port sequences computed from a secret

## How does TocToc works

TocToc is made of three distinct components :
- Client CLI : Send a sequence of TCP connection attempts (the knock sequence) to a remote IP
- Server CLI : Configure the system, protect and unprotect ports
- Daemon : Listens on all knockable ports, tracks sequences per client IP and opens the protected port when a correct sequence is detected

## Security Disclaimer

Port knocking is security by obscurity, useful for:
- Hiding low-profile services
- Blocking automated scans
- Adding another "layer" to defense-in-depth

However it is not a substitute for proper encryption, authentication, and access control.
It is not sufficient alone for protecting critical infrastructure. 

Please combine this with other security :
- Strong service authentication (e.g., SSH keys, VPNs)
- Fail2ban or IP throttling after bad attempts
- IDS/IPS systems to detect abnormal traffic


## Manual Build

```
git clone github.com/William/toctoc.git
cd toctoc
go build -o toctoc
```

## Usage

```
TocToc is a CLI tool for port knocking - detect open ports, harden access, and trigger remote port openings by sending a predefined port sequence.

Usage:
  toctoc [flags]
  toctoc [command]

Available Commands:
  check       Check if a given TCP port is open on a specific host.
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  install     Install toctoc on your system
  list        List all protected ports
  protect     Protect the given port with a dynamic iptable rule
  unprotect   Disable toctoc protection on this port

Flags:
  -h, --help   help for toctoc

Use "toctoc [command] --help" for more information about a command.
```

## License

TocToc is released under the MIT license. See [LICENSE.txt](LICENSE.txt)