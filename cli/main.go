package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "toctoc",
	Short: "TocToc is a cli tool for performing port knocking operations",
	Long:  "TocToc is a CLI tool for port knocking - detect open ports, harden access, and trigger remote port openings by sending a predefined port sequence.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "An error occured while executing TocToc '%s'\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(CheckCmd)
	rootCmd.AddCommand(ProtectCmd)
	rootCmd.AddCommand(UnprotectCmd)
	rootCmd.AddCommand(InstallCmd)
	rootCmd.AddCommand(ListCmd)
	rootCmd.AddCommand(RunAsDaemonCmd)
	rootCmd.AddCommand(KnockCmd)
}

var CheckCmd = &cobra.Command{
	Use:   "check <host> <port>",
	Short: "Check if a given TCP port is open on a specific host",
	Long: `Check if a given TCP port is open on a specific host

Arguments:
  <host>    The target hostname or IP address (e.g., 127.0.0.1)
  <port>    The port number to check (e.g., 22)`,
	Example: `  toctoc check 127.0.0.1 22
  toctoc check 1.1.1.1 53
  toctoc check example.com 443`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		Check(args[0], args[1])
	},
}

var ProtectCmd = &cobra.Command{
	Use:   "protect <port> <password>",
	Short: "Protect the given port with a dynamic iptable rule",
	Long: `Protect the given port with a dynamic iptable rule

Arguments:
  <port>    The port number to protect (e.g., 22)
  <password>  The string that defines the sequence of ports required to unlock access to the protected port`,
	Example: `  toctoc protect 22 S€cr3tP@$$w0rd`,
	Args:    cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		ProtectPort(args[0], args[1])
	},
}

var UnprotectCmd = &cobra.Command{
	Use:   "unprotect <port> <password>",
	Short: "Disable toctoc protection on this port",
	Long: `Disable toctoc protection on this port

Arguments:
  <port>    The port number to unprotect (e.g., 22)`,
	Example: `  toctoc unprotect 22 `,
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		UnprotectPort(args[0])
	},
}

var InstallCmd = &cobra.Command{
	Use:     "install",
	Short:   "Install toctoc on your system",
	Long:    "Install toctoc on your system",
	Example: `  toctoc install `,
	Args:    cobra.ExactArgs(0),
	Run:     func(cmd *cobra.Command, args []string) { Install() },
}

var ListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all protected ports",
	Long:    "List all protected ports",
	Example: `  toctoc list `,
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		List()
	},
}

var RunAsDaemonCmd = &cobra.Command{
	Use:     "daemon",
	Short:   "Run TocToc daemon",
	Long:    "Run TocToc daemon",
	Hidden:  true,
	Example: `  toctoc daemon `,
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Starting TocToc server agent...\n\n%s\n\n", RunServerAgent())
	},
}

var KnockCmd = &cobra.Command{
	Use:   "knock <host> <port> <password>",
	Short: "Send a knock sequence to the host",
	Long: `Send a knock sequence to the host

Arguments:
  <host>      The target hostname or IP address (e.g., 127.0.0.1)
  <port>      The port number to open (e.g., 22)
  <password>  The string that defines the sequence of ports required to unlock access to the protected port`,
	Example: `  toctoc knock 1.1.1.1 22 S€cr3tP@$$w0rd
  toctoc knock example.com 8080 S€cr3tP@$$w0rd`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		Knock(args[0], args[1], args[2])
	},
}
