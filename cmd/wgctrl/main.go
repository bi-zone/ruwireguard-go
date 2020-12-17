/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bi-zone/ruwireguard-go/cmd/wgctrl/key"
	"github.com/bi-zone/ruwireguard-go/cmd/wgctrl/set"
	"github.com/bi-zone/ruwireguard-go/cmd/wgctrl/show"
)

var gitRevision = "unknown"

var subcommands = []struct {
	subcommand  string
	function    func(args []string) int
	description string
}{
	{"show", show.Show, "Shows the current configuration and device information"},
	{"showconf", show.ShowConf, "Shows the current configuration of a given WireGuard interface, for use with 'setconf' command"},
	{"set", set.Set, "Change the current configuration, add peers, remove peers, or change peers"},
	{"setconf", set.SetConf, "Applies a configuration file to a WireGuard interface"},
	{"addconf", set.SetConf, "Appends a configuration file to a WireGuard interface"},
	{"syncconf", set.SetConf, "Synchronizes a configuration file to a WireGuard interface"},
	{"genkey", key.GenKey, "Generates a new private key and writes it to stdout"},
	{"genpsk", key.GenPsk, "Generates a new preshared key and writes it to stdout"},
	{"pubkey", key.PubKey, "Reads a private key from stdin and writes a public key to stdout"},
}

func showUsage(file io.Writer) {
	fmt.Fprintf(file, "wg tool for wireguard-go\n")
	fmt.Fprintf(file, "revision: %s\n\n", gitRevision)
	fmt.Fprintf(file, "Usage: %s <cmd> [<args>]\n\n", os.Args[0])
	fmt.Fprintf(file, "Available subcommands:\n")
	for i := range subcommands {
		fmt.Fprintf(file, "  %s: %s\n", subcommands[i].subcommand, subcommands[i].description)
	}
	fmt.Fprintf(file, "You may pass '--help' to any of these subcommands to view usage.\n")
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		showUsage(os.Stdout)
		os.Exit(0)
	}

	if len(os.Args) == 1 {
		os.Exit(show.Show([]string{"show"}))
	}

	for i := range subcommands {
		if subcommands[i].subcommand == os.Args[1] {
			os.Exit(subcommands[i].function(os.Args[1:]))
		}
	}

	fmt.Fprintf(os.Stderr, "Invalid subcommand: %s\n", os.Args[1])
	showUsage(os.Stderr)
	os.Exit(1)
}
