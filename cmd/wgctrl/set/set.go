/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package set

import (
	"fmt"
	"io"
	"os"

	"github.com/bi-zone/ruwireguard-go/wgctrl"
)

func showSetUsage(file io.Writer) {
	fmt.Fprintf(file, "Usage: %s set <interface> [listen-port <port>] [fwmark <mark>] [private-key <file path>] [peer <base64 public key> [remove] [preshared-key <file path>] [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] ]...\n", os.Args[0])
}

func Set(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showSetUsage(os.Stdout)
		return 0
	}

	if len(args) < 3 {
		showSetUsage(os.Stderr)
		return 1
	}

	device, err := parseCmd(args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse commands: %v\n", err)
		return 1
	}

	c, err := wgctrl.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open wgctrl: %v\n", err)
		return 1
	}
	defer c.Close()

	err = c.ConfigureDevice(args[1], *device)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to configure device: %s\n", err)
		return 1
	}

	return 0
}
