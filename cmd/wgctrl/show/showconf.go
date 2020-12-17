/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package show

import (
	"fmt"
	"io"
	"os"

	"github.com/bi-zone/ruwireguard-go/wgctrl"
)

func showConfUsage(file io.Writer) {
	fmt.Fprintf(file, "Usage: %s showconf <interface>\n", os.Args[0])
}

func ShowConf(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showConfUsage(os.Stdout)
		return 0
	}

	if len(args) != 2 {
		showConfUsage(os.Stderr)
		return 1
	}

	c, err := wgctrl.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open wgctrl: %v\n", err)
		return 1
	}
	defer c.Close()

	device, err := c.Device(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to retrieve current interface configuration: %s\n", err)
		return 1
	}

	printConf(os.Stdout, device)

	return 0
}
