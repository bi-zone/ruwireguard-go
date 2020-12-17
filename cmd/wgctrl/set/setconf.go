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

func showSetConfUsage(file io.Writer, cmd string) {
	fmt.Fprintf(file, "Usage: %s %s <interface> <configuration filename>\n", os.Args[0], cmd)
}

func SetConf(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showSetConfUsage(os.Stdout, args[0])
		return 0
	}

	if len(args) != 3 {
		showSetConfUsage(os.Stderr, args[0])
		return 1
	}

	configFile, err := os.Open(args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open configuration file: %v\n", err)
		return 1
	}

	device, err := parseConfigFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse configuration: %v\n", err)
		return 1
	}

	if args[0] == "setconf" {
		device.ReplacePeers = true
	} else {
		device.ReplacePeers = false
	}

	c, err := wgctrl.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open wgctrl: %v\n", err)
		return 1
	}
	defer c.Close()

	if args[0] == "syncconf" {
		oldDevice, err := c.Device(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to retrieve current interface configuration: %s", err)
			return 1
		}

		syncConf(oldDevice, device)
	}

	err = c.ConfigureDevice(args[1], *device)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to configure device: %s\n", err)
		return 1
	}
	return 0
}
