/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package show

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bi-zone/ruwireguard-go/wgctrl"
)

func showUsage(file io.Writer) {
	fmt.Fprintf(file, "Usage: %s show { <interface> | all | interfaces } [public-key | private-key | listen-port | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | dump]\n", os.Args[0])
}

func Show(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showConfUsage(os.Stdout)
		return 0
	}

	if len(args) > 3 {
		showUsage(os.Stderr)
		return 1
	}

	c, err := wgctrl.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open wgctrl: %v\n", err)
		return 1
	}
	defer c.Close()

	if len(args) == 1 || args[1] == "all" {
		devices, err := c.Devices()
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to retrieve interfaces configurations: %s\n", err)
			return 1
		}

		for i, device := range devices {
			if len(args) == 3 {
				err := uglyPrint(os.Stdout, device, args[2], true)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					return 1
				}
			} else {
				prettyPrint(os.Stdout, device)
				if i < len(devices)-1 {
					fmt.Printf("\n")
				}
			}
		}
	} else if args[1] == "interfaces" {
		devices, err := c.Devices()
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to retrieve interfaces configurations: %s\n", err)
			return 1
		}

		var names []string

		for _, device := range devices {
			names = append(names, device.Name)
		}

		fmt.Printf("%s\n", strings.Join(names, " "))
	} else {
		device, err := c.Device(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to retrieve current interface configuration: %s\n", err)
			return 1
		}

		if len(args) == 3 {
			err := uglyPrint(os.Stdout, device, args[2], false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				return 1
			}
		} else {
			prettyPrint(os.Stdout, device)
		}
	}

	return 0
}
