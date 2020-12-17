/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package show

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

var zeroPrivateKey = [wgtypes.PrivateKeyLen]byte{}
var zeroPublicKey = [wgtypes.PublicKeyLen]byte{}

func prettyTime(left int64) string {
	var s []string

	years := left / (365 * 24 * 60 * 60)
	left = left % (365 * 24 * 60 * 60)
	days := left / (24 * 60 * 60)
	left = left % (24 * 60 * 60)
	hours := left / (60 * 60)
	left = left % (60 * 60)
	minutes := left / 60
	seconds := left % 60

	if years != 0 {
		str := fmt.Sprintf("%d year", years)
		if years != 1 {
			str += "s"
		}
		s = append(s, str)
	}
	if days != 0 {
		str := fmt.Sprintf("%d day", days)
		if days != 1 {
			str += "s"
		}
		s = append(s, str)
	}
	if hours != 0 {
		str := fmt.Sprintf("%d hour", hours)
		if hours != 1 {
			str += "s"
		}
		s = append(s, str)
	}
	if minutes != 0 {
		str := fmt.Sprintf("%d minute", minutes)
		if minutes != 1 {
			str += "s"
		}
		s = append(s, str)
	}
	if seconds != 0 {
		str := fmt.Sprintf("%d second", seconds)
		if seconds != 1 {
			str += "s"
		}
		s = append(s, str)
	}

	return strings.Join(s, ", ")
}

func prettyBytes(bytesSize int64) string {
	if bytesSize < 1024 {
		return fmt.Sprintf("%d B", bytesSize)
	} else if bytesSize < 1024*1024 {
		return fmt.Sprintf("%.2f KiB", float64(bytesSize)/1024)
	} else if bytesSize < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MiB", float64(bytesSize)/(1024*1024))
	} else if bytesSize < 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f GiB", float64(bytesSize)/(1024*1024*1024))
	} else {
		return fmt.Sprintf("%.2f TiB", float64(bytesSize)/(1024*1024*1024)/1024)
	}
}

func prettyPrint(out io.Writer, device *wgtypes.Device) {
	fmt.Fprintf(out, "interface: %s\n", device.Name)
	if !bytes.Equal(device.PublicKey, zeroPublicKey[:]) {
		fmt.Fprintf(out, "  public key: %s\n", base64.StdEncoding.EncodeToString(device.PublicKey))
	}
	if !bytes.Equal(device.PrivateKey, zeroPrivateKey[:]) {
		fmt.Fprintf(out, "  private key: %s\n", base64.StdEncoding.EncodeToString(device.PrivateKey))
	}
	if device.ListenPort != 0 {
		fmt.Fprintf(out, "  listening port: %d\n", device.ListenPort)
	}
	if device.FirewallMark != 0 {
		fmt.Fprintf(out, "  fwmark: 0x%x\n", device.FirewallMark)
	}

	for _, peer := range device.Peers {
		fmt.Fprintf(out, "\npeer: %s\n", base64.StdEncoding.EncodeToString(peer.PublicKey))
		if !bytes.Equal(peer.PresharedKey, zeroPrivateKey[:]) {
			fmt.Fprintf(out, "  preshared key: %s\n", base64.StdEncoding.EncodeToString(peer.PresharedKey))
		}
		if peer.Endpoint != nil {
			fmt.Fprintf(out, "  endpoint: %s\n", peer.Endpoint.String())
		}

		fmt.Fprintf(out, "  allowed-ips: ")
		var s []string
		for _, ip := range peer.AllowedIPs {
			s = append(s, ip.String())
		}
		if len(s) != 0 {
			fmt.Fprintf(out, "%s\n", strings.Join(s, ", "))
		} else {
			fmt.Fprintf(out, "(none)\n")
		}

		now := time.Now()
		zeroTime := time.Time{}
		if !peer.LastHandshakeTime.Equal(zeroTime) {
			fmt.Fprintf(out, "  latest handshake: ")
			if now.Equal(peer.LastHandshakeTime) {
				fmt.Fprintf(out, "Now\n")
			} else if now.Before(peer.LastHandshakeTime) {
				fmt.Fprintf(out, "(System clock wound backward; connection problems may ensue.)\n")
			} else {
				fmt.Fprintf(out, "%s\n", prettyTime(now.Unix()-peer.LastHandshakeTime.Unix()))
			}
		}

		if peer.ReceiveBytes != 0 || peer.TransmitBytes != 0 {
			fmt.Fprintf(out, "  transfer: %s received, %s sent\n", prettyBytes(peer.ReceiveBytes), prettyBytes(peer.TransmitBytes))
		}

		d := peer.PersistentKeepaliveInterval / time.Second
		if d != 0 {
			fmt.Fprintf(out, "  persistent keepalive: every %s\n", prettyTime(int64(d)))
		}
	}
}

func dumpPrint(out io.Writer, device *wgtypes.Device, showDeviceName bool) {
	if showDeviceName {
		fmt.Fprintf(out, "%s\t", device.Name)
	}

	if bytes.Equal(device.PrivateKey, zeroPrivateKey[:]) {
		fmt.Fprintf(out, "(none)\t")
	} else {
		fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(device.PrivateKey))
	}

	if bytes.Equal(device.PublicKey, zeroPublicKey[:]) {
		fmt.Fprintf(out, "(none)\t")
	} else {
		fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(device.PublicKey))
	}

	fmt.Fprintf(out, "%d\t", device.ListenPort)

	if device.FirewallMark != 0 {
		fmt.Fprintf(out, "0x%x\n", device.FirewallMark)
	} else {
		fmt.Fprintf(out, "off\n")
	}

	for _, peer := range device.Peers {
		if showDeviceName {
			fmt.Fprintf(out, "%s\t", device.Name)
		}

		fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(peer.PublicKey))

		if bytes.Equal(peer.PresharedKey, zeroPrivateKey[:]) {
			fmt.Fprintf(out, "(none)\t")
		} else {
			fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(peer.PresharedKey))
		}

		if peer.Endpoint != nil {
			fmt.Fprintf(out, "%s\t", peer.Endpoint.String())
		} else {
			fmt.Fprintf(out, "(none)\t")
		}

		var s []string
		for _, ip := range peer.AllowedIPs {
			s = append(s, ip.String())
		}
		if len(s) != 0 {
			fmt.Fprintf(out, "%s\t", strings.Join(s, ","))
		} else {
			fmt.Fprintf(out, "(none)\t")
		}

		lastHandshake := peer.LastHandshakeTime.Unix()
		if lastHandshake < 0 {
			fmt.Fprintf(out, "0\t")
		} else {
			fmt.Fprintf(out, "%d\t", time.Now().Unix()-lastHandshake)
		}

		fmt.Fprintf(out, "%d\t%d\t", peer.ReceiveBytes, peer.TransmitBytes)

		if peer.PersistentKeepaliveInterval != 0 {
			fmt.Fprintf(out, "%d\n", peer.PersistentKeepaliveInterval/time.Second)
		} else {
			fmt.Fprintf(out, "off\n")
		}
	}
}

func uglyPrint(out io.Writer, device *wgtypes.Device, param string, showDeviceName bool) error {
	if param == "public-key" {
		if showDeviceName {
			fmt.Fprintf(out, "%s\t", device.Name)
		}
		fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(device.PublicKey))
	} else if param == "private-key" {
		if showDeviceName {
			fmt.Fprintf(out, "%s\t", device.Name)
		}
		fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(device.PrivateKey))
	} else if param == "listen-port" {
		if showDeviceName {
			fmt.Fprintf(out, "%s\t", device.Name)
		}
		fmt.Fprintf(out, "%d\n", device.ListenPort)
	} else if param == "fwmark" {
		if showDeviceName {
			fmt.Fprintf(out, "%s\t", device.Name)
		}
		if device.FirewallMark != 0 {
			fmt.Fprintf(out, "0x%x\n", device.FirewallMark)
		} else {
			fmt.Fprintf(out, "off\n")
		}
	} else if param == "endpoints" {
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}
			fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(peer.PublicKey))
			if peer.Endpoint != nil {
				fmt.Fprintf(out, "%s\n", peer.Endpoint.String())
			} else {
				fmt.Fprintf(out, "(none)\n")
			}
		}
	} else if param == "allowed-ips" {
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}

			fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(peer.PublicKey))

			var s []string
			for _, ip := range peer.AllowedIPs {
				s = append(s, ip.String())
			}
			if len(s) != 0 {
				fmt.Fprintf(out, "%s\n", strings.Join(s, " "))
			} else {
				fmt.Fprintf(out, "(none)\n")
			}
		}
	} else if param == "latest-handshakes" {
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}

			lastHandshake := peer.LastHandshakeTime.Unix()
			if lastHandshake < 0 {
				fmt.Fprintf(out, "%s\t0\n", base64.StdEncoding.EncodeToString(peer.PublicKey))
			} else {
				fmt.Fprintf(out, "%s\t%d\n", base64.StdEncoding.EncodeToString(peer.PublicKey), time.Now().Unix()-lastHandshake)
			}
		}
	} else if param == "transfer" {
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}
			fmt.Fprintf(out, "%s\t%d\t%d\n", base64.StdEncoding.EncodeToString(peer.PublicKey), peer.ReceiveBytes, peer.TransmitBytes)
		}
	} else if param == "persistent-keepalive" {
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}

			fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(peer.PublicKey))

			if peer.PersistentKeepaliveInterval != 0 {
				fmt.Fprintf(out, "%d\n", peer.PersistentKeepaliveInterval/time.Second)
			} else {
				fmt.Fprintf(out, "off\n")
			}
		}
	} else if param == "preshared-keys" {
		zeroBytes := make([]byte, len(device.PrivateKey))
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}

			fmt.Fprintf(out, "%s\t", base64.StdEncoding.EncodeToString(peer.PublicKey))

			if bytes.Equal(peer.PresharedKey, zeroBytes) {
				fmt.Fprintf(out, "(none)\n")
			} else {
				fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(peer.PresharedKey))
			}
		}
	} else if param == "peers" {
		for _, peer := range device.Peers {
			if showDeviceName {
				fmt.Fprintf(out, "%s\t", device.Name)
			}

			fmt.Fprintf(out, "%s\n", base64.StdEncoding.EncodeToString(peer.PublicKey))
		}
	} else if param == "dump" {
		dumpPrint(out, device, showDeviceName)
	} else {
		return fmt.Errorf("invalid parameter: %s", param)
	}

	return nil
}

func printConf(out io.Writer, device *wgtypes.Device) {
	fmt.Fprintf(out, "[Interface]\n")
	if device.ListenPort != 0 {
		fmt.Fprintf(out, "ListenPort = %d\n", device.ListenPort)
	}
	if device.FirewallMark != 0 {
		fmt.Fprintf(out, "FwMark = 0x%x\n", device.FirewallMark)
	}
	if !bytes.Equal(device.PrivateKey, zeroPrivateKey[:]) {
		fmt.Fprintf(out, "PrivateKey = %s\n", base64.StdEncoding.EncodeToString(device.PrivateKey))
	}

	for _, peer := range device.Peers {
		fmt.Fprintf(out, "\n[Peer]\nPublicKey = %s\n", base64.StdEncoding.EncodeToString(peer.PublicKey))

		if !bytes.Equal(peer.PresharedKey, zeroPrivateKey[:]) {
			fmt.Fprintf(out, "PresharedKey = %s\n", base64.StdEncoding.EncodeToString(peer.PresharedKey))
		}

		if peer.AllowedIPs != nil {
			fmt.Fprintf(out, "AllowedIPs = ")
			for i, ip := range peer.AllowedIPs {
				fmt.Fprintf(out, "%s", ip.String())

				if i != len(peer.AllowedIPs)-1 {
					fmt.Fprintf(out, ", ")
				}
			}
			fmt.Fprintf(out, "\n")
		}

		if peer.Endpoint != nil {
			fmt.Fprintf(out, "Endpoint = %s\n", peer.Endpoint.String())
		}

		if peer.PersistentKeepaliveInterval != 0 {
			fmt.Fprintf(out, "PersistentKeepalive = %d\n", peer.PersistentKeepaliveInterval/time.Second)
		}
	}
}
