/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package set

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

const PrivateKeyLenBase64 = 44
const PrivateKeyLen = 32
const PublicKeyLenBase64 = 44
const PublicKeyLen = 33

func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return 0, errors.New("string is empty")
	}

	int_64, err := strconv.ParseInt(s, 0, 0)
	if err != nil {
		return 0, err
	}

	return int(int_64), nil
}

func parseFwmark(s string) (*int, error) {
	s = strings.TrimSpace(s)

	if s == "0" || s == "off" {
		return nil, nil
	}

	value, err := parseInt(s)
	if err != nil {
		return nil, err
	}

	return &value, nil
}

func parsePrivateKeyFile(filePath string) (*wgtypes.Key, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return parsePrivateKey(string(data))
}

func parsePrivateKey(s string) (*wgtypes.Key, error) {
	s = strings.TrimSpace(s)

	if len(s) != PrivateKeyLenBase64 {
		return nil, errors.New("invalid private key length")
	}

	rawKey, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(rawKey) != PrivateKeyLen {
		return nil, errors.New("invalid private key length")
	}

	return (*wgtypes.Key)(&rawKey), nil
}

func parsePublicKey(s string) (wgtypes.Key, error) {
	s = strings.TrimSpace(s)

	if len(s) != PublicKeyLenBase64 {
		return nil, errors.New("invalid public key length")
	}

	rawKey, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(rawKey) != PublicKeyLen {
		return nil, errors.New("invalid public key length")
	}

	return rawKey, nil
}

func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	if i := strings.LastIndexByte(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

func parseEndpoint(s string) (*net.UDPAddr, error) {
	s = strings.TrimSpace(s)

	hostStr, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	host, zone := splitHostZone(hostStr)

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	return &net.UDPAddr{
		IP:   ips[0],
		Port: port,
		Zone: zone,
	}, nil
}

func parseAllowedIPs(s string) ([]net.IPNet, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return nil, nil
	}

	var ips []net.IPNet

	pairs := strings.Split(s, ",")

	for i := range pairs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(pairs[i]))
		if err != nil {
			return nil, err
		}

		ips = append(ips, *n)
	}

	return ips, nil
}

func parsePersistentKeepalive(s string) (*time.Duration, error) {
	s = strings.TrimSpace(s)

	if s == "0" || s == "off" {
		return nil, nil
	}

	value, err := parseInt(s)
	if err != nil {
		return nil, err
	}

	if value < 1 || value > 65535 {
		return nil, fmt.Errorf("persistent keepalive interval is neither 0/off nor 1-65535: %d", value)
	}

	duration := time.Duration(value) * time.Second

	return &duration, nil
}

func parseCmd(args []string) (*wgtypes.Config, error) {
	var device wgtypes.Config
	var peer *wgtypes.PeerConfig

	for len(args) > 0 {
		if args[0] == "listen-port" && len(args) >= 2 && peer == nil {
			port, err := parseInt(args[1])
			if err != nil {
				return nil, err
			}

			device.ListenPort = &port

			args = args[2:]
		} else if args[0] == "fwmark" && len(args) >= 2 && peer == nil {
			fwmark, err := parseFwmark(args[1])
			if err != nil {
				return nil, err
			}

			device.FirewallMark = fwmark

			args = args[2:]
		} else if args[0] == "private-key" && len(args) >= 2 && peer == nil {
			key, err := parsePrivateKeyFile(args[1])
			if err != nil {
				return nil, err
			}

			device.PrivateKey = key

			args = args[2:]
		} else if args[0] == "peer" && len(args) >= 2 {
			if peer != nil {
				device.Peers = append(device.Peers, *peer)
			}

			peer = new(wgtypes.PeerConfig)

			key, err := parsePublicKey(args[1])
			if err != nil {
				return nil, err
			}

			peer.PublicKey = key

			args = args[2:]
		} else if args[0] == "remove" && peer != nil {
			peer.Remove = true

			args = args[1:]
		} else if args[0] == "endpoint" && len(args) >= 2 && peer != nil {
			endpoint, err := parseEndpoint(args[1])
			if err != nil {
				return nil, err
			}

			peer.Endpoint = endpoint

			args = args[2:]
		} else if args[0] == "allowed-ips" && len(args) >= 2 && peer != nil {
			ips, err := parseAllowedIPs(args[1])
			if err != nil {
				return nil, err
			}

			peer.AllowedIPs = ips
			peer.ReplaceAllowedIPs = true

			args = args[2:]
		} else if args[0] == "persistent-keepalive" && len(args) >= 2 && peer != nil {
			duration, err := parsePersistentKeepalive(args[1])
			if err != nil {
				return nil, err
			}

			peer.PersistentKeepaliveInterval = duration

			args = args[2:]
		} else if args[0] == "preshared-key" && len(args) >= 2 && peer != nil {
			key, err := parsePrivateKeyFile(args[1])
			if err != nil {
				return nil, err
			}

			peer.PresharedKey = key

			args = args[2:]
		} else {
			return nil, fmt.Errorf("invalid argument: %s", args[0])
		}
	}

	if peer != nil {
		device.Peers = append(device.Peers, *peer)
	}

	return &device, nil
}

func parseConfigFile(file io.Reader) (*wgtypes.Config, error) {
	var device wgtypes.Config
	var peer *wgtypes.PeerConfig
	var isDeviceSection bool
	var isPeerSection bool

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var lines []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	for _, line := range lines {
		if line == "[Interface]" {
			isDeviceSection = true
			isPeerSection = false
			continue
		}

		if line == "[Peer]" {
			isDeviceSection = false
			isPeerSection = true

			if peer != nil {
				if peer.PublicKey == nil {
					return nil, fmt.Errorf("a peer is missing a public key")
				}

				device.Peers = append(device.Peers, *peer)
			}

			peer = new(wgtypes.PeerConfig)

			continue
		}

		params := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(params[0])
		value := strings.TrimSpace(params[1])

		if len(params) != 2 {
			return nil, fmt.Errorf("line unrecognized: %s", line)
		}

		if isDeviceSection {
			if key == "ListenPort" {
				port, err := parseInt(value)
				if err != nil {
					return nil, err
				}

				device.ListenPort = &port

				continue
			} else if key == "FwMark" {
				fwmark, err := parseFwmark(value)
				if err != nil {
					return nil, err
				}

				device.FirewallMark = fwmark

				continue
			} else if key == "PrivateKey" {
				privateKey, err := parsePrivateKey(value)
				if err != nil {
					return nil, err
				}

				device.PrivateKey = privateKey

				continue
			} else {
				return nil, fmt.Errorf("line unrecognized: %s", line)
			}
		}

		if isPeerSection {
			if key == "Endpoint" {
				endpoint, err := parseEndpoint(value)
				if err != nil {
					return nil, err
				}

				peer.Endpoint = endpoint

				continue
			} else if key == "PublicKey" {
				publicKey, err := parsePublicKey(value)
				if err != nil {
					return nil, err
				}

				peer.PublicKey = publicKey

				continue
			} else if key == "AllowedIPs" {
				ips, err := parseAllowedIPs(value)
				if err != nil {
					return nil, err
				}

				peer.AllowedIPs = ips

				continue
			} else if key == "PersistentKeepalive" {
				duration, err := parsePersistentKeepalive(value)
				if err != nil {
					return nil, err
				}

				peer.PersistentKeepaliveInterval = duration

				continue
			} else if key == "PresharedKey" {
				key, err := parsePrivateKey(value)
				if err != nil {
					return nil, err
				}

				peer.PresharedKey = key

				continue
			} else {
				return nil, fmt.Errorf("line unrecognized: %s", line)
			}
		}
	}

	if peer != nil {
		device.Peers = append(device.Peers, *peer)
	}

	return &device, nil
}
