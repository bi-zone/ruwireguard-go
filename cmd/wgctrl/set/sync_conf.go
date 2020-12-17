/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package set

import (
	"bytes"

	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

func syncConf(oldDevice *wgtypes.Device, newDevice *wgtypes.Config) {
	var removePeers []wgtypes.PeerConfig

	// if flag is true then add peer in removePeers
	flag := true
	for _, oldPeer := range oldDevice.Peers {
		for _, newPeer := range newDevice.Peers {
			if bytes.Equal(oldPeer.PublicKey, newPeer.PublicKey) {
				flag = false
				break
			}
		}

		if flag {
			peer := wgtypes.PeerConfig{
				PublicKey: oldPeer.PublicKey,
				Remove:    true,
			}
			removePeers = append(removePeers, peer)
		} else {
			flag = true
		}
	}

	newDevice.Peers = append(newDevice.Peers, removePeers...)
}
