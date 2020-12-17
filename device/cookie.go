/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
	"crypto/rand"
	"sync"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
	"github.com/bi-zone/ruwireguard-go/crypto/mgm"
)

type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [gost34112012256.Size]byte
	}
	mac2 struct {
		secret        [gost34112012256.Size]byte
		secretSet     time.Time
		encryptionKey [AEADSymmetricKeySize]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [gost34112012256.Size]byte
	}
	mac2 struct {
		cookie        [gost34112012256.Size]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [gost34112012256.Size]byte
		encryptionKey [AEADSymmetricKeySize]byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	// mac1 state

	func() {
		hash := gost34112012256.New()
		hash.Write([]byte(WireGuardLabelMAC1))
		hash.Write(pk[:])
		hash.Sum(st.mac1.key[:0])
	}()

	// mac2 state

	func() {
		hash := gost34112012256.New()
		hash.Write([]byte(WireGuardLabelCookie))
		hash.Write(pk[:])
		hash.Sum(st.mac2.encryptionKey[:0])
	}()

	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - gost34112012256.Size
	smac1 := smac2 - gost34112012256.Size

	var mac1 [gost34112012256.Size]byte
	MAC(&mac1, st.mac1.key[:], msg[:smac1])

	return hmac.Equal(mac1[:], msg[smac1:smac2])
}

func (st *CookieChecker) CheckMAC2(msg []byte, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	var cookie [gost34112012256.Size]byte
	func() {
		MAC(&cookie, st.mac2.secret[:], src)
	}()

	// calculate mac of packet (including mac1)

	smac2 := len(msg) - gost34112012256.Size

	var mac2 [gost34112012256.Size]byte
	func() {
		MAC(&mac2, cookie[:], msg[:smac2])
	}()

	return hmac.Equal(mac2[:], msg[smac2:])
}

func (st *CookieChecker) CreateReply(
	msg []byte,
	recv uint32,
	src []byte,
) (*MessageCookieReply, error) {

	st.RLock()

	// refresh cookie secret

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
		_, err := rand.Read(st.mac2.secret[:])
		if err != nil {
			st.Unlock()
			return nil, err
		}
		st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	// derive cookie

	var cookie [gost34112012256.Size]byte
	func() {
		MAC(&cookie, st.mac2.secret[:], src)
	}()

	// encrypt cookie

	size := len(msg)

	smac2 := size - gost34112012256.Size
	smac1 := smac2 - gost34112012256.Size

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = recv

	err := getMGMNonce(&reply.Nonce)
	if err != nil {
		st.RUnlock()
		return nil, err
	}

	aead, _ := mgm.NewMGM(gost3412128.NewCipher(st.mac2.encryptionKey[:]))
	aead.Seal(reply.Cookie[:0], reply.Nonce[:], cookie[:], msg[smac1:smac2])

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	func() {
		hash := gost34112012256.New()
		hash.Write([]byte(WireGuardLabelMAC1))
		hash.Write(pk[:])
		hash.Sum(st.mac1.key[:0])
	}()

	func() {
		hash := gost34112012256.New()
		hash.Write([]byte(WireGuardLabelCookie))
		hash.Write(pk[:])
		hash.Sum(st.mac2.encryptionKey[:0])
	}()

	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [gost34112012256.Size]byte

	aead, _ := mgm.NewMGM(gost3412128.NewCipher(st.mac2.encryptionKey[:]))
	_, err := aead.Open(cookie[:0], msg.Nonce[:], msg.Cookie[:], st.mac2.lastMAC1[:])

	if err != nil {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {

	size := len(msg)

	smac2 := size - gost34112012256.Size
	smac1 := smac2 - gost34112012256.Size

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	// set mac1

	var mac [gost34112012256.Size]byte

	func() {
		MAC(&mac, st.mac1.key[:], msg[:smac1])
		copy(mac1, mac[:])
	}()
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	func() {
		MAC(&mac, st.mac2.cookie[:], msg[:smac2])
		copy(mac2, mac[:])
	}()
}
