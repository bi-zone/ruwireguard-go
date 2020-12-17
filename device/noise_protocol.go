/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
	"github.com/bi-zone/ruwireguard-go/crypto/gosthopper"
	"github.com/bi-zone/ruwireguard-go/crypto/mgm"
	"github.com/bi-zone/ruwireguard-go/tai64n"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction    = "Noise_IKpsk2_GC256A_GOST_R_341112_256_WITH_KUZNYECHIK_MGM"
	WireGuardIdentifier  = "RU WireGuard v1 2020 zx2c4 Jason@zx2c4.com"
	WireGuardLabelMAC1   = "RU mac1---- 2020"
	WireGuardLabelCookie = "RU cookie-- 2020"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 182                                      // size of the first message
	MessageResponseSize        = 125                                      // size of the second response message
	MessageCookieReplySize     = 56                                       // size of cookie reply message
	MessageTransportHeaderSize = 16                                       // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + AEADTagSize // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                     // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                    // size of largest handshake related message
	AdditionalDataSize         = 12                                       // size of additional data in the MGM primitive
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + AEADTagSize]byte
	Timestamp [tai64n.TimestampSize + AEADTagSize]byte
	MAC1      [gost34112012256.Size]byte
	MAC2      [gost34112012256.Size]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [AEADTagSize]byte
	MAC1      [gost34112012256.Size]byte
	MAC2      [gost34112012256.Size]byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [AEADNonceSize]byte
	Cookie   [gost34112012256.Size + AEADTagSize]byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [gost34112012256.Size]byte // hash value
	chainKey                  [gost34112012256.Size]byte // chain key
	presharedKey              AEADSymmetricKey           // psk
	localEphemeral            NoisePrivateKey            // ephemeral secret key
	localIndex                uint32                     // used to clear hash-table
	remoteIndex               uint32                     // index for sending
	remoteStatic              NoisePublicKey             // long term key
	remoteEphemeral           NoisePublicKey             // ephemeral public key
	precomputedStaticStatic   []byte                     // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [gost34112012256.Size]byte
	InitialHash     [gost34112012256.Size]byte
	ZeroNonce       [AEADNonceSize]byte // Used in the first and second handshake messages.
)

func mixKey(dst *[gost34112012256.Size]byte, c *[gost34112012256.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst *[gost34112012256.Size]byte, h *[gost34112012256.Size]byte, data []byte) {
	hash := gost34112012256.New()
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

// Do basic precomputations.
func init() {
	Hash(&InitialChainKey, []byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WireGuardIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	var errZeroECDHResult = errors.New("ECDH returned all zeros")

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newNoisePrivateKey(device.rand())
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.PublicKey(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key
	ss := handshake.localEphemeral.SharedSecret(handshake.remoteStatic)
	if isZero(ss[:]) {
		return nil, errZeroECDHResult
	}
	var key [AEADSymmetricKeySize]byte
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		ss[:],
	)

	cipher, err := gosthopper.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, _ := mgm.NewMGM(cipher)
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], handshake.hash[:])

	handshake.mixHash(msg.Static[:])

	// encrypt timestamp
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errZeroECDHResult
	}
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)

	timestamp := tai64n.Now()
	cipher, err = gosthopper.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, _ = mgm.NewMGM(cipher)
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [gost34112012256.Size]byte
		chainKey [gost34112012256.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key
	var err error
	var peerPK NoisePublicKey
	var key [AEADSymmetricKeySize]byte
	ss := device.staticIdentity.privateKey.SharedSecret(msg.Ephemeral)
	if isZero(ss[:]) {
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := mgm.NewMGM(gost3412128.NewCipher(key[:]))
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ = mgm.NewMGM(gost3412128.NewCipher(key[:]))
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Debug.Printf("%v - ConsumeMessageInitiation: handshake replay @ %v\n", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Debug.Printf("%v - ConsumeMessageInitiation: handshake flood\n", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newNoisePrivateKey(device.rand())
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.PublicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	func() {
		ss := handshake.localEphemeral.SharedSecret(handshake.remoteEphemeral)
		handshake.mixKey(ss[:])
		ss = handshake.localEphemeral.SharedSecret(handshake.remoteStatic)
		handshake.mixKey(ss[:])
	}()

	// add preshared key

	var tau [gost34112012256.Size]byte
	var key [AEADSymmetricKeySize]byte

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	func() {
		cipher, err := gosthopper.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		aead, _ := mgm.NewMGM(cipher)
		aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
		handshake.mixHash(msg.Empty[:])
	}()

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [gost34112012256.Size]byte
		chainKey [gost34112012256.Size]byte
	)

	ok := func() bool {

		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		func() {
			ss := handshake.localEphemeral.SharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		func() {
			ss := device.staticIdentity.privateKey.SharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		// add preshared key (psk)

		var tau [gost34112012256.Size]byte
		var key [AEADSymmetricKeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript
		cipher, err := gosthopper.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		aead, _ := mgm.NewMGM(cipher)
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [AEADSymmetricKeySize]byte
	var recvKey [AEADSymmetricKeySize]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances
	keypair := new(Keypair)

	cs, err := gosthopper.NewCipher(sendKey[:])
	if err != nil {
		panic(err)
	}

	cr, err := gosthopper.NewCipher(recvKey[:])
	if err != nil {
		panic(err)
	}

	keypair.send, _ = mgm.NewMGM(cs)
	keypair.receive, _ = mgm.NewMGM(cr)

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.sendNonce = 0
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.loadNext()
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.storeNext(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.storeNext(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.loadNext() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.loadNext() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.loadNext()
	keypairs.storeNext(nil)
	return true
}
