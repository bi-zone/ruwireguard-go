// old build: !linux,!openbsd

package wgctrl

import (
	"github.com/bi-zone/ruwireguard-go/wgctrl/internal/wginternal"
	"github.com/bi-zone/ruwireguard-go/wgctrl/internal/wguser"
)

// newClients configures wginternal.Clients for systems which only support
// userspace WireGuard implementations.
func newClients() ([]wginternal.Client, error) {
	c, err := wguser.New()
	if err != nil {
		return nil, err
	}

	return []wginternal.Client{c}, nil
}
