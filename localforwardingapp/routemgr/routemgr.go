package routemgr

import (
	"net"
	"sync"
)

type RouteMgr struct {
	lock sync.Mutex
	set  bool
}

func NewRouteMgr() *RouteMgr {
	return &RouteMgr{}
}

func (m *RouteMgr) Set(
	ifname net.Interface,
	clinet net.IP,
	server net.IP,
	local_cidrs []*net.IPNet) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.set {
		m.Reset()
	}
	return nil
}

func (m *RouteMgr) Reset() {
}
