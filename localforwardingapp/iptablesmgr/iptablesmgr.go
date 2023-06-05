package iptablesmgr

import (
	"net"
	"os/exec"
	"sync"

	log "github.com/sirupsen/logrus"
)

type IPTablesMgr struct {
	lock         sync.Mutex
	added        map[string]struct{}
	shuttingdown bool
}

func NewIPTablesMgr() *IPTablesMgr {
	return &IPTablesMgr{
		added:        make(map[string]struct{}),
		shuttingdown: false,
	}
}

func (m *IPTablesMgr) Add(addr net.IP) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.shuttingdown {
		return
	}

	addrname := addr.String()

	if _, ok := m.added[addrname]; ok {
		return
	}

	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", addrname, "-j", "MASQUERADE")

	go func() {
		err := cmd.Run()
		if err != nil {
			log.WithError(err).Error("Error adding iptables rule")
		}
	}()
}

func (m *IPTablesMgr) Remove(addr net.IP) {
	m.lock.Lock()
	defer m.lock.Unlock()

	addrname := addr.String()

	if _, ok := m.added[addrname]; !ok {
		return
	}

	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", addrname, "-j", "MASQUERADE")

	go func() {
		err := cmd.Run()
		if err != nil {
			log.WithError(err).Error("Error removing iptables rule")
		}
	}()
}

func (m *IPTablesMgr) Reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	for addrname := range m.added {
		cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", addrname, "-j", "MASQUERADE")

		err := cmd.Run()
		if err != nil {
			log.WithError(err).WithField("addrname", addrname).Error("Error resetting iptables rule")
		}
	}
}

func (m *IPTablesMgr) SetShutdown() {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.shuttingdown = true
}
