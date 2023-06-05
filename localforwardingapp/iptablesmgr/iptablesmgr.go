package iptablesmgr

import (
	"net"
	"os/exec"
	"sync"

	log "github.com/sirupsen/logrus"
)

type IPTablesMgr struct {
	lock  sync.Mutex
	added map[string]bool
}

func NewIPTablesMgr() *IPTablesMgr {
	return &IPTablesMgr{
		added: map[string]bool{},
	}
}

func (m *IPTablesMgr) Add(addr net.IP) {
	m.lock.Lock()
	defer m.lock.Unlock()

	addrname := addr.String()

	if m.added[addrname] {
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

	if !m.added[addrname] {
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

		go func() {
			err := cmd.Run()
			if err != nil {
				log.WithError(err).Error("Error removing iptables rule")
			}
		}()
	}
}
