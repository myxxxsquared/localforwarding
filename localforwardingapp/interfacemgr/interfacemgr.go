package interfacemgr

import (
	"net"
	"sort"

	log "github.com/sirupsen/logrus"
)

type InterfaceInfo struct {
	Interface net.Interface
	Addrs     []*net.IPNet
}

func GetInterfaces(cidr *net.IPNet) ([]InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("Error getting interfaces")
		return nil, err
	}

	infos := []InterfaceInfo{}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.WithError(err).WithField("interface", i.Name).Error("Error getting addresses")
		}
		matchedAddrs := []*net.IPNet{}
		for _, a := range addrs {
			netaddr, ok := a.(*net.IPNet)
			if !ok {
				log.WithField("interface", i.Name).WithField("addr", a).Error("Error casting address")
				continue
			}
			if cidr.Contains(netaddr.IP) {
				matchedAddrs = append(matchedAddrs, netaddr)
			}
		}

		sort.Slice(matchedAddrs, func(i, j int) bool {
			return matchedAddrs[i].String() < matchedAddrs[j].String()
		})

		if len(matchedAddrs) > 0 {
			infos = append(infos, InterfaceInfo{
				Interface: i,
				Addrs:     matchedAddrs,
			})
		}
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Interface.Name < infos[j].Interface.Name
	})

	return infos, nil
}

type InterfaceMgr struct {
	interfaces []InterfaceInfo
	cidr       *net.IPNet
}

func NewInterfaceMgr(cidr *net.IPNet) (*InterfaceMgr, error) {
	interfaces, err := GetInterfaces(cidr)
	if len(interfaces) == 0 {
		log.Warn("No interfaces")
	}
	for _, i := range interfaces {
		log.WithField("interface", i.Interface.Name).WithField("addrs", i.Addrs).Info("Interface found")
	}
	if err != nil {
		return nil, err
	}

	return &InterfaceMgr{
		interfaces: interfaces,
		cidr:       cidr,
	}, nil
}

func (i *InterfaceMgr) GetInterfaces() []InterfaceInfo {
	return i.interfaces
}

func (i *InterfaceMgr) CheckChanged() ([]InterfaceInfo, bool) {
	interfaces, changed := i.checkChangedInner()

	if changed {
		if len(interfaces) == 0 {
			log.Warn("Interface changed, no new interfaces")
		}
		for _, i := range interfaces {
			log.WithField("interface", i.Interface.Name).WithField("addrs", i.Addrs).Info("Interface changed")
		}
	}

	return interfaces, changed
}

func (i *InterfaceMgr) checkChangedInner() ([]InterfaceInfo, bool) {
	interfaces, err := GetInterfaces(i.cidr)
	if err != nil {
		return nil, false
	}

	if len(interfaces) != len(i.interfaces) {
		return interfaces, true
	}

	for j, iface := range interfaces {
		if iface.Interface.Name != i.interfaces[j].Interface.Name {
			return interfaces, true
		}
		if len(iface.Addrs) != len(i.interfaces[j].Addrs) {
			return interfaces, true
		}
		for k, addr := range iface.Addrs {
			if addr.String() != i.interfaces[j].Addrs[k].String() {
				return interfaces, true
			}
		}
	}

	return nil, false
}
