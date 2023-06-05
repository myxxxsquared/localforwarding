package interfacemgr

import (
	"net"

	log "github.com/sirupsen/logrus"
)

type InterfaceInfo struct {
	i     *net.Interface
	addrs []*net.IPNet
}

func GetInterfaces(cidrs []*net.IPNet) ([]InterfaceInfo, error) {
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
			hasCidr := false
			for _, cidr := range cidrs {
				if cidr.Contains(netaddr.IP) {
					hasCidr = true
					break
				}
			}
			if hasCidr {
				matchedAddrs = append(matchedAddrs, netaddr)
			}
		}

		if len(matchedAddrs) > 0 {
			infos = append(infos, InterfaceInfo{
				i:     &i,
				addrs: matchedAddrs,
			})
		}
	}

	return infos, nil
}
