package localforwardingapp

import (
	"net"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	Cidr     string `yaml:"cidr"`
	Main     bool   `yaml:"main"`
	Password string `yaml:"password"`
}

type Daemon struct {
	cidr     *net.IPNet
	main     bool
	password []byte
}

type interfaceInfo struct {
	i     *net.Interface
	addrs []*net.IPNet
}

func NewDaemon(config *Config) (*Daemon, error) {
	_, cidr, err := net.ParseCIDR(config.Cidr)
	if err != nil {
		return nil, err
	}

	password := []byte(config.Password)

	return &Daemon{
		cidr:     cidr,
		main:     config.Main,
		password: password,
	}, nil
}

func (d *Daemon) Start() error {
	d.getInterfaces()
	return nil
}

func (d *Daemon) Stop() error {
	return nil
}

func (d *Daemon) getInterfaces() ([]interfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("Error getting interfaces")
		return nil, err
	}

	infos := []interfaceInfo{}

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
			if d.cidr.Contains(netaddr.IP) {
				matchedAddrs = append(matchedAddrs, netaddr)
			}
		}

		if len(matchedAddrs) > 0 {
			infos = append(infos, interfaceInfo{
				i:     &i,
				addrs: matchedAddrs,
			})
		}
	}

	return infos, nil
}

// server port udp 6698