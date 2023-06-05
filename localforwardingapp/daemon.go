package localforwardingapp

import (
	"net"

	"github.com/myxxxsquared/localforwarding/localforwardingapp/comm"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/packagemgr"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Cidr     string `yaml:"cidr"`
	Main     bool   `yaml:"main"`
	Password string `yaml:"password"`
}

type Daemon struct {
	cidr         *net.IPNet
	main         bool
	packets      *packagemgr.PackageMgr
	server       *daemonServer
	shuttingdown bool
}

type daemonServer struct {
	listener *net.UDPConn
}

type serverConn struct {
	serverIP net.IP
	clientIP net.IP
	status   comm.ConnStatus
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
		cidr:         cidr,
		main:         config.Main,
		packets:      packagemgr.NewPackageMgr(password),
		shuttingdown: false,
	}, nil
}

func (d *Daemon) Start() error {
	if d.main {
		return d.startServer()
	}
	return nil
}

func (d *Daemon) Stop() {
	if d.main {
		d.stopServer()
	}
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

func (d *Daemon) startServer() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 6698,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.WithError(err).Error("Error listening")
		return err
	}

	d.server = &daemonServer{}
	d.server.listener = conn

	go d.listenServer()

	return nil
}

func (d *Daemon) listenServer() {
	for {
		buffer := make([]byte, 1600)
		n, addr, err := d.server.listener.ReadFromUDP(buffer)
		if err != nil {
			if d.shuttingdown {
				break
			} else {
				log.WithError(err).Error("Error reading from udp")
				continue
			}
		}

		enclosed, err := d.packets.DecodePackage(buffer[:n])
		if err != nil {
			log.WithField("client", addr).WithError(err).Warn("Invalid packet from client.")
		}
		packet := comm.Decode(enclosed)
		if packet == nil {
			log.WithField("client", addr).Warn("Failed to decode packet from client.")
		}

	}
}

func (d *Daemon) stopServer() {
	if d.server != nil && d.server.listener != nil {
		d.server.listener.Close()
	}
}

// server port udp 6698
