package localforwardingapp

import (
	"net"
	"time"

	"github.com/myxxxsquared/localforwarding/localforwardingapp/comm"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/interfacemgr"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/iptablesmgr"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/packagemgr"
	cmap "github.com/orcaman/concurrent-map/v2"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Cidrs    []string `yaml:"cidr"`
	Main     bool     `yaml:"main"`
	Password string   `yaml:"password"`
	Port     int      `yaml:"port"`
}

type Daemon struct {
	cidrs        []*net.IPNet
	main         bool
	packets      *packagemgr.PackageMgr
	server       *daemonServer
	shuttingdown bool
	port         int
	interfaces   *interfacemgr.InterfaceMgr
}

type daemonServer struct {
	listener      *net.UDPConn
	clientUdpConn *cmap.ConcurrentMap[string, chan struct{}]
	iptables      *iptablesmgr.IPTablesMgr
	clientRenew   *cmap.ConcurrentMap[string, chan struct{}]
}

func NewDaemon(config *Config) (*Daemon, error) {
	cidrs := []*net.IPNet{}
	for _, cidr := range config.Cidrs {
		_, parsedCidr, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, parsedCidr)
	}

	password := []byte(config.Password)

	interfaces, err := interfacemgr.NewInterfaceMgr(cidrs)
	if err != nil {
		return nil, err
	}

	return &Daemon{
		cidrs:        cidrs,
		main:         config.Main,
		packets:      packagemgr.NewPackageMgr(password),
		shuttingdown: false,
		port:         config.Port,
		interfaces:   interfaces,
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

func (d *Daemon) startServer() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: d.port,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.WithError(err).Error("Error listening")
		return err
	}

	d.server = &daemonServer{}
	d.server.listener = conn
	m := cmap.New[chan struct{}]()
	d.server.clientUdpConn = &m
	m2 := cmap.New[chan struct{}]()
	d.server.clientRenew = &m2
	d.server.iptables = iptablesmgr.NewIPTablesMgr()

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
			continue
		}

		switch packet.Type {
		case comm.MsgTypeDiscovery:
			d.handleDiscovery(addr, packet)
		case comm.MsgTypeAck:
			d.handleAck(addr, packet)
		case comm.MsgTypeRenew:
			d.handleRenew(addr, packet)
		default:
			log.WithField("client", addr).Warn("Invalid packet type from client.")
		}
	}
}

func (d *Daemon) isInCidr(ip net.IP) bool {
	for _, cidr := range d.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *Daemon) serveClient(clientIP net.IP, addr *net.UDPAddr, ch chan struct{}) {
	succ := false
	select {
	case _, ok := <-ch:
		if ok {
			log.WithField("client", addr).Info("Client acked.")
			succ = true
		} else {
			log.WithField("client", addr).Warn("Client closed.")
		}
	case <-time.After(5 * time.Second):
		log.WithField("client", addr).Warn("Client ACK timeout.")
	}
	var chRenew chan struct{}
	if succ {
		chRenew = make(chan struct{}, 1)
		d.server.clientRenew.Set(clientIP.String(), chRenew)
	}
	d.server.clientUdpConn.Remove(addr.String())

	if !succ {
		return
	}

	d.server.iptables.Add(clientIP)
	defer d.server.iptables.Remove(clientIP)

	for {
		select {
		case <-chRenew:
			log.WithField("client", addr).Info("Client renewed.")
		case <-time.After(30 * time.Minute):
			log.WithField("client", addr).Warn("Client renew timeout.")
			return
		}
	}
}

func (d *Daemon) handleDiscovery(addr *net.UDPAddr, packet *comm.Packet) {
	clientIP := addr.IP.To4()
	if clientIP == nil {
		log.WithField("client", addr).Warn("Client IP is not IPv4.")
		return
	}
	if !net.IP.Equal(clientIP, packet.Client) {
		log.WithField("client", addr).Warn("Client IP mismatch.")
		return
	}
	if !d.isInCidr(packet.Client) {
		log.WithField("client", addr).Warn("Client IP not in CIDR.")
		return
	}

	oldCh, ok := d.server.clientRenew.Get(packet.Client.String())
	if ok {
		oldCh <- struct{}{}
		log.WithField("client", addr).Info("Client renewed.")
		return
	}

	oldCh, ok = d.server.clientUdpConn.Get(addr.String())
	if ok {
		close(oldCh)
		log.WithField("client", addr).Info("Client reconnected.")
	}

	var serverIP net.IP

	interfaces := d.interfaces.GetInterfaces()
	for _, iface := range interfaces {
		for _, addr := range iface.Addrs {
			if addr.Contains(clientIP) {
				serverIP = addr.IP
				break
			}
		}
		if serverIP != nil {
			break
		}
	}

	assignPacket := comm.NewPacket(comm.MsgTypeAssign, packet.Client, serverIP)
	sending, err := d.packets.EncodePackage(assignPacket.Encode())
	if err != nil {
		log.WithField("client", addr).WithError(err).Warn("Failed to encode assign packet.")
		return
	}

	clientUdpChan := make(chan struct{}, 1)
	d.server.clientUdpConn.Set(addr.String(), clientUdpChan)
	d.server.listener.WriteToUDP(sending, addr)
	go d.serveClient(packet.Client, addr, clientUdpChan)
}

func (d *Daemon) handleAck(addr *net.UDPAddr, packet *comm.Packet) {
	clientIP := addr.IP.To4()
	if clientIP == nil {
		log.WithField("client", addr).Warn("Client IP is not IPv4.")
		return
	}
	if !net.IP.Equal(clientIP, packet.Client) {
		log.WithField("client", addr).Warn("Client IP mismatch.")
		return
	}

	ch, ok := d.server.clientUdpConn.Get(addr.String())
	if !ok {
		log.WithField("client", addr).Warn("Client not found.")
		return
	}
	select {
	case ch <- struct{}{}:
		break
	default:
		break
	}
}

func (d *Daemon) handleRenew(addr *net.UDPAddr, packet *comm.Packet) {
	clientIP := addr.IP.To4()
	if clientIP == nil {
		log.WithField("client", addr).Warn("Client IP is not IPv4.")
		return
	}
	if !net.IP.Equal(clientIP, packet.Client) {
		log.WithField("client", addr).Warn("Client IP mismatch.")
		return
	}

	ch, ok := d.server.clientRenew.Get(addr.IP.String())
	if !ok {
		log.WithField("client", addr).Warn("Client not found.")
		return
	}
	select {
	case ch <- struct{}{}:
		break
	default:
		break
	}
}

func (d *Daemon) stopServer() {
	d.shuttingdown = true
	if d.server != nil && d.server.listener != nil {
		d.server.listener.Close()
	}
	if d.server != nil && d.server.iptables != nil {
		d.server.iptables.SetShutdown()
		d.server.iptables.Reset()
	}
}

func (d *Daemon) runClient() {

}

func (d *Daemon) startClient() {
	go d.runClient()
}

func (d *Daemon) stopClient() {
	d.shuttingdown = true
}
