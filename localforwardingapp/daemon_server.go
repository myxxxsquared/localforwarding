package localforwardingapp

import (
	"net"
	"time"

	"github.com/myxxxsquared/localforwarding/localforwardingapp/comm"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/iptablesmgr"
	cmap "github.com/orcaman/concurrent-map/v2"
	log "github.com/sirupsen/logrus"
)

type daemonServer struct {
	clientUdpConn *cmap.ConcurrentMap[string, chan struct{}]
	iptables      *iptablesmgr.IPTablesMgr
	clientRenew   *cmap.ConcurrentMap[string, chan struct{}]
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
	d.listener = conn
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
		n, addr, err := d.listener.ReadFromUDP(buffer)
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

func (d *Daemon) serveServer(clientIP net.IP, addr *net.UDPAddr, ch chan struct{}) {
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
	d.listener.WriteToUDP(sending, addr)
	go d.serveServer(packet.Client, addr, clientUdpChan)
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
	if d.server != nil && d.listener != nil {
		d.listener.Close()
	}
	if d.server != nil && d.server.iptables != nil {
		d.server.iptables.SetShutdown()
		d.server.iptables.Reset()
	}
}

