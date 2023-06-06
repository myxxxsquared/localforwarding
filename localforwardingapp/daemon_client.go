package localforwardingapp

import (
	"fmt"
	"net"
	"time"

	"github.com/myxxxsquared/localforwarding/localforwardingapp/comm"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/routemgr"
	log "github.com/sirupsen/logrus"
)

type daemonClient struct {
	serverChanged chan struct{}
	routemgr      *routemgr.RouteMgr
	connected     bool
	clientIP      net.IP
	serverIP      net.IP
}

func (d *Daemon) clientRenew() {
	if !d.client.connected {
		return
	}

	conn, err := net.ListenPacket("udp", fmt.Sprintf("%s:0", d.client.clientIP.String()))
	if err != nil {
		log.WithError(err).Error("Error listening")
		return
	}
	connUdp := conn.(*net.UDPConn)

	recv_chan := make(chan *packetFromAddr)
	go d.startRecvPacket(recv_chan, connUdp)

	serverAddr := &net.UDPAddr{
		IP:   d.client.serverIP,
		Port: d.port,
	}

	err = d.sendPacket(comm.MsgTypeRenew, d.client.clientIP, nil, connUdp, serverAddr)
	if err != nil {
		log.WithError(err).Error("Error sending renew")
		return
	}

	select {
	case packet, ok := <-recv_chan:
		if !ok {
			log.Error("Error receiving renew ack")
			return
		}
		if packet.packet.Type != comm.MsgTypeAck {
			log.Error("Error receiving renew ack")
			return
		}
		if !d.client.serverIP.Equal(packet.packet.Server) {
			log.Error("Error receiving renew ack")
			return
		}
		if !d.client.clientIP.Equal(packet.packet.Client) {
			log.Error("Error receiving renew ack")
			return
		}
	case <-time.After(UDP_TIMEOUT):
		log.Error("Error receiving renew ack")
		return
	}
}

func (d *Daemon) clinetHandshake() {
	if d.client.connected {
		return
	}
	ifs := d.interfaces.GetInterfaces()
	if len(ifs) == 0 {
		log.Warn("No interfaces found.")
		return
	}

	first_if := ifs[0]
	first_if_addr := first_if.Addrs[0]
	clientIP := first_if_addr.IP

	conn, err := net.ListenPacket("udp", fmt.Sprintf("%s:0", clientIP.String()))
	if err != nil {
		log.WithError(err).Error("Error listening")
		return
	}
	connUdp := conn.(*net.UDPConn)
	broad_cast_addr := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: d.port,
	}

	recv_chan := make(chan *packetFromAddr)
	go d.startRecvPacket(recv_chan, connUdp)

	err = d.sendPacket(comm.MsgTypeDiscovery, clientIP, nil, connUdp, broad_cast_addr)
	if err != nil {
		log.WithError(err).Error("Error sending discovery")
		return
	}

	var serverIP net.IP
	var serverAddr *net.UDPAddr

	select {
	case packet, ok := <-recv_chan:
		if !ok {
			log.Error("Error receiving discovery ack")
			return
		}
		if packet.packet.Type != comm.MsgTypeAck {
			log.Error("Error receiving discovery ack")
			return
		}
		if !packet.addr.IP.Equal(packet.packet.Server) {
			log.Error("Error receiving discovery ack")
			return
		}
		if !clientIP.Equal(packet.packet.Client) {
			log.Error("Error receiving discovery ack")
			return
		}
		serverIP = packet.packet.Server
		serverAddr = packet.addr
	case <-time.After(UDP_TIMEOUT):
		log.Error("Error receiving discovery ack")
		return
	}

	err = d.sendPacket(comm.MsgTypeAck, clientIP, nil, connUdp, serverAddr)
	if err != nil {
		log.WithError(err).Error("Error sending ack")
		return
	}

	select {
	case packet, ok := <-recv_chan:
		if !ok {
			log.Error("Error receiving discovery ack")
			return
		}
		if packet.packet.Type != comm.MsgTypeServerOK {
			log.Error("Error receiving discovery ack")
			return
		}
		if !packet.addr.IP.Equal(packet.packet.Server) {
			log.Error("Error receiving discovery ack")
			return
		}
		if !packet.addr.IP.Equal(packet.packet.Client) {
			log.Error("Error receiving discovery ack")
			return
		}
	case <-time.After(UDP_TIMEOUT):
		log.Error("Error receiving discovery ack")
		return
	}

	err = d.client.routemgr.Set(*first_if.Interface, clientIP, serverIP, d.local_cidrs)
	if err != nil {
		log.WithError(err).Error("Error setting route")
		return
	}
	d.client.connected = true
	d.client.clientIP = clientIP
	d.client.serverIP = serverIP
}

func (d *Daemon) runClient() {
	for {
		if d.shuttingdown {
			break
		}
		d.clinetHandshake()
	}
}

func (d *Daemon) listenClient() {
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
		case comm.MsgTypeServerChanged:
			select {
			case d.client.serverChanged <- struct{}{}:
				break
			default:
				break
			}
		default:
			log.WithField("server", addr).Warn("Invalid packet type from server.")
		}
	}
}

func (d *Daemon) startClient() error {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: d.port,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.WithError(err).Error("Error listening")
		return err
	}

	d.listener = conn

	d.client = &daemonClient{}
	d.client.serverChanged = make(chan struct{}, 1)
	d.client.routemgr = routemgr.NewRouteMgr()

	go d.listenClient()
	go d.runClient()

	return nil
}

func (d *Daemon) stopClient() {
	d.shuttingdown = true
	d.listener.Close()
}
