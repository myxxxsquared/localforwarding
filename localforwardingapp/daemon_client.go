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
	lastRenew     time.Time
}

func (d *Daemon) clientRenew() bool {
	if !d.client.connected {
		return false
	}

	conn, err := net.ListenPacket("udp", fmt.Sprintf("%s:0", d.client.clientIP.String()))
	if err != nil {
		log.WithError(err).Error("Error listening")
		return false
	}
	defer conn.Close()
	connUdp := conn.(*net.UDPConn)

	serverAddr := &net.UDPAddr{
		IP:   d.client.serverIP,
		Port: d.port,
	}

	err = d.sendPacket(comm.MsgTypeRenew, d.client.clientIP, d.client.serverIP, connUdp, serverAddr)
	if err != nil {
		log.WithError(err).Error("Error sending renew")
		return false
	}

	log.WithFields(log.Fields{
		"client": d.client.clientIP,
		"server": d.client.serverIP,
	}).Info("Renew sent")

	recv_chan := make(chan *packetFromAddr)
	go d.startRecvPacket(recv_chan, connUdp)

	select {
	case packet, ok := <-recv_chan:
		if !ok {
			log.Error("Error receiving renew ack")
			return false
		}
		if packet.packet.Type != comm.MsgTypeAck {
			log.Error("Error receiving renew ack")
			return false
		}
		if !d.client.serverIP.Equal(packet.packet.Server) {
			log.Error("Error receiving renew ack")
			return false
		}
		if !d.client.clientIP.Equal(packet.packet.Client) {
			log.Error("Error receiving renew ack")
			return false
		}
	case <-time.After(UDP_TIMEOUT):
		log.Error("Error receiving renew ack")
		return false
	}

	log.WithFields(log.Fields{
		"client": d.client.clientIP,
		"server": d.client.serverIP,
	}).Info("Renewed")

	d.client.lastRenew = time.Now()

	return true
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
	defer conn.Close()
	connUdp := conn.(*net.UDPConn)
	broad_cast_addr := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: d.port,
	}

	err = d.sendPacket(comm.MsgTypeDiscovery, clientIP, nil, connUdp, broad_cast_addr)
	if err != nil {
		log.WithError(err).Error("Error sending discovery")
		return
	}

	log.WithField("client", clientIP).Info("Discovery sent")

	recv_chan := make(chan *packetFromAddr)
	go d.startRecvPacket(recv_chan, connUdp)

	var serverIP net.IP
	var serverAddr *net.UDPAddr

	select {
	case packet, ok := <-recv_chan:
		if !ok {
			log.Error("Error receiving discovery ack")
			return
		}
		if packet.packet.Type != comm.MsgTypeAssign {
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

	log.WithFields(log.Fields{
		"client": clientIP,
		"server": serverIP,
	}).Info("Discovery assign received")

	err = d.sendPacket(comm.MsgTypeAck, clientIP, serverIP, connUdp, serverAddr)
	if err != nil {
		log.WithError(err).Error("Error sending ack")
		return
	}

	log.WithFields(log.Fields{
		"client": clientIP,
		"server": serverIP,
	}).Info("Ack sent")

	select {
	case packet, ok := <-recv_chan:
		if !ok {
			log.Error("Error receiving serverOK, no packet")
			return
		}
		if packet.packet.Type != comm.MsgTypeServerOK {
			log.Error("Error receiving serverOK, invalid type")
			return
		}
		if !serverIP.Equal(packet.packet.Server) {
			log.Error("Error receiving serverOK, invalid server")
			return
		}
		if !clientIP.Equal(packet.packet.Client) {
			log.Error("Error receiving serverOK, invalid client")
			return
		}
	case <-time.After(UDP_TIMEOUT):
		log.Error("Error receiving serverOK, timeout")
		return
	}

	err = d.client.routemgr.Set(first_if.Interface, clientIP, serverIP, d.local_cidrs)
	if err != nil {
		log.WithError(err).Error("Error setting route")
		return
	}

	log.WithFields(log.Fields{
		"client": clientIP,
		"server": serverIP,
	}).Info("Route set")

	d.client.connected = true
	d.client.clientIP = clientIP
	d.client.serverIP = serverIP
	d.client.lastRenew = time.Now()
}

func (d *Daemon) runClient() {
	for {
		if d.shuttingdown {
			break
		}
		d.clinetHandshake()
	connected_for:
		for {
			if !d.client.connected {
				break
			}
			if d.shuttingdown {
				break
			}
			select {
			case <-d.client.serverChanged:
				d.client.connected = false
				d.client.routemgr.Reset()
				d.client.clientIP = nil
				d.client.serverIP = nil
				break connected_for
			case <-time.After(d.durationRetry):
				if time.Since(d.client.lastRenew) > d.durationRenew {
					succ := false
					for i := 0; i < 10; i++ {
						if d.clientRenew() {
							succ = true
							break
						}
					}
					if !succ {
						d.client.connected = false
						d.client.routemgr.Reset()
						d.client.clientIP = nil
						d.client.serverIP = nil
						break connected_for
					}
				}
				if _, changed := d.interfaces.CheckChanged(); changed {
					d.client.connected = false
					d.client.routemgr.Reset()
					d.client.clientIP = nil
					d.client.serverIP = nil
					break connected_for
				}
			}
		}
		time.Sleep(d.durationRetry)
	}
}

func (d *Daemon) listenClient() {
	ch := make(chan *packetFromAddr)
	go d.startRecvPacket(ch, d.listener)
	for {
		recved, ok := <-ch
		if !ok {
			if d.shuttingdown {
				break
			} else {
				log.Fatal("Error receiving packet from client.")
			}
		}
		packet := recved.packet
		addr := recved.addr

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
	log.Info("Stopping client")
	d.shuttingdown = true
	d.listener.Close()
	d.client.routemgr.Shutdown()
}
