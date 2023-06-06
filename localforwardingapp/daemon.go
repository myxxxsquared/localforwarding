package localforwardingapp

import (
	"net"
	"time"

	"github.com/myxxxsquared/localforwarding/localforwardingapp/comm"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/interfacemgr"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/packagemgr"
	log "github.com/sirupsen/logrus"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

type Daemon struct {
	cidr         *net.IPNet
	local_cidrs  []*net.IPNet
	main         bool
	packets      *packagemgr.PackageMgr
	server       *daemonServer
	client       *daemonClient
	shuttingdown bool
	port         int
	interfaces   *interfacemgr.InterfaceMgr
	listener     *net.UDPConn

	durationRenew     time.Duration
	durationKeepalive time.Duration
	durationRetry     time.Duration
}

func NewDaemon(config *Config) (*Daemon, error) {
	_, cidr, err := net.ParseCIDR(config.Cidr)
	if err != nil {
		return nil, err
	}

	local_cidrs := []*net.IPNet{}
	for _, cidr := range config.LocalCidrs {
		_, parsedCidr, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		local_cidrs = append(local_cidrs, parsedCidr)
	}

	password := []byte(config.Password)

	interfaces, err := interfacemgr.NewInterfaceMgr(cidr)
	if err != nil {
		return nil, err
	}

	return &Daemon{
		cidr:              cidr,
		local_cidrs:       local_cidrs,
		main:              config.Main,
		packets:           packagemgr.NewPackageMgr(password),
		shuttingdown:      false,
		port:              config.Port,
		interfaces:        interfaces,
		durationRenew:     time.Duration(config.DurationRenew) * time.Second,
		durationKeepalive: time.Duration(config.DurationKeepalive) * time.Second,
		durationRetry:     time.Duration(config.DurationRetry) * time.Second,
	}, nil
}

func (d *Daemon) checkCap() {
	c := cap.GetProc()
	ok, err := c.GetFlag(cap.Effective, cap.NET_ADMIN)
	if err != nil {
		log.WithError(err).Fatal("Error checking capabilities")
	}
	if !ok {
		log.Fatal("Insufficient capabilities")
	}
}

func (d *Daemon) Start() error {
	d.checkCap()

	if d.main {
		return d.startServer()
	} else {
		return d.startClient()
	}
}

func (d *Daemon) Stop() {
	if d.main {
		d.stopServer()
	} else {
		d.stopClient()
	}
}

func (d *Daemon) isInCidr(ip net.IP) bool {
	return d.cidr.Contains(ip)
}

func (d *Daemon) sendPacket(
	msgType comm.MsgType,
	clientIP net.IP,
	serverIP net.IP,
	conn *net.UDPConn,
	dst *net.UDPAddr) error {
	msg := comm.NewPacket(msgType, clientIP, serverIP)
	encoded, err := msg.Encode()
	if err != nil {
		return err
	}
	sending, err := d.packets.EncodePackage(encoded)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(sending, dst)
	return err
}

type packetFromAddr struct {
	packet *comm.Packet
	addr   *net.UDPAddr
}

func (d *Daemon) startRecvPacket(ch chan<- *packetFromAddr, conn *net.UDPConn) {
	defer close(ch)
	for {
		buf := make([]byte, 1600)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Warn("Error reading from UDP")
			break
		}
		decoded, err := d.packets.DecodePackage(buf[:n])
		if err != nil {
			log.WithError(err).Error("Error decoding package")
			continue
		}
		packet, err := comm.Decode(decoded)
		if err != nil {
			log.WithError(err).Error("Error decoding packet")
			continue
		}
		log.WithFields(log.Fields{"client": addr, "type": packet.Type}).Info("Received packet from UDP.")
		packetWithAddr := packetFromAddr{
			packet: packet,
			addr:   addr,
		}
		ch <- &packetWithAddr
	}
}

const UDP_TIMEOUT time.Duration = 5 * time.Duration(time.Second)
