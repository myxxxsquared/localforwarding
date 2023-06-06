package localforwardingapp

import (
	"net"
	"time"

	"github.com/myxxxsquared/localforwarding/localforwardingapp/comm"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/interfacemgr"
	"github.com/myxxxsquared/localforwarding/localforwardingapp/packagemgr"
)

type Daemon struct {
	cidrs        []*net.IPNet
	local_cidrs  []*net.IPNet
	main         bool
	packets      *packagemgr.PackageMgr
	server       *daemonServer
	client       *daemonClient
	shuttingdown bool
	port         int
	interfaces   *interfacemgr.InterfaceMgr
	listener     *net.UDPConn
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

	local_cidrs := []*net.IPNet{}
	for _, cidr := range config.LocalCidrs {
		_, parsedCidr, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		local_cidrs = append(local_cidrs, parsedCidr)
	}

	password := []byte(config.Password)

	interfaces, err := interfacemgr.NewInterfaceMgr(cidrs)
	if err != nil {
		return nil, err
	}

	return &Daemon{
		cidrs:        cidrs,
		local_cidrs:  local_cidrs,
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
	for _, cidr := range d.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *Daemon) sendPacket(
	msgType comm.MsgType,
	clientIP net.IP,
	serverIP net.IP,
	conn *net.UDPConn,
	dst *net.UDPAddr) error {
	msg := comm.NewPacket(msgType, clientIP, serverIP)
	sending, err := d.packets.EncodePackage(msg.Encode())
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
			break
		}
		decoded, err := d.packets.DecodePackage(buf[:n])
		if err != nil {
			continue
		}
		packet := comm.Decode(decoded)
		if packet == nil {
			continue
		}
		packetWithAddr := packetFromAddr{
			packet: packet,
			addr:   addr,
		}
		ch <- &packetWithAddr
	}
}

const UDP_TIMEOUT time.Duration = 5 * time.Duration(time.Second)
