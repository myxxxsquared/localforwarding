package comm

import "net"

// Discovery D{clientip}
// Assign A{clientip,serverip}
// Ack K{clientip,serverip}
// ServerOK S{clientip,serverip}
// Renew R{clientip,serverip}
// ServerOK S{clientip,serverip}
// ServerChanged C{serverip}

const (
	MsgTypeDiscovery = iota
	MsgTypeAssign
	MsgTypeAck
	MsgTypeServerOK
	MsgTypeRenew
	MsgTypeServerChanged
)

const (
	ConnStatusNew = iota
	ConnStatusAcked
)

type ConnStatus int
type MsgType int

type Packet struct {
	Type   MsgType
	Client net.IP
	Server net.IP
}

func NewPacket(t MsgType, c, s net.IP) *Packet {
	return &Packet{
		Type:   t,
		Client: c,
		Server: s,
	}
}

func (p *Packet) Encode() []byte {
	switch p.Type {
	case MsgTypeDiscovery:
		if len(p.Client) != 4 {
			return nil
		}
		return append([]byte{'D'}, p.Client...)
	case MsgTypeAssign:
		if len(p.Client) != 4 || len(p.Server) != 4 {
			return nil
		}
		return append(append([]byte{'A'}, p.Client...), p.Server...)
	case MsgTypeAck:
		if len(p.Client) != 4 || len(p.Server) != 4 {
			return nil
		}
		return append(append([]byte{'K'}, p.Client...), p.Server...)
	case MsgTypeServerOK:
		if len(p.Client) != 4 || len(p.Server) != 4 {
			return nil
		}
		return append(append([]byte{'S'}, p.Client...), p.Server...)
	case MsgTypeRenew:
		if len(p.Client) != 4 || len(p.Server) != 4 {
			return nil
		}
		return append(append([]byte{'R'}, p.Client...), p.Server...)
	case MsgTypeServerChanged:
		if len(p.Server) != 4 {
			return nil
		}
		return append([]byte{'C'}, p.Server...)
	default:
		return nil
	}
}

func Decode(b []byte) *Packet {
	if len(b) < 1 {
		return nil
	}
	switch b[0] {
	case 'D':
		if len(b) == 5 {
			return &Packet{
				Type:   MsgTypeDiscovery,
				Client: b[1:],
			}
		} else {
			return nil
		}
	case 'A':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeAssign,
				Client: b[1:5],
				Server: b[5:],
			}
		} else {
			return nil
		}
	case 'K':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeAck,
				Client: b[1:5],
				Server: b[5:],
			}
		} else {
			return nil
		}
	case 'S':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeServerOK,
				Client: b[1:5],
				Server: b[5:],
			}
		} else {
			return nil
		}
	case 'R':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeRenew,
				Client: b[1:5],
				Server: b[5:],
			}
		} else {
			return nil
		}
	case 'C':
		if len(b) == 5 {
			return &Packet{
				Type:   MsgTypeServerChanged,
				Server: b[1:],
			}
		} else {
			return nil
		}
	default:
		return nil
	}
}
