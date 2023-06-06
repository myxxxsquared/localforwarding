package comm

import (
	"net"
)

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
	c = c.To4()
	s = s.To4()
	return &Packet{
		Type:   t,
		Client: c,
		Server: s,
	}
}

type EncodeErrorType int
type EncodeError struct {
	Reason EncodeErrorType
}

const (
	EncodeErrorClientIPLength EncodeErrorType = iota
	EncodeErrorServerIPLength
	EncodeErrorInvalidType
)

func (e *EncodeError) Error() string {
	switch e.Reason {
	case EncodeErrorClientIPLength:
		return "Invalid client IP length"
	case EncodeErrorServerIPLength:
		return "Invalid server IP length"
	case EncodeErrorInvalidType:
		return "Invalid type"
	default:
		return "Unknown error"
	}
}

func (p *Packet) Encode() ([]byte, error) {
	switch p.Type {
	case MsgTypeDiscovery:
		if len(p.Client) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorClientIPLength}
		}
		return append([]byte{'D'}, p.Client...), nil
	case MsgTypeAssign:
		if len(p.Client) != 4 || len(p.Server) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorClientIPLength}
		}
		return append(append([]byte{'A'}, p.Client...), p.Server...), nil
	case MsgTypeAck:
		if len(p.Client) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorClientIPLength}
		}
		if len(p.Server) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorServerIPLength}
		}
		return append(append([]byte{'K'}, p.Client...), p.Server...), nil
	case MsgTypeServerOK:
		if len(p.Client) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorClientIPLength}
		}
		if len(p.Server) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorServerIPLength}
		}
		return append(append([]byte{'S'}, p.Client...), p.Server...), nil
	case MsgTypeRenew:
		if len(p.Client) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorClientIPLength}
		}
		if len(p.Server) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorServerIPLength}
		}
		return append(append([]byte{'R'}, p.Client...), p.Server...), nil
	case MsgTypeServerChanged:
		if len(p.Server) != 4 {
			return nil, &EncodeError{Reason: EncodeErrorServerIPLength}
		}
		return append([]byte{'C'}, p.Server...), nil
	default:
		return nil, &EncodeError{Reason: EncodeErrorInvalidType}
	}
}

type DecodeErrorType int
type DecodeError struct {
	Reason DecodeErrorType
}

const (
	DecodeErrorInvalidLength DecodeErrorType = iota
	DecodeErrorInvalidType
)

func (e *DecodeError) Error() string {
	switch e.Reason {
	case DecodeErrorInvalidLength:
		return "Invalid length"
	case DecodeErrorInvalidType:
		return "Invalid type"
	default:
		return "Unknown error"
	}
}

func Decode(b []byte) (*Packet, error) {
	if len(b) < 1 {
		return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
	}
	switch b[0] {
	case 'D':
		if len(b) == 5 {
			return &Packet{
				Type:   MsgTypeDiscovery,
				Client: b[1:],
			}, nil
		} else {
			return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
		}
	case 'A':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeAssign,
				Client: b[1:5],
				Server: b[5:],
			}, nil
		} else {
			return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
		}
	case 'K':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeAck,
				Client: b[1:5],
				Server: b[5:],
			}, nil
		} else {
			return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
		}
	case 'S':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeServerOK,
				Client: b[1:5],
				Server: b[5:],
			}, nil
		} else {
			return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
		}
	case 'R':
		if len(b) == 9 {
			return &Packet{
				Type:   MsgTypeRenew,
				Client: b[1:5],
				Server: b[5:],
			}, nil
		} else {
			return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
		}
	case 'C':
		if len(b) == 5 {
			return &Packet{
				Type:   MsgTypeServerChanged,
				Server: b[1:],
			}, nil
		} else {
			return nil, &DecodeError{Reason: DecodeErrorInvalidLength}
		}
	default:
		return nil, &DecodeError{Reason: DecodeErrorInvalidType}
	}
}
