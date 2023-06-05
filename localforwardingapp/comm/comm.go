package comm

import "net"

// Discovery D{clientip}
// Assign A{clientip,serverip}
// Ack K{clientip,serverip}
// ServerOK S{clientip,serverip}

const (
	MsgTypeDiscovery = iota
	MsgTypeAssign
	MsgTypeAck
	MsgTypeServerOK
)

type MsgType int

func EncodePacketD(clientIP net.IP) []byte {
	return append([]byte("D"), clientIP...)
}

func EncodePacketA(clientIP, serverIP net.IP) []byte {
	return append(append([]byte("A"), clientIP...), serverIP...)
}

func EncodePacketK(clientIP, serverIP net.IP) []byte {
	return append(append([]byte("K"), clientIP...), serverIP...)
}

func EncodePacketS(clientIP, serverIP net.IP) []byte {
	return append(append([]byte("S"), clientIP...), serverIP...)
}

func GetMsgType(b []byte) (MsgType, bool) {
	if len(b) < 1 {
		return 0, false
	}
	switch b[0] {
	case 'D':
		return MsgTypeDiscovery, true
	case 'A':
		return MsgTypeAssign, true
	case 'K':
		return MsgTypeAck, true
	case 'S':
		return MsgTypeServerOK, true
	default:
		return 0, false
	}
}

func DecodePacketD(b []byte) (net.IP, bool) {
	if len(b) == 17 && b[0] == 'D' {
		return b[1:], true
	}
	if len(b) == 5 && b[0] == 'D' {
		return b[1:], true
	}
	return nil, false
}

func DecodePacketA(b []byte) (net.IP, net.IP, bool) {
	if len(b) == 33 && b[0] == 'A' {
		return b[1:17], b[17:], true
	}
	if len(b) == 9 && b[0] == 'A' {
		return b[1:5], b[5:], true
	}
	return nil, nil, false
}

func DecodePacketK(b []byte) (net.IP, net.IP, bool) {
	if len(b) == 33 && b[0] == 'K' {
		return b[1:17], b[17:], true
	}
	if len(b) == 9 && b[0] == 'K' {
		return b[1:5], b[5:], true
	}
	return nil, nil, false
}

func DecodePacketS(b []byte) (net.IP, net.IP, bool) {
	if len(b) == 33 && b[0] == 'S' {
		return b[1:17], b[17:], true
	}
	if len(b) == 9 && b[0] == 'S' {
		return b[1:5], b[5:], true
	}
	return nil, nil, false
}
