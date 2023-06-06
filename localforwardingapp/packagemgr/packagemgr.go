package packagemgr

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

const SALT = "MRmLZi!gHQWBxYwmfSu4Y*88FY1c&qZ&"
const FORGET_DURATION = time.Minute * 10
const TORLANCE = time.Minute * 1

// 8 packetid
// 8 timestamp
// 8 contentlength
// contnet
// password
// 32 sha256
// total extra 56

type PackageMgr struct {
	password []byte

	idsLock   sync.Mutex
	usedIds1  map[uint64]bool
	usedIds2  map[uint64]bool
	lastClear time.Time
}

func NewPackageMgr(password []byte) *PackageMgr {
	return &PackageMgr{
		password:  password,
		idsLock:   sync.Mutex{},
		usedIds1:  map[uint64]bool{},
		usedIds2:  map[uint64]bool{},
		lastClear: time.Now(),
	}
}

func (m *PackageMgr) calcHash(p []byte) []byte {
	hasher := sha256.New()
	hasher.Write(m.password)
	hasher.Write([]byte(SALT))
	hasher.Write(p)
	return hasher.Sum(nil)
}

func (m *PackageMgr) EncodePackage(p []byte) ([]byte, error) {

	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	contentLength := uint64(len(p))
	currentTime := uint64(time.Now().UnixNano())

	result := make([]byte, 0, 56+contentLength)
	result = append(result, randomBytes...)
	result = binary.LittleEndian.AppendUint64(result, currentTime)
	result = binary.LittleEndian.AppendUint64(result, contentLength)
	result = append(result, p...)
	sum := m.calcHash(result)
	result = append(result, sum...)

	return result, nil
}

const (
	ErrInvalidPackageLen = iota
	ErrInvalidPackageTimestamp
	ErrInvalidPackageContentLen
	ErrInvalidPackageSum
	ErrInvalidPackageId
	ErrTooManyPackets
)

type ErrInvalidPackage struct {
	Reason int
}

func (e ErrInvalidPackage) Error() string {
	switch e.Reason {
	case ErrInvalidPackageLen:
		return "Invalid package length"
	case ErrInvalidPackageTimestamp:
		return "Invalid package timestamp"
	case ErrInvalidPackageContentLen:
		return "Invalid package content length"
	case ErrInvalidPackageSum:
		return "Invalid package sum"
	case ErrInvalidPackageId:
		return "Invalid package id"
	case ErrTooManyPackets:
		return "Too many packets"
	default:
		return "Invalid package"
	}
}

func (m *PackageMgr) processId(packetId uint64) bool {
	m.idsLock.Lock()
	defer m.idsLock.Unlock()

	if m.usedIds1[packetId] || m.usedIds2[packetId] {
		return false
	}
	m.usedIds1[packetId] = true

	if time.Since(m.lastClear) > FORGET_DURATION {
		m.lastClear = time.Now()
		m.usedIds2 = m.usedIds1
		m.usedIds1 = map[uint64]bool{}
	}

	return true
}

func (m *PackageMgr) DecodePackage(p []byte) ([]byte, error) {
	if len(p) < 56 {
		return nil, ErrInvalidPackage{Reason: ErrInvalidPackageLen}
	}

	packetId := binary.LittleEndian.Uint64(p[0:8])
	timestamp := binary.LittleEndian.Uint64(p[8:16])
	contentLength := binary.LittleEndian.Uint64(p[16:24])

	timeDelta := time.Since(time.Unix(0, int64(timestamp)))
	if timeDelta > TORLANCE || timeDelta < -TORLANCE {
		return nil, ErrInvalidPackage{Reason: ErrInvalidPackageTimestamp}
	}

	if len(p) != 56+int(contentLength) || contentLength > 1024 {
		return nil, ErrInvalidPackage{Reason: ErrInvalidPackageContentLen}
	}

	content := p[24 : 24+contentLength]

	sum := m.calcHash(p[0 : 24+contentLength])

	if !bytes.Equal(sum, p[24+contentLength:]) {
		return nil, ErrInvalidPackage{Reason: ErrInvalidPackageSum}
	}

	if !m.processId(packetId) {
		return nil, ErrInvalidPackage{Reason: ErrInvalidPackageId}
	}

	return content, nil
}
