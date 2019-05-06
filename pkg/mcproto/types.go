package mcproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

type Packet struct {
	Length   int
	PacketID int
	Data     *bytes.Buffer
}

const PacketIdHandshake = 0x00

type Handshake struct {
	ProtocolVersion int
	ServerAddress   string
	ServerPort      uint16
	NextState       int
}

type ByteReader interface {
	ReadByte() (byte, error)
}

func ReadString(reader io.Reader) (val string, err error) {
	length, err := ReadVarInt(reader)
	if err != nil {
		return
	}
	if length < 0 {
		err = errors.New(fmt.Sprintf("Decode, String length is belowero: %d", length))
		return
	}
	if length > 1048576 { // 2^(21-1)
		err = errors.New(fmt.Sprintf("Decode, String length is above maximum: %d", length))
		return
	}
	bytes := make([]byte, length)
	_, err = reader.Read(bytes)
	if err != nil {
		return
	}
	val = string(bytes)
	return
}

func ReadVarInt(reader io.Reader) (result int, err error) {
	var bytes byte = 0
	var b byte

	for {
		b, err = ReadUint8(reader)
		if err != nil {
			return
		}
		result |= int(uint(b&0x7F) << uint(bytes*7))
		bytes++
		if bytes > 5 {
			err = errors.New("Decode, VarInt is too long")
			return
		}
		if (b & 0x80) == 0x80 {
			continue
		}
		break
	}

	return
}

func ReadBool(reader io.Reader) (val bool, err error) {
	uval, err := ReadUint8(reader)
	if err != nil {
		return
	}
	val = uval != 0
	return
}

func ReadInt8(reader io.Reader) (val int8, err error) {
	uval, err := ReadUint8(reader)
	val = int8(uval)
	return
}

func ReadUint8(reader io.Reader) (val uint8, err error) {
	var protocol [1]byte
	_, err = reader.Read(protocol[:1])
	val = protocol[0]
	return
}

func ReadInt16(reader io.Reader) (val int16, err error) {
	uval, err := ReadUint16(reader)
	val = int16(uval)
	return
}

func ReadUint16(reader io.Reader) (val uint16, err error) {
	var protocol [2]byte
	_, err = reader.Read(protocol[:2])
	val = binary.BigEndian.Uint16(protocol[:2])
	return
}

func ReadInt32(reader io.Reader) (val int32, err error) {
	uval, err := ReadUint32(reader)
	val = int32(uval)
	return
}

func ReadUint32(reader io.Reader) (val uint32, err error) {
	var protocol [4]byte
	_, err = reader.Read(protocol[:4])
	val = binary.BigEndian.Uint32(protocol[:4])
	return
}

func ReadInt64(reader io.Reader) (val int64, err error) {
	uval, err := ReadUint64(reader)
	val = int64(uval)
	return
}

func ReadUint64(reader io.Reader) (val uint64, err error) {
	var protocol [8]byte
	_, err = reader.Read(protocol[:8])
	val = binary.BigEndian.Uint64(protocol[:8])
	return
}

func ReadFloat32(reader io.Reader) (val float32, err error) {
	ival, err := ReadUint32(reader)
	val = math.Float32frombits(ival)
	return
}

func ReadFloat64(reader io.Reader) (val float64, err error) {
	ival, err := ReadUint64(reader)
	val = math.Float64frombits(ival)
	return
}

func ReadPacket(reader io.Reader) (*Packet, error) {
	// borrowed from https://github.com/justblender/gominet/blob/master/protocol/connection.go
	length, err := ReadVarInt(reader)
	if err != nil {
		return nil, err
	}

	if length < 0 || length > 1048576 { // 2^(21-1)
		return nil, errors.New("VarInt has invalid size")
	}

	payload := make([]byte, length)
	_, err = io.ReadFull(reader, payload)

	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(payload)
	id, err := ReadVarInt(buffer)

	if err != nil {
		return nil, err
	}

	return &Packet{
		Length:   length,
		PacketID: id,
		Data:     buffer,
	}, nil
}

func ReadHandshake(buffer *bytes.Buffer) (*Handshake, error) {

	handshake := &Handshake{}
	var err error

	handshake.ProtocolVersion, err = ReadVarInt(buffer)
	if err != nil {
		return nil, err
	}

	handshake.ServerAddress, err = ReadString(buffer)
	if err != nil {
		return nil, err
	}

	handshake.ServerPort, err = ReadUint16(buffer)
	if err != nil {
		return nil, err
	}

	nextState, err := ReadVarInt(buffer)
	if err != nil {
		return nil, err
	}
	handshake.NextState = nextState
	return handshake, nil
}
