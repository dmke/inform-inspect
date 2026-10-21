// Package inform decodes Ubiquiti Unifi inform packets: it parses the
// clear text header and decrypts/decompresses the payload.
package inform

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"

	"github.com/klauspost/compress/snappy"
)

// Packet represents an HTTP POST request from an Unifi device to
// the controllers /inform URL.
type Packet struct {
	PacketVersion  uint32           // version of the packet
	PayloadVersion uint32           // version of the payload
	MAC            net.HardwareAddr // Unifi device's MAC address
	Flags          flags            // 0x01 = encrypted, 0x02 = compressed
	IV             []byte           // AES-128-CBC initialization vector
	Payload        []byte           // payload (usually JSON)

	rawHeader []byte // rawHeader, needed as AAD for AES-GCM decryption
}

// defaultMaxPayloadSize is far above real payloads, which are a few KiB.
const defaultMaxPayloadSize = 4 << 20

var maxPayloadSize atomic.Int64

func init() {
	maxPayloadSize.Store(defaultMaxPayloadSize)
}

// SetMaxPayloadSize limits packet payloads to n bytes, both as sent and
// once decompressed; larger ones fail to decode. The default is 4 MiB.
// It is safe to call while other goroutines decode packets.
func SetMaxPayloadSize(n int) {
	maxPayloadSize.Store(int64(n))
}

// ReadPacket tries to decode the input into a Packet instance.
//
// The reader is read from twice: once to fetch the header (which has a
// fixed size), and another time to read the body (its length is encoded
// in the header). This means, that the reader is not necessarily
// consumed until EOF.
//
// The returned Packet is nil if there's an error. You should not access
// its payload directly, but use the Data() function, which takes care
// of decrypting and decompressing (if necessary).
//
// Use ParsePacket if you have already obtained a full copy of the packet.
func ReadPacket(r io.Reader) (*Packet, error) {
	head := make([]byte, headerLength)
	if _, err := io.ReadFull(r, head); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errIncompletePacket("header too short")
		}
		return nil, err
	}

	pkt := &Packet{}
	if _, err := pkt.ReadHeader(head); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, pkt.Payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errIncompletePacket("payload too short")
		}
		return nil, err
	}

	return pkt, nil
}

// ParsePacket tries to decode the input into a Packet instance.
//
// The returned Packet is nil if there's an error. You should not access
// its payload directly, but use the Data() function, which takes care
// of decrypting and decompressing (if necessary).
//
// Use ReadPacket if you have an io.Reader.
func ParsePacket(body []byte) (*Packet, error) {
	pkt := &Packet{}
	off, err := pkt.ReadHeader(body)
	if err != nil {
		return nil, err
	}

	if len(body[off:]) < len(pkt.Payload) {
		return nil, errIncompletePacket("payload too short")
	}

	copy(pkt.Payload, body[off:])
	return pkt, nil
}

// ReadHeader decodes the packet header from head and returns the number
// of bytes consumed. It allocates the payload buffer, but does not fill
// it, and rejects payloads over the limit set with SetMaxPayloadSize.
// Both ReadPacket and ParsePacket call this for you.
func (p *Packet) ReadHeader(head []byte) (n int, err error) {
	if len(head) < headerLength {
		return 0, errIncompletePacket("header too short")
	}
	p.rawHeader = bytes.Clone(head[:headerLength])

	for _, f := range fieldOrder {
		curr := head[n : n+f.length]
		switch f.name {
		case headerMagic:
			if string(curr) != "TNBU" {
				return n, errInvalidMagic
			}
		case headerPayloadLength:
			val := binary.BigEndian.Uint32(curr)
			if int64(val) > maxPayloadSize.Load() {
				return n, errPayloadTooLarge
			}
			p.Payload = make([]byte, val)
		default:
			p.update(f.name, curr)
		}
		n += f.length
	}

	if len(p.Payload) == 0 {
		return n, errIncompletePacket("header does not define payload length")
	}

	return n, nil
}

// update applies a partial update of the field with the given name.
func (p *Packet) update(name headerField, data []byte) {
	switch name {
	case headerPacketVersion:
		p.PacketVersion = binary.BigEndian.Uint32(data)
	case headerMAC:
		p.MAC = net.HardwareAddr(bytes.Clone(data))
	case headerFlags:
		p.Flags = flags(binary.BigEndian.Uint16(data))
	case headerIV:
		p.IV = bytes.Clone(data)
	case headerPayloadVersion:
		p.PayloadVersion = binary.BigEndian.Uint32(data)
	}
}

// Data deflates and decrypts the payload (if necessary).
func (p *Packet) Data(key []byte) (res []byte, err error) {
	res = p.Payload

	if p.Flags&AESEncrypted != 0 {
		gcm := p.Flags&GCMMode != 0
		if res, err = aesDecrypt(key, p, gcm); err != nil {
			return nil, err
		}
	}

	if p.Flags&ZlibCompressed != 0 {
		r := bytes.NewReader(res)
		if res, err = zlibDecompress(r); err != nil {
			return nil, err
		}
	}

	if p.Flags&SnappyCompressed != 0 {
		if res, err = snappyDecompress(res); err != nil {
			return nil, err
		}
	}

	return
}

// snappyDecompress decompresses data using Snappy, up to the payload
// size limit.
func snappyDecompress(data []byte) ([]byte, error) {
	// Decode allocates the claimed length before validating the data
	n, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, err
	}
	if int64(n) > maxPayloadSize.Load() {
		return nil, errPayloadTooLarge
	}
	return snappy.Decode(nil, data)
}

// aesDecrypt decodes the payload with the given key. The key, and in CBC
// mode the IV, must be 16 bytes long.
func aesDecrypt(key []byte, p *Packet, gcm bool) ([]byte, error) {
	if len(key) != 16 {
		return nil, errInvalidKey
	}

	if !gcm && len(p.Payload)%aes.BlockSize != 0 {
		return nil, errInvalidPadding("data is not padded")
	}
	if !gcm && len(p.IV) != aes.BlockSize {
		return nil, errInvalidIV
	}

	// err would be a crypto.KeySizeError, which is handled above
	block, _ := aes.NewCipher(key)

	if gcm {
		aead, err := cipher.NewGCMWithNonceSize(block, len(p.IV))
		if err != nil {
			return nil, err
		}
		// GCM is a stream mode, hence no padding to remove
		return aead.Open(nil, p.IV, p.Payload, p.rawHeader)
	}

	plaintext := make([]byte, len(p.Payload))
	mode := cipher.NewCBCDecrypter(block, p.IV)
	mode.CryptBlocks(plaintext, p.Payload)

	return pkcs7unpad(plaintext)
}

// pkcs7unpad removes padding from a decoded stream.
func pkcs7unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errInvalidPadding("no data")
	}
	c := b[len(b)-1]
	n := int(c)
	// same error as below, so the reason leaks nothing about the plaintext
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, errInvalidPadding("structure invalid")
	}
	for _, pad := range b[len(b)-n:] {
		if pad != c {
			return nil, errInvalidPadding("structure invalid")
		}
	}
	return b[:len(b)-n], nil
}

// zlibDecompress decompresses data using zlib, up to the payload size
// limit.
func zlibDecompress(r io.Reader) ([]byte, error) {
	z, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer z.Close()

	// one byte over the limit tells a payload at the limit from a larger one
	limit := maxPayloadSize.Load()
	res, err := io.ReadAll(io.LimitReader(z, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(res)) > limit {
		return nil, errPayloadTooLarge
	}
	return res, nil
}
