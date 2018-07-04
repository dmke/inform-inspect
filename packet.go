package inform // import "github.com/dmke/inform-inspect"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"

	"github.com/golang/snappy"
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
func ReadPacket(r io.Reader) (*Packet, error) {
	head := make([]byte, headerLength)
	n, err := r.Read(head)
	if err != nil {
		return nil, err
	}
	if n != headerLength {
		return nil, errIncompletePacket("header too short")
	}

	off := 0
	pkt := &Packet{}
	for _, f := range fieldOrder {
		curr := head[off : off+f.length]
		switch f.name {
		case headerMagic:
			if string(curr) != "UBNT" {
				return nil, errInvalidMagic
			}
		case headerPayloadLength:
			val := binary.BigEndian.Uint32(curr)
			pkt.Payload = make([]byte, val)
		default:
			pkt.update(f.name, curr)
		}
		off += f.length
	}

	if len(pkt.Payload) == 0 {
		return nil, errIncompletePacket("header does not define payload length")
	}

	if _, err = io.ReadFull(r, pkt.Payload); err != nil {
		return nil, errIncompletePacket(err.Error())
	}

	return pkt, nil
}

// update applies a partial update of the field with the given name.
func (p *Packet) update(name headerField, data []byte) {
	switch name {
	case headerPacketVersion:
		p.PacketVersion = binary.BigEndian.Uint32(data)
	case headerMAC:
		p.MAC = net.HardwareAddr(data)
	case headerFlags:
		p.Flags = flags(binary.BigEndian.Uint16(data))
	case headerIV:
		p.IV = data
	case headerPayloadVersion:
		p.PayloadVersion = binary.BigEndian.Uint32(data)
	}
}

// Data deflates and decrypts the payload (if necessary).
func (p *Packet) Data(key []byte) (res []byte, err error) {
	res = p.Payload

	if p.Flags&Encrypted != 0 {
		if res, err = decrypt(key, p.IV, p.Payload); err != nil {
			return nil, err
		}
	}

	if p.Flags&Compressed != 0 {
		return nil, errFlagNotSupported("compressed")
	}

	if p.Flags&SnappyCompressed != 0 {
		if res, err = deflate(res); err != nil {
			return nil, nil
		}
	}

	return
}

// deflate decompresses data
func deflate(data []byte) ([]byte, error) {
	return snappy.Decode(nil, data[:len(data)-10])
}

// decrypt decodes the payload with the given key. The key must be 16
// bytes long.
func decrypt(key, iv, data []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errInvalidKey
	}

	ciphertext := make([]byte, len(data))
	copy(ciphertext, data)
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errInvalidPadding("data is not padded")
	}

	// err would be a crypto.KeySizeError, which is handled above
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return pkcs7unpad(ciphertext)
}

// pkcs7unpad removes padding from a decoded stream.
func pkcs7unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errInvalidPadding("no data")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errInvalidPadding("data is not padded")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errInvalidPadding("structure invalid")
		}
	}
	return b[:len(b)-n], nil
}
