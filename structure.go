package inform

import "fmt"

type headerField byte

const (
	headerMagic headerField = iota
	headerPacketVersion
	headerMAC
	headerFlags
	headerIV
	headerPayloadVersion
	headerPayloadLength
)

func (f headerField) String() string {
	switch f {
	case headerMagic:
		return "Magic"
	case headerPacketVersion:
		return "PacketVersion"
	case headerMAC:
		return "MAC"
	case headerFlags:
		return "Flags"
	case headerIV:
		return "IV"
	case headerPayloadVersion:
		return "PayloadVersion"
	case headerPayloadLength:
		return "PayloadLength"
	}
	return fmt.Sprintf("%%!unknown(%02x)", byte(f))
}

type flags uint16

// Various packet flags
const (
	Encrypted        flags = 1 << iota // packet's payload is encrypted
	Compressed                         // the packet's payload is compressed
	SnappyCompressed                   // payload is compressed with Google's snappy algorithm
)

// fieldOrder statically describes a packet's fields, their order and the
// length of each field (in bytes).
var fieldOrder = []struct {
	name   headerField
	length int
}{
	{headerMagic, 4},
	{headerPacketVersion, 4},
	{headerMAC, 6},
	{headerFlags, 2},
	{headerIV, 16},
	{headerPayloadVersion, 4},
	{headerPayloadLength, 4},
}

// headerLength is the combined length of the inform packet's clear text
// header.
const headerLength = 0 +
	4 /* headerMagic */ +
	4 /* headerPacketVersion */ +
	6 /* headerMAC */ +
	2 /* headerFlags */ +
	16 /* headerIV */ +
	4 /* headerPayloadVersion */ +
	4 /* headerPayloadLength */
