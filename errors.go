package inform

import (
	"errors"
	"fmt"
)

type errInvalidPadding string

func (err errInvalidPadding) Error() string {
	return fmt.Sprintf("invalid padding: %s", string(err))
}

type errIncompletePacket string

func (err errIncompletePacket) Error() string {
	return fmt.Sprintf("insufficient data: %s", string(err))
}

var (
	errInvalidKey   = errors.New("invalid key: must be 16 bytes long")
	errInvalidMagic = errors.New("invalid packet: must begin with 'TNBU'")
)
