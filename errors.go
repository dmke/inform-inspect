package inform

import (
	"errors"
	"fmt"
)

type errUnknownField string

func (err errUnknownField) Error() string {
	return fmt.Sprintf("unknown field: %s", string(err))
}

type errInvalidPadding string

func (err errInvalidPadding) Error() string {
	return fmt.Sprintf("invalid padding: %s", string(err))
}

type errFlagNotSupported string

func (err errFlagNotSupported) Error() string {
	return fmt.Sprintf("unsupported flag: %s", string(err))
}

type errIncompletePacket string

func (err errIncompletePacket) Error() string {
	return fmt.Sprintf("insufficient data: %v", string(err))
}

var (
	errInvalidKey   = errors.New("invalid key: must be 16 bytes long")
	errInvalidMagic = errors.New("invalid packet: must begin with 'TNBU'")
)
