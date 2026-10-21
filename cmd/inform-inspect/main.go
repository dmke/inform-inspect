// Command inform-inspect decrypts a captured Unifi inform packet and
// prints its payload.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	inform "github.com/dmke/inform-inspect"
)

var errNoData = errors.New("packet contains no data")

func main() {
	if len(os.Args[1:]) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key> <packet>\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Missing <key> and <packet> arguments.")
		os.Exit(1)
	}

	if err := run(os.Args[1], os.Args[2], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run decrypts the packet in the file at path with the hex-encoded key
// and writes its payload to w: verbatim if it looks like JSON, as a hex
// dump otherwise.
func run(key, path string, w io.Writer) error {
	aesKey, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("key must be 32 character long and hex-encoded: %w", err)
	}

	pktFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("error opening %q: %w", path, err)
	}
	defer pktFile.Close()

	pkt, err := inform.ReadPacket(pktFile)
	if err != nil {
		return fmt.Errorf("cannot read packet: %w", err)
	}

	// the key length is checked here, and only for encrypted packets
	data, err := pkt.Data(aesKey)
	if err != nil {
		return fmt.Errorf("error decrypting packet: %w", err)
	}
	if len(data) == 0 {
		return errNoData
	}

	switch data[0] {
	case '{', '[':
		_, err = w.Write(data)
	default:
		_, err = io.WriteString(w, hex.Dump(data))
	}
	return err
}
