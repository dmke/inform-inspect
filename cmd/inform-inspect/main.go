package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	inform "github.com/dmke/inform-inspect"
)

func main() {
	if len(os.Args[1:]) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key> <packet>\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Missing <key> and <packet> arguments.")
		os.Exit(1)
	}

	aesKey, err := hex.DecodeString(os.Args[1])
	if err != nil || len(aesKey) != 16 {
		log.Fatalf("key must be 32 character long and hex-encoded: %v", err)
	}

	pktFile, err := os.Open(os.Args[2])
	if err != nil {
		log.Fatalf("error opening %q: %v", os.Args[2], err)
	}
	defer pktFile.Close()

	pkt, err := inform.ReadPacket(pktFile)
	if err != nil {
		log.Fatalf("cannot read packet: %v", err)
	}

	if len(pkt.Payload) == 0 {
		log.Printf("no payload found")
	}

	data, err := pkt.Data(aesKey)
	if err != nil {
		log.Printf("error decrypting packet: %v", err)
	}

	switch data[0] {
	case '{', '[':
		fmt.Print(string(data))
	default:
		fmt.Print(hex.Dump(data))
	}
}
