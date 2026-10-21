package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	inform "github.com/dmke/inform-inspect"
)

// packet returns an unencrypted inform packet with the given flags and
// payload; magic aside, all other header fields are zero.
func packet(flags uint16, payload []byte) []byte {
	head := make([]byte, 40)
	copy(head, "TNBU")
	binary.BigEndian.PutUint16(head[14:], flags)
	binary.BigEndian.PutUint32(head[36:], uint32(len(payload)))
	return append(head, payload...)
}

// writeFile writes data to a temporary file and returns its path.
func writeFile(t *testing.T, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "inform.dat")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestRun(t *testing.T) {
	t.Parallel()

	const (
		key       = "e2c930683af3945e4d0d58d37a78c2a6"
		wrongKey  = "11111111111111111111111111111111"
		encrypted = "../../testdata/aes_snappy.dat"
	)

	empty := packet(uint16(inform.SnappyCompressed), snappy.Encode(nil, nil))

	for name, tc := range map[string]struct {
		key, path string
		want      string
		wantErr   string
	}{
		"json object":    {key, writeFile(t, packet(0, []byte(`{"a":1}`))), `{"a":1}`, ""},
		"json array":     {key, writeFile(t, packet(0, []byte(`[1]`))), `[1]`, ""},
		"hex dump":       {key, writeFile(t, packet(0, []byte("hello"))), hex.Dump([]byte("hello")), ""},
		"invalid hex":    {"zz", encrypted, "", "key must be 32 character long and hex-encoded: encoding/hex: invalid byte: U+007A 'z'"},
		"short key":      {"00", encrypted, "", "error decrypting packet: invalid key: must be 16 bytes long"},
		"wrong key":      {wrongKey, encrypted, "", "error decrypting packet: invalid padding: structure invalid"},
		"missing file":   {key, "missing.dat", "", `error opening "missing.dat": open missing.dat: no such file or directory`},
		"invalid packet": {key, writeFile(t, []byte("hello")), "", "cannot read packet: insufficient data: header too short"},
		"empty payload":  {key, writeFile(t, empty), "", "packet contains no data"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			err := run(tc.key, tc.path, &out)
			if tc.wantErr == "" {
				assert.NoError(t, err, "run failed")
			} else {
				assert.EqualError(t, err, tc.wantErr, "unexpected error")
			}
			assert.Equal(t, tc.want, out.String(), "unexpected output")
		})
	}

	// decrypting real data
	var out bytes.Buffer
	require.NoError(t, run(key, encrypted, &out), "run failed")
	assert.True(t, json.Valid(out.Bytes()), "payload not printed as JSON")
}
