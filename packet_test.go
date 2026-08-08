package inform

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvalidPacket(t *testing.T) {
	t.Parallel()

	_, err := ReadPacket(bytes.NewReader(nil))
	assert.EqualError(t, err, "EOF")

	_, err = ReadPacket(bytes.NewReader([]byte("hello")))
	assert.EqualError(t, err, "insufficient data: header too short")

	_, err = ParsePacket([]byte("hello"))
	assert.EqualError(t, err, "insufficient data: header too short")

	_, err = ParsePacket(bytes.Repeat([]byte("x"), headerLength))
	assert.EqualError(t, err, "invalid packet: must begin with 'TNBU'")
}

func TestTruncatedPayload(t *testing.T) {
	t.Parallel()

	dat, err := os.ReadFile("testdata/aes_snappy.dat")
	require.NoError(t, err)
	dat = dat[:len(dat)-1]

	_, err = ParsePacket(dat)
	assert.EqualError(t, err, "insufficient data: payload too short")

	_, err = ReadPacket(bytes.NewReader(dat))
	assert.EqualError(t, err, "insufficient data: unexpected EOF")
}

type decodeTestcase struct {
	datFile string
	hexKey  string

	flags        flags
	mac          string
	firmware     string
	model        string
	modelDisplay string
}

// Run executes a decodeTestcase and allows chosing the reader/parser
// method. The parse argument receives the tc.datFile read from disk
// needs to construct a Packet from it. See TestDecode for usage below.
func (tc *decodeTestcase) Run(t *testing.T, parse func([]byte) (*Packet, error)) {
	t.Helper()

	assert, require := assert.New(t), require.New(t)

	dat, err := os.ReadFile(tc.datFile)
	require.NoError(err)

	packet, err := parse(dat)
	require.NoError(err)
	require.NotNil(packet)

	assert.Equal(tc.mac, packet.MAC.String())
	assert.EqualValues(0, packet.PacketVersion)
	assert.EqualValues(1, packet.PayloadVersion)
	assert.Equal(tc.flags, packet.Flags)

	invalidKey, err := hex.DecodeString("11111111111111111111111111111111")
	require.NoError(err)
	_, err = packet.Data(invalidKey)
	if tc.flags&GCMMode != 0 {
		assert.EqualError(err, "cipher: message authentication failed")
	} else {
		assert.EqualError(err, "invalid padding: structure invalid")
	}

	validKey, err := hex.DecodeString(tc.hexKey)
	require.NoError(err)
	data, err := packet.Data(validKey)
	require.NoError(err)

	jsonData := make(map[string]any)
	assert.NoError(json.Unmarshal(data, &jsonData))
	assert.Equal(tc.firmware, jsonData["version"])
	assert.Equal(tc.model, jsonData["model"])
	assert.Equal(tc.modelDisplay, jsonData["model_display"])
}

func TestDecode(t *testing.T) {
	t.Parallel()

	tt := []decodeTestcase{{
		datFile: "testdata/aes_snappy.dat",
		hexKey:  "e2c930683af3945e4d0d58d37a78c2a6",

		flags:        AESEncrypted | SnappyCompressed,
		mac:          "f0:9f:c2:79:63:90",
		firmware:     "3.9.27.8537",
		model:        "U7PG2",
		modelDisplay: "UAP-AC-Pro-Gen2",
	}, {
		datFile: "testdata/gcm_zlib.dat",
		hexKey:  "05223125e6b44aca0a0599551168d766",

		flags:        AESEncrypted | GCMMode | ZlibCompressed,
		mac:          "fc:ec:da:fc:c5:35",
		firmware:     "4.0.66.10832",
		model:        "U7PG2",
		modelDisplay: "UAP-AC-Pro-Gen2",
	}}

	for _, tc := range tt { //nolint:paralleltest
		// wrap file contents in a reader and test ReadPacket
		t.Run(tc.datFile+"_ReadPacket", func(t *testing.T) {
			t.Parallel()
			tc.Run(t, func(dat []byte) (*Packet, error) {
				return ReadPacket(bytes.NewReader(dat))
			})
		})

		// pass file contents directly to ParsePacket
		t.Run(tc.datFile+"_ParsePacket", func(t *testing.T) {
			t.Parallel()
			tc.Run(t, ParsePacket)
		})
	}
}
