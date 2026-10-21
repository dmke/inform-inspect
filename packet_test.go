package inform

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"testing"

	"github.com/klauspost/compress/snappy"
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

	_, err = ReadPacket(bytes.NewReader(bytes.Repeat([]byte("x"), headerLength)))
	assert.EqualError(t, err, "invalid packet: must begin with 'TNBU'")

	// valid magic, but all other header fields zero
	head := append([]byte("TNBU"), make([]byte, headerLength-4)...)
	_, err = ParsePacket(head)
	assert.EqualError(t, err, "insufficient data: header does not define payload length")
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

func TestData(t *testing.T) {
	t.Parallel()

	plain := []byte(`{"model":"U7PG2"}`)

	var zbuf bytes.Buffer
	z := zlib.NewWriter(&zbuf)
	_, err := z.Write(plain)
	require.NoError(t, err)
	require.NoError(t, z.Close())
	zlibbed := zbuf.Bytes()
	snappied := snappy.Encode(nil, plain)

	key := make([]byte, 16)

	for name, tc := range map[string]struct {
		pkt     Packet
		key     []byte
		want    []byte
		wantErr error
	}{
		"plain":          {Packet{Payload: plain}, nil, plain, nil},
		"zlib":           {Packet{Flags: ZlibCompressed, Payload: zlibbed}, nil, plain, nil},
		"snappy":         {Packet{Flags: SnappyCompressed, Payload: snappied}, nil, plain, nil},
		"short key":      {Packet{Flags: AESEncrypted, Payload: key}, key[:15], nil, errInvalidKey},
		"unaligned CBC":  {Packet{Flags: AESEncrypted, Payload: key[:15]}, key, nil, errInvalidPadding("data is not padded")},
		"zlib header":    {Packet{Flags: ZlibCompressed, Payload: plain}, nil, nil, zlib.ErrHeader},
		"zlib truncated": {Packet{Flags: ZlibCompressed, Payload: zlibbed[:len(zlibbed)-6]}, nil, nil, io.ErrUnexpectedEOF},
		"snappy corrupt": {Packet{Flags: SnappyCompressed, Payload: plain}, nil, nil, snappy.ErrCorrupt},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.pkt.Data(tc.key)
			assert.ErrorIs(t, err, tc.wantErr, "unexpected error")
			assert.Equal(t, tc.want, got, "unexpected data")
		})
	}
}

func TestPKCS7Unpad(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		in      []byte
		want    []byte
		wantErr error
	}{
		"one pad byte":   {[]byte{7, 7, 1}, []byte{7, 7}, nil},
		"only padding":   {[]byte{2, 2}, []byte{}, nil},
		"empty":          {nil, nil, errInvalidPadding("no data")},
		"zero pad byte":  {[]byte{7, 7, 0}, nil, errInvalidPadding("data is not padded")},
		"pad too long":   {[]byte{7, 3}, nil, errInvalidPadding("data is not padded")},
		"pad mismatched": {[]byte{7, 3, 2}, nil, errInvalidPadding("structure invalid")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := pkcs7unpad(tc.in)
			assert.ErrorIs(t, err, tc.wantErr, "unexpected error")
			assert.Equal(t, tc.want, got, "unexpected data")
		})
	}
}
